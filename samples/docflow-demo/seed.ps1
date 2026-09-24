# Настраивает TSL Auth для демо «Документооборот» через Admin API:
#   • приложения docflow-api (API + App API), docflow-web (PWA, PKCE), docflow-security-bot (бот);
#   • матрицу доступа docflow-api — ЕДИНСТВЕННОЕ место, где определяются роли и их права;
#   • демо-сотрудников с ролями и офицера безопасности.
# Секреты клиентов пишутся в samples/docflow-demo/.env (его читают docker compose и run-local.ps1).
# Повторный запуск безопасен: существующее обновляется, секреты перевыпускаются, только если их нет в .env.
param(
    [string]$Issuer = "http://localhost:8080",
    [string]$AdminClientId = "admin-cli",
    [string]$AdminClientSecret = "demo-admin-cli-secret-2026",
    [string]$UserPassword = "Demo-Passw0rd!",
    # Адреса PWA: собранная (раздаёт API) и dev-сервер Vite.
    [string[]]$WebOrigins = @("http://localhost:5200", "http://localhost:5173")
)
$ErrorActionPreference = "Stop"
$Issuer = $Issuer.TrimEnd("/")
$tok = Invoke-RestMethod "$Issuer/connect/token" -Method Post -Body @{
    grant_type = "client_credentials"; client_id = $AdminClientId; client_secret = $AdminClientSecret; scope = "tsl-auth-admin" }
$H = @{ Authorization = "Bearer $($tok.access_token)" }

function Api($method, $path, $body) {
    $req = @{ Uri = "$Issuer/api/admin$path"; Method = $method; Headers = $H; ContentType = "application/json; charset=utf-8" }
    if ($null -ne $body) { $req.Body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $body -Depth 6)) }
    try { Invoke-RestMethod @req }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404 -and $method -eq "GET") { throw }
        throw "$method $path -> $($_.ErrorDetails.Message)"
    }
}

$envFile = Join-Path $PSScriptRoot ".env"
$secrets = @{}
if (Test-Path $envFile) { Get-Content $envFile | ForEach-Object { $k, $v = $_ -split "=", 2; if ($k -and -not $k.StartsWith("#")) { $secrets[$k] = $v } } }

# Создаёт или обновляет приложение; секрет confidential-клиента — новый, если в .env его нет.
function Upsert-App($app, $secretKey) {
    $exists = $true
    try { Api GET "/applications/$($app.clientId)" | Out-Null } catch { $exists = $false }
    if (-not $exists) {
        $secret = (Api POST "/applications" $app).clientSecret
        if ($secretKey) { $secrets[$secretKey] = $secret }
        return
    }
    Api PUT "/applications/$($app.clientId)" $app | Out-Null
    if ($secretKey -and -not $secrets[$secretKey]) { $secrets[$secretKey] = (Api POST "/applications/$($app.clientId)/secret").clientSecret }
}

# --- Приложения ---
Upsert-App @{ clientId = "docflow-api"; displayName = "Документооборот (API)"; clientType = "confidential";
    grantTypes = @("client_credentials"); scopes = @(); selfManagement = $true } "DOCFLOW_API_SECRET"
Upsert-App @{ clientId = "docflow-web"; displayName = "Документооборот"; clientType = "public";
    grantTypes = @("authorization_code", "refresh_token"); scopes = @("profile", "email", "roles", "docflow-api");
    redirectUris = @($WebOrigins | ForEach-Object { "$_/callback" }); postLogoutRedirectUris = @($WebOrigins | ForEach-Object { "$_/" });
    selfRegistration = $true } $null
Upsert-App @{ clientId = "docflow-security-bot"; displayName = "Бот безопасности документооборота"; clientType = "confidential";
    grantTypes = @("client_credentials"); scopes = @("tsl-auth-admin") } "DOCFLOW_BOT_SECRET"
# Боту — роль security-bot: сброс пароля, блокировка, принудительная смена (права решает матрица tsl-auth-admin).
# В образах TSL Auth без расширенного Bot API этой роли нет — тогда бот получает reset-bot (только привязка и сброс).
$systemRoles = (Api GET "/applications/tsl-auth-admin/matrix").roles.name
$hasSecurityBot = $systemRoles -contains "security-bot"
if (-not $hasSecurityBot) {
    Write-Warning "В этой версии TSL Auth нет ролей security-bot/security-officer: команды /lock, /unlock, /forcepwd работать не будут. Нужен образ с расширенным Bot API."
}
Api PUT "/applications/docflow-security-bot/service-roles" @(@{ clientId = "tsl-auth-admin"; role = $(if ($hasSecurityBot) { "security-bot" } else { "reset-bot" }) }) | Out-Null

# --- Матрица доступа docflow-api: роли определяются только здесь, в TSL Auth ---
$permissions = [ordered]@{
    "documents.view" = "Просмотр документов"; "documents.create" = "Создание и редактирование своих документов"
    "documents.review" = "Согласование"; "documents.approve" = "Утверждение"; "documents.archive" = "Архив и управление любыми документами"
    "dashboard.view" = "Дашборд"; "users.manage" = "Управление пользователями и назначение ролей"
}
$roles = [ordered]@{
    "employee"      = @{ title = "Сотрудник"; perms = @("documents.view", "documents.create", "dashboard.view"); requestable = $true }
    "reviewer"      = @{ title = "Согласующий"; perms = @("documents.view", "documents.create", "documents.review", "dashboard.view"); requestable = $true }
    "approver"      = @{ title = "Руководитель (утверждает)"; perms = @("documents.view", "documents.create", "documents.review", "documents.approve", "dashboard.view"); requestable = $false }
    "clerk"         = @{ title = "Делопроизводитель"; perms = @("documents.view", "documents.archive", "dashboard.view"); requestable = $false }
    "docflow-admin" = @{ title = "Администратор документооборота"; perms = @($permissions.Keys); requestable = $false }
}
$m = Api GET "/applications/docflow-api/matrix"
foreach ($p in $permissions.Keys) {
    if (-not ($m.permissions.name -contains $p)) { Api POST "/applications/docflow-api/permissions" @{ name = $p; description = $permissions[$p] } | Out-Null }
}
foreach ($r in $roles.Keys) {
    $def = $roles[$r]
    if (-not ($m.roles.name -contains $r)) {
        Api POST "/applications/docflow-api/roles" @{ name = $r; displayName = $def.title; permissions = $def.perms; requestable = $def.requestable } | Out-Null
    } else {
        Api PUT "/applications/docflow-api/roles/$r/permissions" $def.perms | Out-Null
        Api PUT "/applications/docflow-api/roles/$r" @{ displayName = $def.title } | Out-Null
    }
}

# --- Сотрудники ---
function Upsert-User($name, $display, $roleRefs) {
    $found = Api GET "/users?search=$name"
    $body = @{ userName = $name; email = "$name@docflow.local"; displayName = $display; isActive = $true; roles = $roleRefs }
    if ($found.total -eq 0) { $body.password = $UserPassword; Api POST "/users" $body | Out-Null }
    else {
        Api PUT "/users/$($found.items[0].id)" $body | Out-Null
        Api POST "/users/$($found.items[0].id)/password" @{ password = $UserPassword } | Out-Null
    }
}
$d = { param($role) @{ clientId = "docflow-api"; role = $role } }
Upsert-User "ivanova"   "Иванова Анна"     @((& $d "employee"))
Upsert-User "petrov"    "Петров Сергей"    @((& $d "reviewer"))
Upsert-User "sidorova"  "Сидорова Мария"   @((& $d "approver"))
Upsert-User "kozlov"    "Козлов Дмитрий"   @((& $d "clerk"))
# Администратор документооборота — ещё и офицер безопасности: через бота блокирует чужие учётки.
$officer = @((& $d "docflow-admin"))
if ($hasSecurityBot) { $officer += @{ clientId = "tsl-auth-admin"; role = "security-officer" } }
Upsert-User "admin-doc" "Орлова Екатерина" $officer

$secrets["DOCFLOW_ISSUER"] = "$Issuer/"
$secrets.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content $envFile
Write-Host "Готово. Сотрудники ivanova, petrov, sidorova, kozlov, admin-doc — пароль $UserPassword. Секреты: $envFile"
