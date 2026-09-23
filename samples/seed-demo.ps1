# Регистрирует демо-приложения, матрицы доступа и тестовых пользователей через Admin API.
# Требуется клиент Admin API (BOOTSTRAP_API_CLIENT_ID / _SECRET). Секреты приложений пишутся в samples/.env.demo.
param(
    [string]$Issuer = "http://localhost:8080",
    [string]$AdminClientId = "admin-cli",
    [string]$AdminClientSecret = "demo-admin-cli-secret-2026",
    [string]$UserPassword = "Demo-Passw0rd!"
)
$ErrorActionPreference = "Stop"
$J = "application/json"
$tok = Invoke-RestMethod "$Issuer/connect/token" -Method Post -Body @{
    grant_type = "client_credentials"; client_id = $AdminClientId; client_secret = $AdminClientSecret; scope = "tsl-auth-admin" }
$H = @{ Authorization = "Bearer $($tok.access_token)" }

function Api($method, $path, $body) {
    $req = @{ Uri = "$Issuer/api/admin$path"; Method = $method; Headers = $H; ContentType = $J }
    if ($null -ne $body) { $req.Body = ConvertTo-Json -InputObject $body -Depth 6 }
    try { Invoke-RestMethod @req }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404 -and $method -eq "GET") { throw }
        throw "$method $path -> $($_.ErrorDetails.Message)"
    }
}
function Upsert-App($app) {
    $exists = $true
    try { Api GET "/applications/$($app.clientId)" | Out-Null } catch { $exists = $false }
    if ($exists) { Api PUT "/applications/$($app.clientId)" $app | Out-Null; return $null }
    (Api POST "/applications" $app).clientSecret
}
function Matrix($clientId, $perms, $roles) {
    $m = Api GET "/applications/$clientId/matrix"
    foreach ($p in $perms) { if (-not ($m.permissions.name -contains $p)) { Api POST "/applications/$clientId/permissions" @{ name = $p } | Out-Null } }
    foreach ($r in $roles.Keys) {
        if (-not ($m.roles.name -contains $r)) { Api POST "/applications/$clientId/roles" @{ name = $r; permissions = $roles[$r].perms; requestable = $roles[$r].requestable } | Out-Null }
        else { Api PUT "/applications/$clientId/roles/$r/permissions" $roles[$r].perms | Out-Null }
    }
}

# --- Ресурсы (API) ---
$goSecret = Upsert-App @{ clientId = "demo-go-api"; displayName = "Демо Go API"; clientType = "confidential";
    grantTypes = @("token_exchange"); scopes = @("demo-node-api") }
Upsert-App @{ clientId = "demo-node-api"; displayName = "Демо Node API"; clientType = "public"; grantTypes = @() } | Out-Null
Matrix "demo-go-api" @("reports.view", "reports.export") @{ analyst = @{ perms = @("reports.view"); requestable = $true }; manager = @{ perms = @("reports.view", "reports.export"); requestable = $false } }
Matrix "demo-node-api" @("orders.read", "orders.write") @{ viewer = @{ perms = @("orders.read"); requestable = $true }; operator = @{ perms = @("orders.read", "orders.write"); requestable = $false } }

# --- Клиенты с разными типами фронта ---
$dotnetSecret = Upsert-App @{ clientId = "demo-dotnet"; displayName = "Демо .NET MVC"; clientType = "confidential";
    grantTypes = @("authorization_code", "refresh_token"); scopes = @("profile", "email", "roles", "demo-go-api");
    redirectUris = @("http://localhost:5101/signin-oidc"); postLogoutRedirectUris = @("http://localhost:5101/signout-callback-oidc") }
Upsert-App @{ clientId = "demo-node-spa"; displayName = "Демо SPA (Node)"; clientType = "public";
    grantTypes = @("authorization_code", "refresh_token"); scopes = @("profile", "email", "roles", "demo-node-api", "demo-go-api");
    redirectUris = @("http://localhost:5102/callback"); postLogoutRedirectUris = @("http://localhost:5102/"); selfRegistration = $true } | Out-Null
$pySecret = Upsert-App @{ clientId = "demo-python"; displayName = "Демо Python"; clientType = "confidential";
    grantTypes = @("password", "refresh_token"); scopes = @("profile"); selfManagement = $true }
Matrix "demo-python" @("tickets.read", "tickets.close") @{ support = @{ perms = @("tickets.read", "tickets.close"); requestable = $true } }
Matrix "demo-dotnet" @("dashboard.view") @{ user = @{ perms = @("dashboard.view"); requestable = $true } }

# --- Оформление страницы входа у SPA ---
Api PUT "/applications/demo-node-spa/branding" @{ title = "Портал заказов"; welcomeText = "Вход для сотрудников отдела продаж";
    accentColor = "#0f766e"; backgroundColor = "#e6f4f1"; footerText = "Поддержка: доб. 1234" } | Out-Null

# --- Пользователи ---
function Upsert-User($name, $display, $roles) {
    $found = Api GET "/users?search=$name"
    $body = @{ userName = $name; email = "$name@tsl.local"; displayName = $display; isActive = $true; roles = $roles }
    if ($found.total -eq 0) { $body.password = $UserPassword; (Api POST "/users" $body).user }
    else { Api PUT "/users/$($found.items[0].id)" $body; Api POST "/users/$($found.items[0].id)/password" @{ password = $UserPassword } | Out-Null }
}
Upsert-User "alice" "Алиса (полный доступ)" @(
    @{ clientId = "demo-go-api"; role = "manager" }, @{ clientId = "demo-node-api"; role = "operator" },
    @{ clientId = "demo-dotnet"; role = "user" }, @{ clientId = "demo-python"; role = "support" }) | Out-Null
Upsert-User "bob" "Боб (только заказы)" @(@{ clientId = "demo-node-api"; role = "viewer" }, @{ clientId = "demo-dotnet"; role = "user" }) | Out-Null

# --- Секреты для демо-приложений ---
$envFile = Join-Path $PSScriptRoot ".env.demo"
$existing = @{}
if (Test-Path $envFile) { Get-Content $envFile | ForEach-Object { $k, $v = $_ -split "=", 2; if ($k) { $existing[$k] = $v } } }
if ($goSecret) { $existing["GO_CLIENT_SECRET"] = $goSecret }
if ($dotnetSecret) { $existing["DOTNET_CLIENT_SECRET"] = $dotnetSecret }
if ($pySecret) { $existing["PYTHON_CLIENT_SECRET"] = $pySecret }
$existing.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content $envFile
Write-Host "Готово. Пользователи alice / bob, пароль $UserPassword. Секреты клиентов: $envFile"
