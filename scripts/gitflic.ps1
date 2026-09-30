# Командная утилита для GitFlic без браузера: конвейеры, задания, артефакты, агенты — через REST API (api.gitflic.ru).
# Токен: API-токен профиля (Настройки → «API токены») в переменной GITFLIC_API_TOKEN или в файле -TokenFile
# (по умолчанию C:\Projects\TSL\Key\gitflic-api-token.txt) либо строкой GITFLIC_API_TOKEN=… в C:\Projects\TSL\Key\gitflic-tokens.env —
# оба файла вне репозитория. Значение токена не выводится.
#
#   ./scripts/gitflic.ps1 pipelines [-Top 10]            список конвейеров: номер, статус, ветка, коммит
#   ./scripts/gitflic.ps1 jobs 45                        задания конвейера №45: имя, статус, агент
#   ./scripts/gitflic.ps1 artifacts 45                   артефакты конвейера №45
#   ./scripts/gitflic.ps1 runners                        агенты проекта: имя, статус, теги, uuid
#   ./scripts/gitflic.ps1 runner-tags <uuid> tsl-auth    задать теги агенту
#   ./scripts/gitflic.ps1 runner-delete <uuid>           удалить запись агента
#   ./scripts/gitflic.ps1 restart 45 | cancel 45         перезапустить / отменить конвейер
#   ./scripts/gitflic.ps1 prune-pipelines [-Keep 3]      удалить конвейеры старше Keep новейших (вместе с артефактами)
#   ./scripts/gitflic.ps1 raw GET /project/uklad/tsl-auth/cicd/pipeline?size=1     произвольный запрос (JSON как есть)
# -DryRun — для prune-pipelines и runner-delete: только показать, что было бы сделано.
param(
    [Parameter(Position = 0)][string]$Command = "pipelines",
    [Parameter(Position = 1)][string]$Arg1,
    [Parameter(Position = 2)][string]$Arg2,
    [string]$Project = "uklad/tsl-auth",
    [string]$Api = "https://api.gitflic.ru",
    [string]$TokenFile = "C:\Projects\TSL\Key\gitflic-api-token.txt",
    [string]$EnvFile = "C:\Projects\TSL\Key\gitflic-tokens.env",
    [int]$Top = 10,
    [int]$Keep = 3,
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$token = $env:GITFLIC_API_TOKEN
if (-not $token -and (Test-Path $TokenFile)) { $token = (Get-Content $TokenFile -Raw).Trim() }
# Общий файл токенов (формат KEY=VALUE): строка GITFLIC_API_TOKEN=<значение>.
if (-not $token -and (Test-Path $EnvFile)) {
    $line = Get-Content $EnvFile | Where-Object { $_ -match '^\s*GITFLIC_API_TOKEN\s*=' } | Select-Object -First 1
    if ($line) { $token = ($line -split '=', 2)[1].Trim().Trim('"') }
}
if (-not $token) { throw "Нет токена: задайте GITFLIC_API_TOKEN, строку GITFLIC_API_TOKEN=… в $EnvFile или файл $TokenFile" }
$headers = @{ Authorization = "token $token" }

function Invoke-Api([string]$method, [string]$path, $body = $null) {
    $p = @{ Uri = "$Api$path"; Method = $method; Headers = $headers }
    if ($null -ne $body) { $p.Body = ($body | ConvertTo-Json -Depth 8); $p.ContentType = "application/json" }
    Invoke-RestMethod @p
}
# Списки приходят страницами (поле _embedded или content) либо массивом — возвращаем массив, где бы он ни лежал.
function Get-Items($response) {
    if ($response -is [array]) { return $response }
    if ($response._embedded) { return @($response._embedded.PSObject.Properties | Select-Object -First 1 -ExpandProperty Value) }
    if ($response.content) { return @($response.content) }
    return @($response)
}
function Get-Pipelines([int]$size = 100) { Get-Items (Invoke-Api GET "/project/$Project/cicd/pipeline?size=$size") }

switch ($Command) {
    "pipelines" {
        Get-Pipelines $Top | Select-Object -First $Top | ForEach-Object {
            "{0,-5} {1,-12} {2,-14} {3,-9} {4}" -f "#$($_.localId)", $_.status, $_.ref, "$($_.commitId)".Substring(0, [Math]::Min(7, "$($_.commitId)".Length)), $_.createdAt
        }
    }
    "jobs" {
        Get-Items (Invoke-Api GET "/project/$Project/cicd/pipeline/$Arg1/jobs?size=100") | ForEach-Object {
            "{0,-6} {1,-22} {2,-12} {3,-10} {4}" -f $_.localId, $_.name, $_.status, $_.stageName, $_.runnerName
        }
    }
    "artifacts" { Get-Items (Invoke-Api GET "/project/$Project/cicd/pipeline/$Arg1/artifacts?size=100") | ConvertTo-Json -Depth 6 }
    "runners" {
        Get-Items (Invoke-Api GET "/project/$Project/runners?size=100") | ForEach-Object {
            "{0,-20} {1,-10} {2,-26} {3}" -f $_.name, $_.status, (@($_.tags) -join ","), ($_.uuid ?? $_.id)
        }
    }
    "runner-tags" { Invoke-Api POST "/project/$Project/runners/$Arg1/edit" @{ tags = @($Arg2 -split ",") } | ConvertTo-Json -Depth 4 }
    "runner-delete" {
        if ($DryRun) { "[dry-run] DELETE runner $Arg1" } else { Invoke-Api DELETE "/project/$Project/runners/$Arg1" | Out-Null; "агент $Arg1 удалён" }
    }
    "restart" { Invoke-Api POST "/project/$Project/cicd/pipeline/$Arg1/restart" | Out-Null; "конвейер #$Arg1 перезапущен" }
    "cancel" { Invoke-Api POST "/project/$Project/cicd/pipeline/$Arg1/cancel" | Out-Null; "конвейер #$Arg1 отменён" }
    "prune-pipelines" {
        # Новейшие Keep остаются; выполняющиеся не трогаем. Удаление конвейера убирает и его артефакты.
        $all = Get-Pipelines 200 | Sort-Object { [int]$_.localId } -Descending
        $old = $all | Select-Object -Skip $Keep | Where-Object { $_.status -notmatch "RUN|PEND|CREATED|WAIT" }
        "конвейеров: $($all.Count), к удалению: $($old.Count) (остаются $Keep новейших)"
        foreach ($p in $old) {
            if ($DryRun) { "  [dry-run] #$($p.localId) $($p.status)" }
            else { try { Invoke-Api DELETE "/project/$Project/cicd/pipeline/$($p.localId)/delete" | Out-Null; "  удалён #$($p.localId)" } catch { "  #$($p.localId): $($_.Exception.Message)" } }
        }
    }
    "raw" { Invoke-Api $Arg1 $Arg2 | ConvertTo-Json -Depth 10 }
    default { throw "Неизвестная команда '$Command' (см. шапку файла)" }
}
