# Отрисовка схем Mermaid в картинки для площадок без рендера Mermaid (GitFlic; GitHub рендерит и так).
#   ./scripts/render-diagrams.ps1            — обновить разметку и отрисовать недостающие картинки
# Что делает с каждым блоком ```mermaid в Markdown-файлах репозитория:
#   1. ставит перед ним картинку docs/diagrams/<хеш>.svg (хеш — первые 12 знаков SHA-256 исходника схемы);
#   2. заворачивает исходник в сворачиваемый блок «Исходник схемы (Mermaid)» — править схему нужно в нём;
#   3. отрисовывает SVG, которых ещё нет (mermaid-cli в Docker, тот же образ, что в validate-docs.ps1);
#   4. удаляет из docs/diagrams картинки, на которые больше никто не ссылается.
# Повторный запуск идемпотентен: изменился исходник — меняется хеш, путь картинки и сама картинка.
# validate-docs.ps1 проверяет, что у каждой схемы есть актуальная картинка (иначе — запустить этот скрипт).
param([switch]$Force)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$outDir = Join-Path $root "docs/diagrams"
New-Item -ItemType Directory -Force $outDir | Out-Null
$summary = "<details><summary>Исходник схемы (Mermaid)</summary>"

function Get-DiagramHash([string[]]$block) {
    $text = ($block | ForEach-Object { $_.TrimEnd() }) -join "`n"
    $bytes = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text.Trim()))
    ([Convert]::ToHexString($bytes)).Substring(0, 12).ToLowerInvariant()
}

# Те же файлы, что проверяет validate-docs.ps1: все отслеживаемые *.md, кроме сторонних.
$files = git ls-files "*.md" | Where-Object { $_ -notmatch 'node_modules|/bin/|/obj/' }
$needed = @{}
foreach ($f in $files) {
    $raw = [IO.File]::ReadAllText((Join-Path $root $f))
    $nl = if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = $raw -split "\r?\n"
    if (-not ($lines -match '^```mermaid')) { continue }
    $rel = [IO.Path]::GetRelativePath((Split-Path (Join-Path $root $f)), $outDir).Replace('\', '/')
    $out = [System.Collections.Generic.List[string]]::new()
    $heading = "Схема"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^#{1,6}\s+(.+)$') { $heading = $Matches[1].Trim() }
        if ($line -notmatch '^```mermaid\s*$') { $out.Add($line); continue }

        $j = $i + 1; $block = @()
        while ($j -lt $lines.Count -and $lines[$j] -notmatch '^```\s*$') { $block += $lines[$j]; $j++ }
        $hash = Get-DiagramHash $block
        $needed[$hash] = $block
        $image = "![$heading]($rel/$hash.svg)"

        # Уже обёрнут (картинка + <details>): обновляем только путь картинки.
        $k = $out.Count - 1
        while ($k -ge 0 -and $out[$k] -eq "") { $k-- }
        if ($k -ge 0 -and $out[$k] -eq $summary) {
            $m = $k - 1
            while ($m -ge 0 -and $out[$m] -eq "") { $m-- }
            if ($m -ge 0 -and $out[$m] -match 'diagrams/[0-9a-f]{12}\.svg\)$') { $out[$m] = $out[$m] -replace '\([^)]*diagrams/[0-9a-f]{12}\.svg\)$', "($rel/$hash.svg)" }
            $out.Add($line); $out.AddRange([string[]]$block); $out.Add($lines[$j])
        }
        else {
            $out.Add($image); $out.Add(""); $out.Add($summary); $out.Add("")
            $out.Add($line); $out.AddRange([string[]]$block); $out.Add($lines[$j])
            $out.Add(""); $out.Add("</details>")
        }
        $i = $j
    }
    $new = ($out -join $nl)
    if ($new -ne $raw) { [IO.File]::WriteAllText((Join-Path $root $f), $new, [Text.UTF8Encoding]::new($false)); Write-Host "обновлён $f" }
}

# Отрисовка недостающих картинок одним контейнером mermaid-cli.
$missing = $needed.Keys | Where-Object { $Force -or -not (Test-Path (Join-Path $outDir "$_.svg")) }
if ($missing) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("diagrams-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory $tmp | Out-Null
    foreach ($h in $missing) { Set-Content (Join-Path $tmp "$h.mmd") ($needed[$h] -join "`n") -Encoding utf8NoBOM }
    # Подписи — обычным SVG-текстом (htmlLabels: false): картинка вставляется через <img>, а там HTML внутри SVG
    # (foreignObject) отображается не везде. Белый фон — читается и в тёмной теме площадки.
    '{"theme":"default","htmlLabels":false,"flowchart":{"htmlLabels":false,"wrappingWidth":400},"themeVariables":{"fontFamily":"Arial, sans-serif"}}' |
        Set-Content (Join-Path $tmp "config.json") -Encoding utf8NoBOM
    $script = 'for f in /data/*.mmd; do mmdc -p /puppeteer-config.json -q -c /data/config.json -b white -i "$f" -o "${f%.mmd}.svg" || exit 1; done'
    $userArgs = if ($IsWindows) { @() } else { @("--user", "$(id -u):$(id -g)", "-e", "HOME=/tmp") }
    $image = "minlag/mermaid-cli:11.17.1@sha256:d302a7cceeb01b6e4a94a377107056f85e2e488b8789e23fc80835a97960801d"
    docker run --rm @userArgs -v "${tmp}:/data" --entrypoint sh $image -c $script
    if ($LASTEXITCODE -ne 0) { throw "mermaid-cli не отрисовал схемы (см. вывод выше)" }
    foreach ($h in $missing) { Copy-Item (Join-Path $tmp "$h.svg") (Join-Path $outDir "$h.svg") -Force }
    Remove-Item $tmp -Recurse -Force
    Write-Host "отрисовано схем: $(@($missing).Count)"
}

# Картинки, на которые больше нет ссылок (схему изменили или удалили).
Get-ChildItem $outDir -Filter *.svg | Where-Object { -not $needed.ContainsKey($_.BaseName) } | ForEach-Object {
    Remove-Item $_.FullName; Write-Host "удалена $($_.Name)"
}
Write-Host "Схем: $($needed.Count), каталог: docs/diagrams"
