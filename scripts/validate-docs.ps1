# Проверка документации (README.md, docs/*.md) на корректность отображения на GitHub:
#   • синтаксис всех диаграмм Mermaid — настоящим парсером (mermaid-cli в Docker, одним запуском на все);
#   • относительные ссылки на файлы и каталоги репозитория;
#   • якоря (#раздел) — по правилам GitHub для заголовков, в т.ч. кириллических;
#   • таблицы — одинаковое число столбцов в заголовке, разделителе и строках.
# Код выхода = число найденных проблем. Используется в CI (.github/workflows/ci.yml, задача docs).
param([switch]$SkipMermaid)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$problems = [System.Collections.Generic.List[string]]::new()
$files = @("README.md") + (Get-ChildItem docs -Filter *.md | ForEach-Object { "docs/$($_.Name)" })

# Якорь заголовка по правилам GitHub: нижний регистр, пробелы → "-", убрать всё, кроме букв/цифр/-/_.
function Get-Slug([string]$heading) {
    $s = $heading.Trim().ToLowerInvariant()
    $s = [regex]::Replace($s, '[^\p{L}\p{Nd}\s_-]', '')
    return $s -replace ' ', '-'
}

$anchors = @{}
foreach ($f in $files) {
    $seen = @{}
    $inCode = $false
    $anchors[$f] = foreach ($line in Get-Content $f) {
        if ($line -match '^```') { $inCode = -not $inCode; continue }
        if ($inCode -or $line -notmatch '^#{1,6}\s+(.+)$') { continue }
        $slug = Get-Slug $Matches[1]
        if ($seen.ContainsKey($slug)) { $seen[$slug]++; "$slug-$($seen[$slug])" } else { $seen[$slug] = 0; $slug }
    }
}

$mermaid = [System.Collections.Generic.List[object]]::new()
foreach ($f in $files) {
    $lines = Get-Content $f
    $inCode = $false; $lang = ""; $block = @(); $start = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^```(\w*)') {
            if (-not $inCode) { $inCode = $true; $lang = $Matches[1]; $block = @(); $start = $i + 1 }
            else {
                $inCode = $false
                if ($lang -eq "mermaid") { $mermaid.Add([pscustomobject]@{ File = $f; Line = $start; Text = ($block -join "`n") }) }
            }
            continue
        }
        if ($inCode) { $block += $line; continue }

        # Ссылки [текст](цель), кроме внешних и почты.
        foreach ($m in [regex]::Matches($line, '\]\(([^)\s]+)\)')) {
            $target = $m.Groups[1].Value
            if ($target -match '^(https?:|mailto:)') { continue }
            $path, $anchor = $target -split '#', 2
            $dir = Split-Path $f; if (-not $dir) { $dir = "." }
            $resolved = if ($path) { [IO.Path]::GetFullPath((Join-Path (Resolve-Path $dir).Path $path)) } else { (Resolve-Path $f).Path }
            if ($path -and -not (Test-Path $resolved)) { $problems.Add("${f}:$($i+1): нет файла '$target'"); continue }
            if ($anchor -and $resolved -match '\.md$') {
                $rel = [IO.Path]::GetRelativePath($root, $resolved).Replace('\', '/')
                if ($anchors[$rel] -notcontains $anchor) { $problems.Add("${f}:$($i+1): нет раздела '#$anchor' в $rel") }
            }
        }

        # Таблицы: число столбцов строки против заголовка.
        if ($line -match '^\|') {
            $cells = ($line.Trim() -replace '\\\|', '' -replace '`[^`]*`', 'x').Trim('|').Split('|').Count
            if ($i -gt 0 -and $lines[$i - 1] -notmatch '^\|') { $tableCols = $cells }
            elseif ($cells -ne $tableCols) { $problems.Add("${f}:$($i+1): в строке таблицы $cells столбцов вместо $tableCols") }
        }
    }
}

if (-not $SkipMermaid -and $mermaid.Count -gt 0) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mermaid-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory $tmp | Out-Null
    for ($n = 0; $n -lt $mermaid.Count; $n++) { Set-Content (Join-Path $tmp "$n.mmd") $mermaid[$n].Text -Encoding utf8NoBOM }
    # Один контейнер на все диаграммы: браузер mermaid-cli поднимается один раз.
    $script = 'for f in /data/*.mmd; do mmdc -p /puppeteer-config.json -q -i "$f" -o "${f%.mmd}.svg" >/dev/null 2>"${f%.mmd}.err" || true; done'
    # Контейнер работает под своим пользователем (там его Chrome) — в Linux открываем каталог на запись.
    if (-not $IsWindows) { chmod 777 $tmp }
    docker run --rm -v "${tmp}:/data" --entrypoint sh minlag/mermaid-cli -c $script | Out-Null
    for ($n = 0; $n -lt $mermaid.Count; $n++) {
        if (-not (Test-Path (Join-Path $tmp "$n.svg"))) {
            $err = (Get-Content (Join-Path $tmp "$n.err") -ErrorAction SilentlyContinue | Select-String 'Parse error|Expecting|Error' | Select-Object -First 2) -join ' '
            $problems.Add("$($mermaid[$n].File):$($mermaid[$n].Line): диаграмма Mermaid не разбирается: $err")
        }
    }
    Remove-Item $tmp -Recurse -Force
}

Write-Host "Файлов: $($files.Count), диаграмм Mermaid: $($mermaid.Count), проблем: $($problems.Count)"
$problems | ForEach-Object { Write-Host "  ✗ $_" -ForegroundColor Red }
exit $problems.Count
