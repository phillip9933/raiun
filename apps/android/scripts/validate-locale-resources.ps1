param(
    [string]$Locale = 'de',
    [switch]$RequireComplete,
    [string]$Repository = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'
if ($Locale -notmatch '^[a-z]{2,3}(-r[A-Z]{2})?$') {
    throw 'Use an Android language qualifier such as de or de-rDE.'
}

function Read-TextResources([string]$Directory) {
    $entries = @{}
    foreach ($file in Get-ChildItem -LiteralPath $Directory -Filter '*.xml') {
        $document = [xml][IO.File]::ReadAllText($file.FullName)
        foreach ($node in $document.resources.ChildNodes) {
            if ($node.LocalName -notin @('string', 'plurals') -or $node.translatable -eq 'false') { continue }
            $key = "$($node.LocalName)/$($node.name)"
            if ($entries.ContainsKey($key)) { throw "Duplicate $key in $Directory" }
            $entries[$key] = $node
        }
    }
    return $entries
}

function Format-Tokens([string]$Value) {
    return (@([regex]::Matches($Value, '%(?:\d+\$)?[-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z]') |
        ForEach-Object { $_.Value } | Sort-Object) -join '|')
}

$count = 0
$modules = 0
$missing = 0
$resourceDirectories = Get-ChildItem -LiteralPath $Repository -Directory | Where-Object Name -in @('app', 'core', 'feature') |
    ForEach-Object {
        if ($_.Name -eq 'app') { Join-Path $_.FullName 'src/main/res' }
        else { Get-ChildItem -LiteralPath $_.FullName -Directory | ForEach-Object { Join-Path $_.FullName 'src/main/res' } }
    }
foreach ($resources in $resourceDirectories) {
    $defaults = Join-Path $resources 'values'
    if (-not (Test-Path -LiteralPath $defaults)) { continue }
    $source = Read-TextResources $defaults
    # The app localizes the pinned scanner AAR without copying its implementation or English defaults.
    $scannerOverlay = Join-Path $resources "values-$Locale/strings_scanner_sdk.xml"
    if ((Test-Path -LiteralPath $scannerOverlay) -and
        $resources -eq (Join-Path $Repository 'app/src/main/res')) {
        $lock = Get-Content -LiteralPath (Join-Path $Repository 'scripts/offline-scanner-sdk.lock.json') -Raw | ConvertFrom-Json
        $version = $lock.version
        $aar = Join-Path $Repository ".gradle/open-android-doc-scanner-$version/maven/dev/offlinescan/scanner-ui-compose/$version/scanner-ui-compose-$version.aar"
        if (-not (Test-Path -LiteralPath $aar)) { throw 'Install the pinned scanner SDK before validating its translations.' }
        $archive = [IO.Compression.ZipFile]::OpenRead($aar)
        try {
            foreach ($entry in $archive.Entries | Where-Object FullName -match '^res/values/[^/]+\.xml$') {
                $reader = [IO.StreamReader]::new($entry.Open())
                try { $document = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
                foreach ($node in $document.resources.ChildNodes) {
                    if ($node.LocalName -notin @('string', 'plurals') -or $node.translatable -eq 'false') { continue }
                    $key = "$($node.LocalName)/$($node.name)"
                    if ($source.ContainsKey($key)) { throw "Scanner resource collision: $key" }
                    $source[$key] = $node
                }
            }
        } finally { $archive.Dispose() }
    }
    if ($source.Count -eq 0) { continue }
    $translated = Join-Path $resources "values-$Locale"
    if (-not (Test-Path -LiteralPath $translated)) {
        if ($RequireComplete) { throw "Missing locale directory: $translated" }
        $missing += $source.Count
        continue
    }
    $target = Read-TextResources $translated
    foreach ($key in $source.Keys) {
        if (-not $target.ContainsKey($key)) {
            if ($RequireComplete) { throw "Missing $key in $translated" }
            $missing++
            continue
        }
        $original = $source[$key]
        $localized = $target[$key]
        if ($original.LocalName -eq 'string') {
            if ((Format-Tokens $original.InnerText) -ne (Format-Tokens $localized.InnerText)) {
                throw "Format token mismatch: $key in $translated"
            }
        } else {
            if (-not (@($localized.item) | Where-Object quantity -eq 'other')) { throw "Missing other quantity: $key" }
            foreach ($item in $localized.item) {
                $reference = @($original.item) | Where-Object quantity -eq $item.quantity | Select-Object -First 1
                if (-not $reference) { $reference = @($original.item) | Where-Object quantity -eq 'other' | Select-Object -First 1 }
                if ((Format-Tokens $reference.InnerText) -ne (Format-Tokens $item.InnerText)) {
                    throw "Plural format mismatch: $key/$($item.quantity) in $translated"
                }
            }
        }
        $count++
    }
    foreach ($key in $target.Keys) {
        if (-not $source.ContainsKey($key)) { throw "Unexpected resource $key in $translated" }
    }
    $modules++
}
if ($count -eq 0 -and $RequireComplete) { throw 'No resources were checked.' }
Write-Output "Validated $count strings/plurals across $modules modules for $Locale. This checks structure, not linguistic or device acceptance."
Write-Output "Missing translations: $missing (default-language fallback; completeness required: $RequireComplete)."
