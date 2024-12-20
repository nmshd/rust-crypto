$ErrorActionPreference = "Stop"

$pkgRoot = $PSScriptRoot
$indexFilePath = "generated/index.ts"

$indexFileFullPath = Join-Path $pkgRoot $indexFilePath
$indexFileParentPath = Split-Path -Path $indexFileFullPath -Parent

$rustLibPath = (gi $pkgRoot).Parent


$prevEnv = $env:TS_RS_EXPORT_DIR
$env:TS_RS_EXPORT_DIR = $indexFileParentPath
cd $rustLibPath

cargo test -F ts-interface export_bindings

cd $pkgRoot
$env:TS_RS_EXPORT_DIR = $prevEnv


if (Test-Path $indexFileFullPath) {
    Remove-Item $indexFileFullPath
}

Get-ChildItem "$indexFileParentPath/*.ts" -Exclude "index.ts" | foreach {
    $mod = ($_).BaseName
    Write-Host "Writing $mod"
    "export * from './$mod';" >> $indexFileFullPath
}