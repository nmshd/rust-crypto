
cd ..

$prevEnv = $env:TS_RS_EXPORT_DIR

$env:TS_RS_EXPORT_DIR="./ts-interface/src/types"
cargo test -F ts-interface export_bindings

$env:TS_RS_EXPORT_DIR = $prevEnv

cd ./ts-interface


if (Test-Path "./src/types/index.ts") {
    Remove-Item "./src/types/index.ts"
}

Get-ChildItem ./src/types/*.ts -Exclude "index.ts" | foreach {
    $mod = ($_).BaseName
    Write-Host "Writing $mod"
    "export * from './$mod';" >> ./src/types/index.ts
}