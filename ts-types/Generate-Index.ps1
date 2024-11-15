
if (Test-Path "./index.d.ts") {
    Remove-Item "./index.d.ts"
}

Get-ChildItem ./types/*.ts | foreach {
    $mod = ($_).Name
    Write-Host "Writing $mod"
    "export * from './types/$mod';" >> index.d.ts
}