
param(
    [String]$SigningKeyHash
)

Write-Host "Compiling Debug Test Build"
[string]$cargo_test_output = cargo test -F "apple-secure-enclave,software" --no-run 2>&1
$path_regex = [regex]"target\/debug\/deps\/crypto_layer-[a-z0-9]*"

if ($cargo_test_output -match $path_regex) {
    $debug_binary_path = $Matches[0]
    Write-Host $debug_binary_path
    
    Write-Host "Signing"
    [string]$signature_output = codesign -f -s $SigningKeyHash --entitlements binary-knights.entitlement -o runtime -i "de.jssoft.BinaryKnights" $debug_binary_path 2>&1

    if (-not $?) {
        Write-Error "Failed to sign executable:`r`n$signature_output" -ErrorAction Stop
    }

    Write-Host "Executing Tests"
    & $debug_binary_path
}
else {
    Write-Host $cargo_test_output
    Write-Error "Failed to match cargo test output." -ErrorAction Stop
}