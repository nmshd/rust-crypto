# crypto-layer-ts-types

**Generated TS Types for the Crypto-Layer Crate.**

## Build

```pwsh
cd ..
$env:TS_RS_EXPORT_DIR="./ts-types/types"
cargo test -F ts-interface export_bindings
cd ./ts-types
pwsh Generate-Index.ps1
```

