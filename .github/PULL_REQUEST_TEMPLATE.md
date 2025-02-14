### Added:

### Changed:

### Removed:

### Checklist:

-   [ ] Do the unit tests in CAL run? Check at least those that you can run: `cargo test -F software`
-   [ ] Are changes in common propagated to all providers that are currently in use?
    -   [ ] `software`
    -   [ ] `tpm/android`
    -   [ ] `tpm/apple_secure_enclave`
-   [ ] Did changes in the API occur, such that `./ts-types` needs to be updated?
    -   [ ] [Generate types partially](https://github.com/nmshd/rust-crypto/tree/main/ts-types#generate-the-types).
    -   [ ] Have you given the maintainer of [`crypto-layer-node`](https://github.com/nmshd/crypto-layer-node) a heads up?
-   [ ] Do the dart bindings have to be [re-generated](https://github.com/nmshd/rust-crypto/tree/main/flutter_plugin#generating-dart-bindings)?
-   [ ] Does the flutter plugin still compile?
-   [ ] Do the integration tests in flutter-app still [run](https://github.com/nmshd/rust-crypto/tree/main/flutter_app#running-the-app)?
-   [ ] There are no build artifacts in the commit. (`node_modules`, `lib`, `target` and everything in `.gitignore`)
