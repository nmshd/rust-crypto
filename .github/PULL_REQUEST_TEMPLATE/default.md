### Added:


### Changed:


### Removed:


### Checklist:
* [ ] Do the unit tests in CAL run? Check at least those that you can run: `cargo test -F software`
* [ ] Are changes in common propagated to all providers that are currently in use? 
    * [ ] `software`
    * [ ] `tpm/android`
    * [ ] `tpm/apple_secure_enclave`
* [ ] Did changes in the API occur, such that `./ts-types` needs to be updated?
* [ ] Does the node plugin (`./node-plugin`) still compile?
* [ ] (flutter things here)
* [ ] There are no build artifacts in the commit. (`node_modules`, `lib`, `target` and everything in `.gitignore`)
