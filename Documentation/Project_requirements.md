# Project requirements

## Functional requirements

1. Secure key management: The wrapper must be able to generate, store and manage keys securely using the HSM.
2. Integration with Samsung Knox Vault: The wrapper must enable the abstraction layer to use the functions of Knox Vault.
3. Access control: The wrapper must ensure that only a correctly authorized application can access the services of the wrapper.
4. Encryption and decryption: The wrapper must offer to encrypt and decrypt data using the keys stored in the HSM.
5. Logging and monitoring: The wrapper must provide a mechanism for logging of key operations and monitoring of access to keys stored in the Knox Vault in order to detect possiblle security breaches

## Non-functional requirements

1. Security: The wrapper must manage the keys securely. To check this requirement, j&s-soft carries out a pentest and incorporates the feedback into the wrapper.
2. Performance: The wrapper must be able to perform frequent operations such as data encryption and decryption in less than one second, provided that this is supported by the hardware security module.
3. Reliability: The wrapper must provide a suitable response for correct requests and respond with an error message for incorrect requests.
4. Compatibility: The wrapper must be compatible with all devices that currently support Knox Vault. A list of these devices can be found in the Documentation. Compliance with this requirement can only be checked for devices that are available to Vulcan's Limes.
5. Integration with Samsung Knox SDK: The wrapper must be integrated with the Samsung Knox SDK in order to access and use the security functions and capabilities of Knox Vault.
8. Implementation of the abstraction layer: The wrapper must enable all implementable functions of the abstraction layer
9. Programming language: The wrapper is written in the Rust programming language.
6. Maintainability: The code of the wrapper is documented so that any subsequent further development by other persons is possible.
7. Documentation: Documentation is provided for the wrapper that describes installation, configuration and use.
