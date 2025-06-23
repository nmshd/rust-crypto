# Testing the Apple Secure Enclave Provider

An executable running the apple secure enclave provider musst be signed with the right entitlements.
This in turn means, that the unit tests also need to be signed.
The powershell scrip [`execute_test.ps1`](./execute_test.ps1) builds the unit tests for the apple secure enclave provider,
signs said unit tests,
given a valid certificate id,
and executed the unit test.

Valid certificates can be found by running:
```
security find-identity -p codesigning -v
```

For more information please visit https://github.com/cep-sose2024/binary_knights/tree/main?tab=readme-ov-file#commands .
