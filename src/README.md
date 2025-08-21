`crypto-layer` is meant as a library interfacing with secure elements of different operating systems.

# Providers

Every operating system provides a different native API for accessing secure elements.
Providers are implementations of the `crypto-layer` API.

Though there are some caveats:

-   The `crypto-layer` API is vast and not every provider supports all algorithms or operations!
-   Some of the `crypto-layer` API is not applicable to every provider.

There are following providers:

-   `ANDROID_PROVIDER` and `ANDROID_PROVIDER_SECURE_ELEMENT` (Android)
    -   These two providers differ in the security they minimally provide.
        `ANDROID_PROVIDER_SECURE_ELEMENT` always uses a [Strongbox](https://source.android.com/docs/compatibility/15/android-15-cdd#9112_strongbox),
        while `ANDROID_PROVIDER` may use secure elements that are not certified **or non at all!**
-   `APPLE_SECURE_ENCLAVE` (IOS and MacOS)
    -   Is only usable, when the application using `crypto-layer` is code signed!
    -   Supports asymmetric cryptography including asymmetric hybrid encryption schemes.
-   `SoftwareProvider` (Fallback)
    -   Supports every operating system, but also does not make use of any secure element.

Currently there is no good way to check, what provider supports what operation explicitly.
A provider returns an error with `CalErrorKind::NotImplemented`, if an operation is not supported or implemented.
