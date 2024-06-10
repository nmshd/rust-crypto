
# Documentation

## Introduction
This project is part of a student development project at [Hochschule Mannheim (HSMA)](https://www.english.hs-mannheim.de/the-university.html). The project goal is provided by j&s-soft GmbH as part of their open-source project [enmeshed](https://github.com/nmshd).

### Problem Description
The enmeshed app from j&s-soft GmbH currently secures cryptographic keys in the software. This leads to security vulnerabilities and points of attack. To prevent this, hardware security modules are to be used on which the cryptographic keys are to be securely stored so that they cannot be retrieved even on compromised devices. Our team was tasked with implementing a solution to this problem in the sub-project for Samsung's secure element, the Knox Vault.

### Product Description
This Repository contains a Wrapper that is used to perform cryptographic operations for mobile applications in a Secure Element (SE) on Android devices. Specifically, this project is focused on Samsung Knox Vault as the SE. The interface to the mobile application is provided in Rust, while the communication with the SE will be done using the Android Keychain API.


## Table of Contents
1. [Introduction](#introduction)
    - [Problem Description](#problem-description)
    - [Product Description](#product-description)
2. [Comprehensive Overview](#comprehensive-overview)
    - [Supported Devices](#supported-devices)
    - [Performance](#performance)
    - [Feature List](#feature-list)
    - [Supported Algorithms](#supported-algorithms)
3. [Installation Guide](#installation-guide)
    - [Required Software](#required-software)
4. [Usage](#usage)
5. [Architecture](#architecture)
    - [Component Diagram](#component-diagram)
    - [Components](#components)
    - [Libraries](#libraries)
6. [Implementation](#implementation)
    - [JNI-Implementation](#jni-implementation)
    - [Javadoc](#javadoc)
    - [Rustdoc](#rustdoc)
7. [Next Steps](#next-steps)
    - [Ideas for our wrapper](#ideas-for-our-wrapper)
    - [Ideas for the crypto layer](#ideas-for-the-crypto-layer)
8. [Open Source Project](#open-source-guidelines)
9. [References](#references)



## Comprehensive Overview

<details open>  
  <summary>

### Supported Devices
</summary>  

This wrapper should work for all Android devices equiped with a SE, but the focus for our group is specifically on smartphones using Samsung Knox Vault. Therefore, testing will only be done using a Samsung smartphone, and in case there are incompatibilities between device manufacturers, Samsung will take priority. An up-to-date list of devices equipped with Knox Vault can be found [here](https://www.samsungknox.com/en/knox-platform/supported-devices) after selecting Knox Vault in the filter options. As of April 2024, the following devices are equipped with Knox Vault:

Smartphones
- Samsung Galaxy A 35 / A55
- Samsung Galaxy S 22 / S23 / S 24
    - the plus / ultra versions as well
- Samsung Galaxy Z Flip 3 / 4 / 5
- Samsung Galaxy Z Fold 3 / 4 / 5
- Samsung Galaxy X Cover 7 (Enterprise Edition)

Tablets
- Galaxy Tab S 8 / S 9
    - the plus, ultra, FE and 5G versions as well
- Galaxy Tab Active 5 (Enterprise Edition)
    - the 5G version as well

We have received a Samsung S22 from j&s-soft and have used this device for testing purposes throughout the project.
</details>  

<details open>  
  <summary>

### Performance
</summary>  

After an extensive performance test, we can conclude that data encryption using AES-256-CBC on the Knox Vault Chip occurs at a rate of approximately 0.11 MB/s. The test showed a variance of 0.58 s².
</details>  

<details open>  
  <summary>

### Feature List
</summary>  

Our project supports the following features:

- **Saving keys in the strongbox**: All generated keys are stored securely within the strongbox.
- **Encrypt and Decrypt Data**: Utilizing symmetric encryption, our system ensures data confidentiality through encryption and decryption mechanisms.
- **Sign and Verify Data**: We provide functionality for asymmetric signing and verification, ensuring data integrity and authenticity.

In the following chapter, you will find detailed information on the supported algorithms.
</details>  

<details open>  
  <summary>

### Supported Algorithms
</summary>  

We have provided a list of the supported Algorithms of our project:

| Algorithm Type    | Details                                     |  
|-------------------|---------------------------------------------|
| **ECC**           | **Curve / Hashing**              |  
|                   | secp256r1 / SHA-256                            |  
|                   | secp384r1 / SHA-256                         |  
|                   | secp521r1 / SHA-256                         |  
| **RSA**           | **Keysize / Hashing / Padding**           |  
|                   | 512 / SHA-256 / PKCS1                       |  
|                   | 1024 / SHA-256 / PKCS1                      |  
|                   | 2048 / SHA-256 / PKCS1                      |  
|                   | 3072 / SHA-256 / PKCS1                      |  
|                   | 4096 / SHA-256 / PKCS1                      |  
|                   | 8192 / SHA-256 / PKCS1                      |  
|          |                       | | **Symmetric**     | **Keysize / Block Mode / Padding**          |  
| **3DES**          | 168  CBC / PKCS7Padding                     |  
| **AES**           | 128 / GCM / NoPadding                       |  
|                   | 128 / CBC / PKCS7Padding                    |  
|                   | 128 / CTR / NoPadding                       |  
|                   | 192 / GCM / NoPadding                       |  
|                   | 192 / CBC / PKCS7Padding                    |  
|                   | 192 / CTR / NoPadding                       |  
|                   | 256 / GCM / NoPadding                       |  
|                   | 256 / CBC / PKCS7Padding                    |  
|                   | 256 / CTR / NoPadding                       |
</details>  

## Installation Guide

<details open>  
  <summary>

### Required Software
</summary>   

If you want to build this project on your own from the source code, these tools are necessary:

- Android Studio is an IDE specifically for Android app development. While not strictly necessary, having it will make all further steps easier. This guide will assume that you are using it.
- If you plan on modifying the Rust code, it might be smart to also have RustRover installed, since there is no Rust plugin for Android Studio.
- RustUp is the easiest way to install Rust and Cargo. Installation is easiest from within RustRover: After starting to create a new project, there will be a button below the toolchain location selection. Pressing it will install RustUp. Alternatively you can also install RustUp directly from [their page](https://rustup.rs/).
- You will need the Android NDK (Native Development Kit) to build and run the project. The NDK can be installed from within Android Studio: Go to Settings > Languages & Frameworks > Android SDK > SDK Tools and select and install the NDK.
- Cargo and [cargo-ndk](https://docs.rs/crate/cargo-ndk/3.5.4) are necessary to compile the Rust code in a format usable by Android. Cargo should already be installed by RustUp, cargo-ndk can be installed with `cargo install cargo-ndk`.
- You will need to configure cargo further by using this command: `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android` (The "linux" in this command refers to the phone architecture, not your development machine. You can use this command on Windows as well). This will make cargo compile your Rust code in a format suitable for Android architectures
</details>   

<details open>   
<summary><strong>Installing Android Studio + RustRover</strong></summary>    

The easiest way to install both IDEs is to use the [JetBrains Toolbox](https://www.jetbrains.com/de-de/toolbox-app/), where you can install both IDEs with a single click each.    
Alternatively you can also refer to the [Android CodeLab guide](https://developer.android.com/codelabs/basic-android-kotlin-compose-install-android-studio#0), and the [RustRover download page](https://www.jetbrains.com/rust/nextversion/).

</details>
<details open>    
<summary>

### First test in Android Studio
</summary>   

The goal of this section is to test Android Studio and run a "Hello World"-App on a real device to confirm that the connection between the computer and phone is working. We will use a USB connection to get the app onto the device, although Wi-Fi should also be possible. This step is not strictly necessary, but eliminates a possible source of error later on.

- Make sure that USB debugging is enabled on the phone. Refer to [this guide](https://developer.android.com/studio/debug/dev-options) if necessary.
- Install the proper driver for your smartphone on your PC / Laptop according to [this list](https://developer.android.com/studio/run/oem-usb#Drivers).
- Open a new project in Android Studio and select Phone/Tablet on the left and use "Empty Activity" as the template.
- Plug your phone into your PC / Laptop with a USB cable capable of transmitting data.
- You should be able to see your phone's storage in your file explorer.
- In Android Studio, go to "Running Devices" (on the top right by default), click on the plus sign and select your phone.
- The screen of your phone will be mirrored inside Android Studio.
- Build and run your application and open it on the phone.
</details>  

<details open>   
<summary>

### Creating a project combining Rust and Java
</summary>  

If you already have a project combining Rust and Java, you can skip this section. Otherwise, here is a quick guide for a minimal Project combining the two using [Robusta](https://github.com/giovanniberti/robusta/tree/master).

- Create a new Android studio project (or use an existing one), that fits your needs for the Android/Java side of your project.
- Create a new folder `rust` in your project files that has the same parent folder as `app`.
- Create a `Cargo.toml` file in that folder with the following content: [`Cargo.toml`](resources/Cargo.toml).
- Create a `lib.rs` file in the same folder with the following content:  [`lib.rs`](resources/lib.rs).
- Adjust the package marker for the `RustDef` struct in `lib.rs` on line 14 to contain the correct java package.
</details>  

<details open>   
<summary><strong>Integrating this Repo into your project</strong></summary>  

- Fork this Repo and integrate it into the project you created as a submodule. This can be done with:
    ```  
  git submodule add <Link to your forked Repo>  
git submodlue update --init --recursive ```- The two files `CryptoManager.java` and `RustDef.java` in [`src/tpm/android/knox/java`](https://github.com/cep-sose2024/rust-crypto-knox/tree/main/src/tpm/android/knox/java) will need to be moved to the other Java files in your project. By default, this is something like `src/main/java/com/example/example_project`.
- Adjust the `const CLASS_SIGNATURE` in [`src/tpm/android/knox/interface.rs`](https://github.com/cep-sose2024/rust-crypto-knox/blob/main/src/tpm/android/knox/interface.rs) to match the package that you put `RustDef.java` into. For the example above, that would be `const CLASS_SIGNATURE: &str = "com/example/example_project/RustDef";` 
</details>

<details open>  
<summary>

### Building and running the project
</summary>  

Now you are ready to compile everything. The following command will compile all your Rust code into a dynamic library (`.so`) that can be used by your android app. You will need to run this command within your `rust` folder:

cargo ndk -t armeabi-v7a -t arm64-v8a -o ../app/src/main/jniLibs build After completing that step, check the directory specified in the command (`app/src/main/jniLibs` in this example). You should find two files `libexampleproject.so` in a sub directory. If so, then the last step was successful. Now you will  need to adjust which library Java is looking for. This can be found in `RustDef.java` in line 57.  Set the string there to the same as the name of your package in the `rust/Cargo.toml` that you created for your main project.

Afterwards, you can compile your Java code. You will need to specify the location that the compiled Rust library is in.  The easiest way to do that is by specifying the library path when running gradle like this:

.\gradlew -D java.library.path=app/src/main/jniLibs installDebug With that, you should have everything complete and compiled the project from scratch.
</details>  

## Usage

Example of how to create a provider and initialize it:
```rust  
let instance = SecModules::get_instance(    
    "test_key".to_owned(),    
    SecurityModule::Tpm(TpmType::Android(AndroidTpmType::Knox)),    
    None)
.unwrap();
let mut module = instance.lock().unwrap();  
```  
To create a key, first you will have to decide which algorithm to use, then set a unique alias for the key. Finally, you can create a key. Here is an example of how that could look like:
```rust  
let sym_key = Aes(SymmetricMode::Cbc, Bits128); //Key to be used for symmetric encryption let asym_key = Rsa(Bits2048); //Key to be used for asymmetric encryption  
  
// creating a symmetric key  
let keyname: &str = "sym_key"; 
let config = Box::new(KnoxConfig::new(None,    
                                      Some(sym_key),    
                                      environment.get_java_vm().unwrap())    
.expect("Failed to create KnoxConfig")); 
let result = module.create_key(keyname, config);  
  
// creating an asymmetric key  
let keyname: &str = &format!("Asym{}", "asym_key");
let config = Box::new(KnoxConfig::new(Some(asym_key),    
                                      None,    
				      environment.get_java_vm().unwrap())); 
module.create_key(keyname, config)  
```  
So now that we know how to create keys, let us look at examples of how to use them.  
First, we will need to load a key to be used.
```rust  
// loading a symmetric key  
let config = Box::new(KnoxConfig::new(None,    
                                      Some(sym_key),    
				      environment.get_java_vm().unwrap()));
module.load_key(keyname, config); 
let config = Box::new(KnoxConfig::new(Some(asym_key),    
                                      None,    
				      environment.get_java_vm().unwrap())); 
module.load_key(keyname, config)  
```  
Now that we loaded the key, we can use encrypt & decrypt, or sign & verify. Here is an example:
```rust  
let clear_data: &[u8] = &[1, 0, 255]; //Data to be symmetrically encrypted let sign_data: &[u8] = &[1, 0, 255]; //Data to be signed by the asym key  
  
// after loading a symmetric key, we can encrypt or decrypt  
let enc_data = module.encrypt_data(clear_data)  
let dec_data = module.decrypt_data(&enc_data)  
  
// after loading an asymmetric key, we can sign or verify  
let verify_data = module.sign_data(sign_data)  
let result_verify = module.verify_signature(&sign_data, &verify_data)  
```  

- If the method call is successful `(Ok(..))`, `Ok(())` is returned.
- In the event of an error `(Err(e))`, the exact error is examined and a corresponding error message is returned.






## Architecture
<details open>  
  <summary>

### Component Diagram
</summary>   

![component diagram](resources/component_diagram.jpg)
</details>  

<details open>  
<summary>

### Components
</summary>   

The component diagram illustrates the relationships and interactions between the different classes and modules of the project. Here are the main components:

- **CryptoManager**:  
  The `CryptoManager` class handles cryptographic operations within the Android environment. It provides functions for generating and storing symmetric and asymmetric keys in the Android Keystore, as well as for encrypting and decrypting data. Additionally, it enables signing and verifying data using keys stored in the Keystore.


- **RustDef**:   
  The `RustDef` class defines the interface to the cryptographic functions implemented in Rust. It loads the native library.


- **interface.rs**:  
  `interface.rs` serves as the interface between the Rust implementation and the Java side, acting as the counterpart to `RustDef.java`. It facilitates seamless communication between Rust and Java, allowing for the invocation of Rust functions from Java code. This enables developers to leverage the robust cryptographic capabilities implemented in Rust within their Android applications.
</details>  

<details open>   
<summary>

### Libraries
</summary>   

- #### JNI

The Java Native Interface (JNI) is a foreign-function interface (FFI) that supports  
cross-communication between Java and native languages such as C or Rust. We use it to  
communicate between the Rust- and Java parts of the wrapper by calling Java methods from  
the Rust environment and passing parameters that way. The JNI is provided by Oracle and tied directly into the JDK.  
To find out more about how the exact communication works, check the [JNI Implementation](#JNI-Implementation).
- **KeyStore API**

The [Android Keystore system](https://developer.android.com/privacy-and-security/keystore) handles the cryptographic keys for us. We went with this over the Knox SDK because it's a better fit for our needs, and even Samsung recommends it in their [Knox Vault Whitepaper](https://image-us.samsung.com/SamsungUS/samsungbusiness/solutions/topics/iot/071421/Knox-Whitepaper-v1.5-20210709.pdf).

With the Keystore and related APIs, we can use keys to encrypt and decrypt data, as well as sign and verify it. The API also helps us solve the central requirenment from j&s-soft, as we can enforce generated cryptographic keys to be saved in the Knox Vault (or any other strongbox).

The Knox Vault doesn't support all the cryptographic algorithms enabled by the Keystore and other APIs. As we couldn't find any detailed documentation about what the Knox Vault supports, we had to test it out by trial and error. You can see all the algorithms that have passed our tests in the [Supported Algorithms](#supported-algorithms) section.

You can find out more about the KeyStore API and other APIs that are normally used with it in the following repository: [Android-Security-Reference](https://github.com/doridori/Android-Security-Reference/blob/master/framework/keystore.md). It also has some useful general info about security on Android.
</details>  

## Implementation
<details open>  
<summary>

### JNI-Implementation
</summary>   

The basic premise of our JNI connection is to have a `JavaVM` passed to the Rust Code. With this reference we are able  
to call methods provided by the [JNI crate](https://crates.io/crates/jni). Those allow us to call Java functions and  
pass parameters to them and receive return values and Java exceptions.

In order to aid type conversion, we are currently using Robusta as a wrapper around the JNI, but we are only using  
functionality that is provided by the JNI itself, in order to make a future conversion to pure JNI easier.

From the `JavaVM` that is passed in the `KnoxConfig` struct we are able to obtain a `JNIEnv`. For us the most important  
method provided by this is this method:

```  
call_static_method(&self,  
 class: T, name: U, sig: V, args: &[JValue]) -> Result<JValue>  
```  

This method gets the class definition with the full package name,  
the name of the method in the class,  
a signature of the parameters used by the method,  
and finally the parameters themselves as JValues.

The class and method name can be determined manually, but the signature should always be automatically generated. To do  
this, call the following command on the commandline:

javap -s -p path/to/the/java/file.class  
with the compiled `.class` file. This will print all method signatures to the command line, including the name and the  
parameter signature needed for `sig`.

The conversion of your parameters to JValues can be done through `JValue::from(<xyz>)` most of the time.

The method returns a JValue containing the return type of the Java method that needs to be converted back to Rust data  
types. If a Java exception is thrown, the method returns an Error.

Example:

call_static_method(    "com/example/vulcans_limes/RustDef",    
"create_key",    
"(Ljava/lang/String;Ljava/lang/String;)V",    
&[JValue::from(jnienv.new_string(key_id).unwrap()),    
JValue::from(jnienv.new_string(key_gen_info).unwrap())]);
</details>  

<details open>  
<summary>

### Javadoc
</summary>   

All used Java code is documented [here](JavaDoc/index.html).

</details>  

<details open>  
<summary>

### Rustdoc
</summary>   

All used Rust code is documented [here](RustDoc/crypto_layer/index.html).

</details>  


## Next Steps
This chapter is all about looking to the future and thinking about how to take this project in new directions.
<details open>  
<summary>

### Ideas for our wrapper
</summary>   

- Check out how many keys the Knox Vault can store and document the result, as apparently the Keystore API does not limit how many keys can be stored. This theoretically means the only limit is the available data storage the Vault has for keys.
- Improve the encrypt and decrypt methods so they can use asymmetric keys.
- Implement a modular key usage handling system. The system should take the information about the key usages when the key gets created, and create it with these specific purposes (e.g. encrypt, decrypt, sign, verify, key lifetime, limited key usages).
- Have a broader spectrum of devices to test on. Knox Vault should technically not be different on the current devices, though in the future that might change. Newer security modules might provide more cryptographic algorithms or performance in the future.
- Obtain a reference to the JavaVM without having to pass it to the crypto layer.
</details>  

<details open>  
<summary>

### Ideas for the crypto layer
</summary>   

- Encryption and Decryption in Knox Vault is very slow. So creating derived keys for encryption and decryption outside of the security module will speed this process up immensely. The drawback however, this comes with security considerations.
- Implementing some kind of attestation, if possible, so the enmeshed app knows its communicating with a security module, and which security module. (e.g. for our case the Google attestation service)
- A method that lists and returns all the capabilities/supported algorithms the wrapper and security module provide.
- a method that returns metadata about the loaded key like usages, algorithm, etc.
 
</details>

## Open Source Guidelines

This Project is published under an [MIT License](https://github.com/cep-sose2024/rust-crypto-knox/blob/4989f3eb36552537e00fe58cbd29fa95312a6892/LICENSE).

A Contribution guide can be found [here](https://github.com/nmshd/.github/tree/main).





## References
[Samsung Knox Whitepaper](https://image-us.samsung.com/SamsungUS/samsungbusiness/solutions/topics/iot/071421/Knox-Whitepaper-v1.5-20210709.pdf): Hold information about Samsung Knox, but also about the Knox Vault feature.

[Android Keystore system](https://developer.android.com/privacy-and-security/keystore): Holds information about the Keystore system, how to use the Android keystore, as well as leading to other Android developer documents.

[Robusta](https://github.com/giovanniberti/robusta/tree/master): The library we use for easier communication between Rust and Java.

[Java Native Interface (JNI)](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/): Needed for the communication between Rust and Java, Robusta makes using this interface easier for us.

[j&s-soft GmbH](https://www.js-soft.com/en/): The company behind enmeshed and the client for this project.

[enmeshed](https://github.com/nmshd): An app developed by j&s-soft that provides secure communication between education providers and individuals.

[Hochschule Mannheim (HSMA)](https://www.english.hs-mannheim.de/the-university.html): The university of applied science cooperating with j&s-soft for this project.
