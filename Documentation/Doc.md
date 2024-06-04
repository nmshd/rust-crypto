## Table of Contents

1. [Introduction](#introduction)
    - [Problem Description](#problem-description)
    - [Product Description](#product-description)
2. [Architecture](#architecture)
    - [Component Diagram](#component-diagram)
    - [Explanation](#explanation)
    - [Abstraction Layer](#abstraction-layer)
    - [Libraries](#libraries)
3. [Installation Guide](#installation-guide)
    - [Required Software](#required-software)
4. [Implementations](#implementations)
    - [Supported Devices](#supported-devices)
    - [Devices We Tested On](#devices-we-tested-on)
    - [Performance](#performance)
    - [Feature List](#feature-list)
    - [Supported Algorithms](#supported-algorithms)
    - [Out of Scope](#out-of-scope)
5. [Implementation](#implementation)
    - [Code](#code)
   - [Connection Documentation](#JNI-Implementation)
    - [Javadoc](#javadoc)
    - [Rustdoc](#rustdoc)
6. [Example Usage with Our Custom App](#example-usage-with-our-custom-app)
    - [Code Examples](#code-examples)
7. [Risk Management](#risk-management)
    - [Retrospective](#retrospective)
    - [Risk Identification](#risk-identification)
8. [Next Steps](#next-steps)
    - [Ideas](#ideas)
    - [What Could Be Done](#what-could-be-done)
    - [What Can Be Improved](#what-can-be-improved)
9. [Open Source Project](#open-source-project)
    - [License](#license)
    - [Issue Guide](#issue-guide)
    - [Pull Request Guide](#pull-request-guide)
10. [References](#references)
    - [Source Documents](#source-documents)
    - [Research Documents](#research-documents)

### Introduction
This project is part of a student development project at [Hochschule Mannheim (HSMA)](https://www.english.hs-mannheim.de/the-university.html). The project goal is provided by j&s-soft GmbH as part of their open-source project [enmeshed](https://github.com/nmshd).

### Problem Description
The enmeshed app from j&s-soft GmbH currently secures cryptographic keys in the software. This leads to security vulnerabilities and points of attack. To prevent this, hardware security modules are to be used on which the cryptographic keys are to be securely stored so that they cannot be retrieved even on compressed devices.
Our team was tasked with implementing a solution to this problem in the sub-project for Samsung's secure element, the Knox Vault.

### Product Description
The Repository contains a Wrapper that is used to perform cryptographic operations for mobile applications in a Secure Element (SE) on Android devices. Specifically, this project is focused on Samsung Knox Vault as the SE. The interface to the mobile application is provided in Rust, while the communication with the SE will be done using the Android Keystore system.
## Architecture

### Component Diagram

![component diagram](images/component_diagram.jpg)

### Explanation

### Abstraction Layer

### Libraries

- #### JNI

The Java Native Interface (JNI) is a foreign-function interface (FFI) that supports
cross-communication between Java and native languages such as C or Rust. We use it to
communicate between the Rust- and Java parts of the wrapper by calling Java methods from
the Rust environment and passing parameters that way. The JNI is provided by Oracle and tied directly into the JDK.
To find out more about how the exact communication works, check the [JNI Implementation](#JNI-Implementation).
- **KeyStore API**

The [Android Keystore system](https://developer.android.com/privacy-and-security/keystore) handles the cryptographic keys for us. We went with this over the Knox SDK because it's a better fit for our needs, and even Samsung recommends it in their [Knox Vault Whitepaper](https://image-us.samsung.com/SamsungUS/samsungbusiness/solutions/topics/iot/071421/Knox-Whitepaper-v1.5-20210709.pdf). After more research, it also seemed like the best way to achieve the project goal in the limited time we had.

With the Keystore and other APIs, we can use the keys to encrypt and decrypt data, as well as sign and verify it. The API also helps us solve the problem from j&s-soft, as we can enforce generated cryptographic keys to be saved in the Knox Vault (or any other strongbox).

The Knox Vault doesn't support all the cryptographic algorithms enabled by the Keystore and other APIs. As we couldn't find any detailed documentation about what the Knox Vault supports, we had to test it out by trial and error. You can see all the algorithms that have passed our tests in the [Supported Algorithms](#supported-algorithms) section.

You can find out more about the KeyStore API and other APIs that are normally used with it in the following repository: [Android-Security-Reference](https://github.com/doridori/Android-Security-Reference/blob/master/framework/keystore.md). It also has some useful general info about security on Android.

## Installation Guide

### Required Software
- **Android Studio**
- Additional tools and dependencies

## Implementations

### Supported Devices

### Devices We Tested On

### Performance

### Feature List

### Supported Algorithms

### Out of Scope

## Implementation

### Code

### JNI-Implementation

The basic premise of our JNI connection is to have a `JavaVM` passed to the Rust Code. With this reference we are able
to call methods provided by the [JNI crate](https://crates.io/crates/jni). Those allow us to call Java functions and
pass parameters to them and receive return values and Java exceptions.

In order to aid type conversion, we are currently using Robusta as a wrapper around the JNI, but we are only using
functionality that is provided by the JNI itself, in order to make a future conversion to pure JNI easier.

From the `JavaVM` that is passed in the `KnoxConfig` struct we are able to obtain a `JNIEnv`. For us the most important
method provided by this is this method:

```
call_static_method(&self,
 class: T,
 name: U,
 sig: V,
 args: &[JValue]) 
-> Result<JValue>
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

    call_static_method(  
    "com/example/vulcans_limes/RustDef",  
    "create_key",  
    "(Ljava/lang/String;Ljava/lang/String;)V",  
    &[JValue::from(jnienv.new_string(key_id).unwrap()),  
      JValue::from(jnienv.new_string(key_gen_info).unwrap())]);

### Javadoc

### Rustdoc

## Example Usage with Our Custom App

### Code Examples

## Risk Management

### Retrospective

### Risk Identification

## Next Steps

### Ideas

### What Could Be Done

### What Can Be Improved

## Open Source Project

### License

### Issue Guide

### Pull Request Guide

## References

### Source Documents

### Research Documents
