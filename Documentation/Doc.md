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

## Introduction
In today's digital era, safeguarding sensitive data on mobile devices is paramount. Our project focuses on enhancing data security by developing a wrapper for the Crypto Abstraction Layer. This wrapper enables access to a Hardware Security Module (HSM) through Samsung Knox Vault. By securely storing encryption keys within the HSM, we ensure robust protection for data stored on Samsung devices.

### Problem Description
In today's digital age, the security of data stored on mobile devices is of paramount importance. Sensitive information, whether personal or professional, is frequently stored on smartphones, making them a prime target for cyber threats. Ensuring the confidentiality, integrity, and accessibility of this data requires robust encryption and secure key management solutions.

### Product Description
Our project aims to address this critical need by developing a comprehensive solution for encrypting data stored on mobile devices. Specifically, our task is to write a wrapper for the proposed Crypto Abstraction Layer to access a specific hardware security module (HSM) on Samsung devices using Samsung Knox Vault. This solution ensures that encryption keys are securely stored and managed within the HSM, providing an added layer of security for the encrypted data.
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
