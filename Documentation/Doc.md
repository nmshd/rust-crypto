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
    - [Connection Documentation](#connection-documentation)
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
![Komponentendiagramm](../Documentation/BSP.jpg)

### Explanation

### Abstraction Layer

### Libraries
- **Robusta**
- **JNI**
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

### Connection Documentation

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
