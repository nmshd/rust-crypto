# Crypto-Layer TS Type Definitions

This is an npm package with the ts type defintions of the CAL project.

## Use the Package with [GitPkg](https://gitpkg.vercel.app/)

```
npm install 'https://gitpkg.vercel.app/nmshd/rust-crypto/ts-types?main&scripts.postinstall=npm%20i%20--ignore-scripts%20%26%26%20npm%20run%20build'
```

## Build Package

1. You need to have rust installed.
2. You need to have npm or similar installed.

<a name="generation" />

### Generate the Types

```
.\Generate-Types.ps1
```

### Build the Package

```
npm i
npm run build
```

## Usage

Add the npm package as dependecy

```
npm add --save ./PathToLib/rust-crypto/ts-types/
```

Import the types

```ts
import { type EccCurve } from "crypto-layer-ts-types";
```
