# Crypto-Layer TS Type Definitions

[![NPM Version](https://img.shields.io/npm/v/%40nmshd%2Frs-crypto-types)](https://www.npmjs.com/package/@nmshd/rs-crypto-types)

This is an npm package with the ts type defintions of the CAL project.

## Build Package

1. You need to have rust installed.
2. You need to have npm or similar installed.

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
