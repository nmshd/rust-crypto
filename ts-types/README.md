# Crypto-Layer TS Type Definitions

[![NPM Version](https://img.shields.io/npm/v/%40nmshd%2Frs-crypto-types)](https://www.npmjs.com/package/@nmshd/rs-crypto-types)

This is an npm package with the ts type definitions of the CAL project.

## Usage

Add the npm package as dependency:
```sh
npm add --save @nmshd/rs-crypto-types
```

Import the types

```ts
import { type EccCurve } from "crypto-layer-ts-types";
```

## Build Package

1. You need to have rust installed.
2. You need to have npm or similar installed.

### Generate the Types

```pwsh
.\Generate-Types.ps1
```

Or if you have [task](https://taskfile.dev/) installed, run:
```sh
task gents testts
```

### Build the Package

```
npm i
npm run build
```

