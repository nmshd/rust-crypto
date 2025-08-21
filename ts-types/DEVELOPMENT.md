# Crypto-Layer TS Type Definitions Development Documentation

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

## Creating a New Release

* Update the version in [`package.json`](./package.json).
* Update `package-lock.json` by calling
    ```sh
    npm update
    ```
* Merge your changes onto `main` branch.
* Call the `Release` (`release.yml`) GitHub action. The action should publish the new version of the package.
