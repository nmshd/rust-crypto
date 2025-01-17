# Contribution Guide

## Style

Your coding style should follow the [official rust style guide](https://doc.rust-lang.org/nightly/style-guide/).

* `rustfmt` should be activated with it's default settings.
* If available use [`Even Better TOML`](https://marketplace.visualstudio.com/items?itemName=tamasfe.even-better-toml) formatter.


## Error Handling

* Errors should, when available be wrapped with `CalError` before returning. 
    * Make use of `CalErrorKind` categories. 
    * The source error should be wrapped into an `anyhow::Error` and be set as source.
    * Errors should be logged with `tracing::error!()` right where they are first seen.
    * Structured logging should always be preffered: `tracing::error!(error=the_error_Im_logging, "My error message")` ✔️
    * Do not log `CalError` as debug print: `tracing::error!("{:?}", the_error_Im_logging)` ❌
    * Consider using `#[tracing::instrument(level = "trace")]` for complex functions.
    * Consider using `#[tracing::instrument]` for important functions, like `delete()`.
    * **Never log secrets!**. Skip secrets: `#[instrument(skip(secret1, secret2))]` or `#[instrument(skip_all)]`


## Commits

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) guidelines.


## Branch Names

Branch names must adhere to the following schme: `the-operation/the-thing-being-worked-on`

```
feature/structured-error-logging
```
```
fix/program-crash-on-second-provider-creation
```


## Pull Requests

A PR should have a good description of what has been added, changed and removed. Examples might be usefull.

Before merging a PR go over the [checklist](.github/PULL_REQUEST_TEMPLATE/default.md).


## Examples

The examples should cover the core use cases of the library.


## Sub Projects

### README

The README of the subprojects should describe how to build and test the subprojects.

