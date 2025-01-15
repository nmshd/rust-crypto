# Examples

To execute the examples you need to clone this git repository and cd into its root:
```
git clone https://github.com/nmshd/rust-crypto.git
cd rust-crypto
```

## Sign Data Example

> [!WARNING]
> There might be some issues compiling the software provider with gnu windows toolchain.

```
cargo run -F software --example sign_data
```

Example showing how to create a software provider, create a key pair, sign and verify data.