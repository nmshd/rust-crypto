# Rust Binary calls Swift Package

In this example we create a Rust binary that statically links to a Swift Package.

This means that we:

1. Use `swift-bridge-build` to generate our Swift FFI layer.

2. Compile the Swift Package into a static library. We include our generated `swift-bridge` FFI glue from step 1.

3. Compile our Rust executable. Along the way we link to our Swift static library.

