# Example Flutter App integration

This repository additionally contains a Flutter native plugin and an example Flutter app to test the Crypto Abstraction Layer, currently only supporting Android.

To run this App, the following tools are reqiuired:

-   Rust compiler
-   Rust aarch64-linux-android and armv7-linux-androideabi toolchains
-   cargo-ndk
-   Android Debug Bridge (adb)
-   Flutter
-   Android SDK
-   Android NDK

## Dependencies

```
# rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# toolchains
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android

# cargo-ndk
cargo install cargo-ndk
```

Addidtionally install Flutter and either install Android Studio or Download the Android SDK
Now you can install the NDK with:

```
sdkmanager ndk-bundle
```

<a name="run" />

## Running the App

Get the id of the connected Android device with `flutter devices`, then run the App in debug mode:

```
cd flutter_app
flutter run -d $DEVICEID
```

This should compile the Rust code and the plugin and start the App on the device.

As Android Emulators don't contain a Secure Element, the App was only tested on real devices.
