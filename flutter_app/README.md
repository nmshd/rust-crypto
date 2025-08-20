# Example Flutter App

Example flutter app using [crypto-layer](../README.md) via the [`cal_flutter_plugin`](../cal_flutter_plugin/README.md). 


## Prerequisites

To run this App, the following tools are required:

-   [Rust compiler](https://www.rust-lang.org/tools/install)
-   [Flutter](https://docs.flutter.dev/get-started/install)


### Android Specifics

-   [cargo-ndk](https://github.com/bbqsrc/cargo-ndk?tab=readme-ov-file#installing)
    -   Do not forget to install cargo-ndk dependencies (the toolchains) first!
-   Android SDK
-   Android Debug Bridge (adb)
-   Android NDK


## Running the App

> [!TIP]
> Android Emulators don't contain a Secure Element.

1. Start an emulator (`flutter emulators --launch ____`) or connect a device.
2. Compile and run the app:
    ```sh
    flutter run
    ```

You might also want to use a specific device:
1. List connected devices:
    `flutter devices`
2. Compile and run the app:
    `flutter run -d ______`

## Logs

See the [`cal_flutter_plugin` documentation](../cal_flutter_plugin/README.md#reading-logs).
