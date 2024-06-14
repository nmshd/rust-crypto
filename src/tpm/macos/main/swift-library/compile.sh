if [ $# -eq 0 ]; then
  echo "No target as argument given. Please provide 'ios' or 'macos' as target."
  exit 1
fi

TARGET=$1

if [ "$TARGET" == "ios" ]; then
    swiftc -target arm64-apple-ios14.0 -sdk $(xcrun --sdk iphoneos --show-sdk-path) -emit-library -static -F /swift-library/ -o ./.build/libswift-library_ios.a ./Sources/swift-library/SecureEnclaveManager.swift ./Sources/swift-library/generated/SwiftBridgeCore.swift ./Sources/swift-library/generated/rust-calls-swift/rust-calls-swift.swift  -import-objc-header ./Sources/swift-library/bridging-header.h
    echo "Compiled for: $TARGET"

elif [ "$TARGET" == "macos" ]; then
    swift build -Xswiftc -static -Xswiftc -import-objc-header -Xswiftc ./Sources/swift-library/bridging-header.h
    echo "Compiled for: $TARGET"

else
    echo "No valid target as argument. Please choose 'ios' or 'macos' as targets."
fi
