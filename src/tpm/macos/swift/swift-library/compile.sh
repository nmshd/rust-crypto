
compile_files_path='.build/libswift-library_ios.a Sources/swift-library/SecureEnclaveManager.swift Sources/swift-library/generated/SwiftBridgeCore.swift Sources/swift-library/generated/rust-calls-swift/rust-calls-swift.swift'
compile_header_path='Sources/swift-library/bridging-header.h'

regex_file_path='\.build/libswift-library_ios\.a (Sources/[a-zA-Z_/-]+\.swift )+'
regex_header_path='^Sources\/[a-zA-Z0-9_-]+\/bridging-header\.h$'

TARGET=$1

file_path_valid=true
is_valid_file_path() {
    if echo "$compile_files_path" | grep -qE "$regex_file_path"; then
        echo "valid files path"
        file_path_valid=true # valid file path
    else
        echo "unvalid header path"
        file_path_valid=false # unvalid file path
    fi
}

headder_path_valid=true
is_valid_header_path() {
    if echo "$compile_header_path" | grep -qE "$regex_header_path"; then
        echo "valid header path"
        headder_path_valid=true # valid header path
    else
        echo "unvalid header path"
        headder_path_valid=false # unvalid header path
    fi
}

is_valid_file_path
is_valid_header_path 

if $file_path_valid && $headder_path_valid; then
    if [ $# -eq 0 ]; then
        echo "No target as argument given. Please provide 'ios' or 'macos' as target."
        exit 1
    fi

    if [ "$TARGET" == "ios" ]; then
        swiftc -target arm64-apple-ios14.0 -sdk $(xcrun --sdk iphoneos --show-sdk-path) -emit-library -static -F /swift-library -o $compile_files_path  -import-objc-header $compile_header_path
        echo "Compiled for: $TARGET"

    elif [ "$TARGET" == "macos" ]; then
        swift build -Xswiftc -static -Xswiftc -import-objc-header -Xswiftc ./Sources/swift-library/bridging-header.h
        echo "Compiled for: $TARGET"

    else
        echo "No valid target as argument. Please choose 'ios' or 'macos' as targets."
    fi
else
    echo "Error. Minimum one parameter is unvalid."
    exit 1
fi
