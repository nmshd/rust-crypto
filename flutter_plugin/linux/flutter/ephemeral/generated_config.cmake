# Generated code do not commit.
file(TO_CMAKE_PATH "/home/mark/flutter" FLUTTER_ROOT)
file(TO_CMAKE_PATH "/home/mark/rust-crypto/flutter_plugin" PROJECT_DIR)

set(FLUTTER_VERSION "0.0.1" PARENT_SCOPE)
set(FLUTTER_VERSION_MAJOR 0 PARENT_SCOPE)
set(FLUTTER_VERSION_MINOR 0 PARENT_SCOPE)
set(FLUTTER_VERSION_PATCH 1 PARENT_SCOPE)
set(FLUTTER_VERSION_BUILD 0 PARENT_SCOPE)

# Environment variables to pass to tool_backend.sh
list(APPEND FLUTTER_TOOL_ENVIRONMENT
  "FLUTTER_ROOT=/home/mark/flutter"
  "PROJECT_DIR=/home/mark/rust-crypto/flutter_plugin"
  "DART_OBFUSCATION=false"
  "TRACK_WIDGET_CREATION=true"
  "TREE_SHAKE_ICONS=false"
  "PACKAGE_CONFIG=/home/mark/rust-crypto/flutter_plugin/.dart_tool/package_config.json"
  "FLUTTER_TARGET=integration_test/cal_test.dart"
)
