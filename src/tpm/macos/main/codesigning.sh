#!/bin/bash
codesign -f -s "F5C0AD229021961EF94754EE76F28E2CD538545D" --entitlements "binaryknights.entitlements" -o runtime -i "de.jssoft.BinaryKnights" "target/debug/rust-binary-calls-swift-package"