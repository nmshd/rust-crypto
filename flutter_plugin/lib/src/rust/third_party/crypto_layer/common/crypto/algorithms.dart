// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.3.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../../../frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `assert_receiver_is_total_eq`, `clone`, `eq`, `fmt`, `from`, `from`, `from`, `from`, `hash`

/// Represents the bit length of a cryptographic key.
///
/// This enum defines various key bit lengths commonly used in cryptography.
/// It provides a convenient way to specify and work with different key sizes.
///
/// The available key bit lengths are:
///
/// - `Bits128`: 128-bit key length
/// - `Bits192`: 192-bit key length
/// - `Bits256`: 256-bit key length
/// - `Bits512`: 512-bit key length
/// - `Bits1024`: 1024-bit key length
/// - `Bits2048`: 2048-bit key length
/// - `Bits3072`: 3072-bit key length
/// - `Bits4096`: 4096-bit key length
/// - `Bits8192`: 8192-bit key length
///
/// This enum can be converted to and from `u32` values using the `From` trait implementations.
enum KeyBits {
  bits128,
  bits192,
  bits256,
  bits512,
  bits1024,
  bits2048,
  bits3072,
  bits4096,
  bits8192,
  ;
}
