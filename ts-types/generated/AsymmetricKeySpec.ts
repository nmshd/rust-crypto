// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.
import type { EccCurve } from "./EccCurve";
import type { EccSigningScheme } from "./EccSigningScheme";
import type { KeyBits } from "./KeyBits";

/**
 * Represents the available encryption algorithms.
 *
 * This enum provides a C-compatible representation of different encryption
 * methods supported by the system, including asymmetric algorithms like RSA and ECC.
 * It is designed to be extensible, allowing for the addition
 * of more encryption algorithms in the future.
 *
 * # Examples
 *
 * Basic usage for RSA (assuming `RsaBits` is defined):
 *
 * ```
 * use crypto_layer::common::crypto::algorithms::{KeyBits, encryption::AsymmetricKeySpec};
 *
 * let encryption_method = AsymmetricKeySpec::Rsa(KeyBits::Bits2048);
 *
 * ```
 *
 * Basic usage for ECC:
 *
 * ```
 * use crypto_layer::common::crypto::algorithms::encryption::{AsymmetricKeySpec, EccSigningScheme, EccCurve};
 *
 * let encryption_method = AsymmetricKeySpec::Ecc{
 *     scheme: EccSigningScheme::EcDsa,
 *     curve: EccCurve::P256,
 * };
 * ```
 *
 * # Note
 *
 * This enum uses `#[repr(C)]` to ensure that it has the same memory layout as a C enum,
 * facilitating interfacing with C code or when ABI compatibility is required.
 * flutter_rust_bridge:non_opaque
 */
export type AsymmetricKeySpec = { "Rsa": KeyBits } | {
  "Ecc": { scheme: EccSigningScheme; curve: EccCurve };
};
