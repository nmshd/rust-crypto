// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.

/**
 * Represents the bit length of a cryptographic key.
 *
 * This enum defines various key bit lengths commonly used in cryptography.
 * It provides a convenient way to specify and work with different key sizes.
 *
 * The available key bit lengths are:
 *
 * - `Bits128`: 128-bit key length
 * - `Bits192`: 192-bit key length
 * - `Bits256`: 256-bit key length
 * - `Bits512`: 512-bit key length
 * - `Bits1024`: 1024-bit key length
 * - `Bits2048`: 2048-bit key length
 * - `Bits3072`: 3072-bit key length
 * - `Bits4096`: 4096-bit key length
 * - `Bits8192`: 8192-bit key length
 *
 * This enum can be converted to and from `u32` values using the `From` trait implementations.
 */
export type KeyBits =
  | "Bits128"
  | "Bits192"
  | "Bits256"
  | "Bits512"
  | "Bits1024"
  | "Bits2048"
  | "Bits3072"
  | "Bits4096"
  | "Bits8192";