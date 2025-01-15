/**
 * Represents the available cipher algorithms.
 *
 * This enum provides a C-compatible representation of various algorithms supported,
 * including AES, ChaCha20 variants, Triple DES, DES, RC2, and Camellia. Some algorithms can be configured with specific modes of operation and key sizes.
 * It is designed for flexibility, allowing for easy extension to include additional cipher algorithms.
 * Stream ciphers encrypt plaintext one bit or byte at a time, offering different security and performance characteristics compared to block ciphers.
 * XChaCha20 is the recommended stream cipher for new applications due to its strong security profile.
 *
 * # Note
 *
 * Marked with `#[repr(C)]` to ensure it has the same memory layout as a C enum,
 * facilitating ABI compatibility and interfacing with C code.
 * flutter_rust_bridge:non_opaque
 */
export type Cipher = "AesGcm128" | "AesGcm256" | "AesCbc128" | "AesCbc256" | "ChaCha20Poly1305" | "XChaCha20Poly1305";
//# sourceMappingURL=Cipher.d.ts.map