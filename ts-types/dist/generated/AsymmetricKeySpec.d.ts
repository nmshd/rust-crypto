/**
 * Represents the available encryption algorithms.
 *
 * This enum provides a C-compatible representation of different encryption
 * methods supported by the system, including asymmetric algorithms like RSA and ECC.
 * It is designed to be extensible, allowing for the addition
 * of more encryption algorithms in the future.
 *
 * # Note
 *
 * This enum uses `#[repr(C)]` to ensure that it has the same memory layout as a C enum,
 * facilitating interfacing with C code or when ABI compatibility is required.
 * flutter_rust_bridge:non_opaque
 */
export type AsymmetricKeySpec = "RSA1024" | "RSA2048" | "RSA3072" | "RSA4096" | "RSA8192" | "P256" | "P384" | "P521" | "Secp256k1" | "BrainpoolP256r1" | "BrainpoolP384r1" | "BrainpoolP512r1" | "BrainpoolP638" | "Curve25519" | "Curve448" | "Frp256v1";
//# sourceMappingURL=AsymmetricKeySpec.d.ts.map