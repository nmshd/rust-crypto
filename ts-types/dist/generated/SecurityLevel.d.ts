/**
 * Enum describing the security level of a provider.
 *
 * * [SecurityLevel::Hardware]: Provider is hardware backed (tpm, other security chips, StrongBox KeyStore).
 * * [SecurityLevel::Software]: Provder uses the systems software keystore.
 * * [SecurityLevel::Network]: Provider uses a network key store (Hashicorp).
 * * [SecurityLevel::Unsafe]: Provder uses software fallback.
 */
export type SecurityLevel = "Hardware" | "Software" | "Network" | "Unsafe";
//# sourceMappingURL=SecurityLevel.d.ts.map