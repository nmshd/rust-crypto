import type { AsymmetricKeySpec } from "./AsymmetricKeySpec";
import type { Cipher } from "./Cipher";
import type { CryptoHash } from "./CryptoHash";
import type { SecurityLevel } from "./SecurityLevel";
/**
 * Capabilities of a Provider
 */
export type ProviderConfig = {
    max_security_level: SecurityLevel;
    min_security_level: SecurityLevel;
    supported_ciphers: Array<Cipher>;
    supported_hashes: Array<CryptoHash>;
    supported_asym_spec: Array<AsymmetricKeySpec>;
};
//# sourceMappingURL=ProviderConfig.d.ts.map