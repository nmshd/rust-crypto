import type { AsymmetricKeySpec } from "./AsymmetricKeySpec";
import type { Cipher } from "./Cipher";
import type { CryptoHash } from "./CryptoHash";
/**
 * flutter_rust_bridge:non_opaque
 */
export type KeyPairSpec = {
    asym_spec: AsymmetricKeySpec;
    cipher: Cipher | null;
    signing_hash: CryptoHash;
    ephemeral: boolean;
};
//# sourceMappingURL=KeyPairSpec.d.ts.map