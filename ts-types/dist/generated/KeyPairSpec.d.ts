import type { AsymmetricKeySpec } from "./AsymmetricKeySpec";
import type { Cipher } from "./Cipher";
import type { CryptoHash } from "./CryptoHash";
/**
 * Struct used to configure key pairs.
 */
export type KeyPairSpec = {
    /**
     * Asymmetric algorithm to be used.
     */
    asym_spec: AsymmetricKeySpec;
    /**
     * Cipher used for hybrid encryption. If set to None, no hybrid encryption will be used.
     */
    cipher: Cipher | null;
    /**
     * Hash function used for signing and encrypting.
     */
    signing_hash: CryptoHash;
    /**
     * If set to true, the key pair will be discarded after the handle is dropped.
     */
    ephemeral: boolean;
    /**
     * If set to true, the key can't be exported (also software keys)
     */
    non_exportable: boolean;
};
//# sourceMappingURL=KeyPairSpec.d.ts.map