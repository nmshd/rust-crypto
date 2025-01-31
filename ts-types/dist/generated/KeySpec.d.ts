import type { Cipher } from "./Cipher";
import type { CryptoHash } from "./CryptoHash";
/**
 * Struct used to configure keys.
 */
export type KeySpec = {
    /**
     * Cipher used for symmetric encryption.
     */
    cipher: Cipher;
    /**
     * Hash function used with HMAC.
     */
    signing_hash: CryptoHash;
    /**
     * If set to `true`, the key is going to be deleted when the handle is dropped.
     */
    ephemeral: boolean;
};
//# sourceMappingURL=KeySpec.d.ts.map