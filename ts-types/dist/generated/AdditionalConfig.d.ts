import type { KeyHandle } from "./KeyHandle";
import type { KeyPairHandle } from "./KeyPairHandle";
/**
 * Configuration needed for using or initializing providers.
 */
export type AdditionalConfig = {
    "KVStoreConfig": {
        get_fn: (id: string) => Uint8Array | undefined;
        store_fn: (id: string, data: Uint8Array) => boolean;
        delete_fn: (id: string) => void;
        all_keys_fn: () => string[];
    };
} | {
    "FileStoreConfig": {
        /**
         * Path to a directory where the database holding key metadata will be saved.
         */
        db_dir: string;
    };
} | {
    "StorageConfigHMAC": KeyHandle;
} | {
    "StorageConfigDSA": KeyPairHandle;
} | {
    "StorageConfigPass": string;
};
//# sourceMappingURL=AdditionalConfig.d.ts.map