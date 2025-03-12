// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.
import type { KeyHandle } from "./KeyHandle";
import type { KeyPairHandle } from "./KeyPairHandle";

/**
 * Configuration needed for using or initializing providers.
 * flutter_rust_bridge:non_opaque
 */
export type AdditionalConfig =
  | {
    "KVStoreConfig": {
      get_fn: (id: string) => Uint8Array | undefined;
      store_fn: (id: string, data: Uint8Array) => boolean;
      delete_fn: (id: string) => void;
      all_keys_fn: () => string[];
    };
  }
  | {
    "FileStoreConfig": {
      /**
       * Path to a directory where the database holding key metadata will be saved.
       */
      db_dir: string;
    };
  }
  | { "StorageConfigHMAC": KeyHandle }
  | { "StorageConfigDSA": KeyPairHandle }
  | { "StorageConfigPass": string };
