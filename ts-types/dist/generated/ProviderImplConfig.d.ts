import type { AdditionalConfig } from "./AdditionalConfig";
/**
 * Configuration needed for using or initializing providers.
 *
 * Either
 * * [AdditionalConfig::KVStoreConfig]
 * * [AdditionalConfig::FileStoreConfig]
 *
 * and either
 * * [AdditionalConfig::StorageConfigHMAC]
 * * [AdditionalConfig::StorageConfigDSA]
 * * [AdditionalConfig::StorageConfigPass]
 *
 * need to be supplied.
 *
 * ## Example
 *
 * ```rust
 * use crypto_layer::prelude::*;
 * let implementation_config = ProviderImplConfig {
 *       additional_config: vec![
 *          AdditionalConfig::FileStoreConfig {
 *              db_dir: "./testdb".to_owned(),
 *          },
 *          AdditionalConfig::StorageConfigPass("password".to_owned()),
 *      ],
 * };
 * ```
 */
export type ProviderImplConfig = {
    additional_config: Array<AdditionalConfig>;
};
//# sourceMappingURL=ProviderImplConfig.d.ts.map