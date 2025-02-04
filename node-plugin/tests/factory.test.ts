import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, CreateProviderFromNameFunc, CreateProviderFunc, GetAllProvidersFunc } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test provider factory methods", () => {
    const FACTORY_DB_DIR_PATH = DB_DIR_PATH + "/factory";

    let providerConfig: ProviderConfig = {
        max_security_level: "Software",
        min_security_level: "Software",
        supported_asym_spec: ["P256"],
        supported_ciphers: ["AesGcm256"],
        supported_hashes: ["Sha2_256"]
    };

    test("get provider names", async () => {
        let provider_arr = await getAllProviders();
        expect(provider_arr).toBeTruthy();
        expect(provider_arr).toContain(SOFTWARE_PROVIDER_NAME);
    });

    test("create simple provider with file store",  async () => {
        let providerImplConfigWithFileStore: ProviderImplConfig = {
            additional_config: [{ FileStoreConfig: { db_dir: FACTORY_DB_DIR_PATH } }, { StorageConfigPass: "1234" }]
        };
        expect(await createProvider(providerConfig, providerImplConfigWithFileStore)).toBeTruthy();
    });

    test("create software provider from name with file store", async () => {
        let providerImplConfigWithFileStore: ProviderImplConfig = {
            additional_config: [{ FileStoreConfig: { db_dir: FACTORY_DB_DIR_PATH + "FromName" } }, { StorageConfigPass: "1234" }]
        };
        expect(await createProviderFromName(SOFTWARE_PROVIDER_NAME, providerImplConfigWithFileStore)).toBeTruthy();
    });

    test("functions fullfilling defined types", async () => {
        let _a: GetAllProvidersFunc = getAllProviders;
        let _b: CreateProviderFromNameFunc = createProviderFromName;
        let _c: CreateProviderFunc = createProvider;
    });
});
