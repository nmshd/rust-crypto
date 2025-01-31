import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, Provider, KeySpec, KeyHandle, KeyPairSpec } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test key handle methods", () => {
    const KEY_HANDLE_DB_DIR_PATH = DB_DIR_PATH + "/key_handle";

    let providerImplConfigWithFileStore: ProviderImplConfig = {
        additional_config: [{ FileStoreConfig: { db_dir: KEY_HANDLE_DB_DIR_PATH } }, { StorageConfigPass: "1234" }]
    };

    let provider = createProviderFromName(SOFTWARE_PROVIDER_NAME, providerImplConfigWithFileStore);
    if (!provider) {
        throw Error("Failed initializing simple software provider.");
    }

    let spec: KeySpec = {
        cipher: "AesGcm256",
        signing_hash: "Sha2_256",
        ephemeral: false
    };

    test("id", () => {
        expect(provider.createKey(spec).id()).toBeTruthy();
    });

    test("delete", () => {
        let key = provider.createKey(spec);
        key.delete();
    });

    test("encrypt and decrypt data", () => {
        let key = provider.createKey(spec);
        let hello_msg: Uint8Array = Buffer.from("Hello World!");

        let encrypted_data = key.encryptData(hello_msg);

        let decrypted_data = key.decryptData(...encrypted_data);

        expect(Buffer.from(decrypted_data).toString("utf8")).toEqual("Hello World!");
    });

    test("spec", () => {
        let key = provider.createKey(spec);
        expect(key.spec()).toEqual(spec);
    });
});
