import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, Provider, KeySpec, KeyHandle, KeyPairSpec } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test key pair handle methods", () => {
    const KEY_HANDLE_DB_DIR_PATH = DB_DIR_PATH + "/key_pair_handle";

    let providerImplConfigWithFileStore: ProviderImplConfig = {
        additional_config: [{ FileStoreConfig: { db_dir: KEY_HANDLE_DB_DIR_PATH } }, { StorageConfigPass: "1234" }]
    };

    let provider = createProviderFromName(SOFTWARE_PROVIDER_NAME, providerImplConfigWithFileStore);
    if (!provider) {
        throw Error("Failed initializing simple software provider.");
    }

    let spec: KeyPairSpec = {
        asym_spec: "P256",
        cipher: null,
        signing_hash: "Sha2_256",
        ephemeral: false,
        non_exportable: false,
    };

    test("id", () => {
        expect(provider.createKeyPair(spec).id()).toBeTruthy();
    });

    test("delete", () => {
        let key_pair = provider.createKeyPair(spec);
        key_pair.delete();
    });

    test("spec", () => {
        let key_pair = provider.createKeyPair(spec);
        expect(key_pair.spec()).toEqual(spec);
    });

    // TODO: not yet implemented for software provider.
    /* test("encrypt and decrypt data", () => {
        let key = provider.createKeyPair(spec);
        let hello_msg: Uint8Array = Buffer.from("Hello World!");

        let encrypted_data = key.encryptData(hello_msg);

        let decrypted_data = key.decryptData(encrypted_data);

        expect(decrypted_data).toEqual(hello_msg);
    }); */
});
