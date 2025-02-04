import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, Provider, KeySpec, KeyHandle, KeyPairSpec } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test key handle methods", () => {
    const KEY_HANDLE_DB_DIR_PATH = DB_DIR_PATH + "/key_handle";

    let providerImplConfigWithFileStore: ProviderImplConfig = {
        additional_config: [{ FileStoreConfig: { db_dir: KEY_HANDLE_DB_DIR_PATH } }, { StorageConfigPass: "1234" }]
    };

    let provider: Provider;
    beforeAll(async () => {
        let provider_or_null = await createProviderFromName(SOFTWARE_PROVIDER_NAME, providerImplConfigWithFileStore);
        if (!provider_or_null) {
            throw Error("Failed initializing simple software provider.");
        }
        provider = provider_or_null
    })

    let spec: KeySpec = {
        cipher: "AesGcm256",
        signing_hash: "Sha2_256",
        ephemeral: false
    };

    test("id", async () => {
        expect((await provider.createKey(spec)).id()).toBeTruthy();
    });

    test("delete", async () => {
        let key = await provider.createKey(spec);
        key.delete();
    });

    test("encrypt and decrypt data", async () => {
        let key = await provider.createKey(spec);
        let hello_msg: Uint8Array = Buffer.from("Hello World!");

        let encrypted_data = await key.encryptData(hello_msg);

        console.log("data length: ", encrypted_data[0].length);
        console.log("iv length: ", encrypted_data[1].length);

        let decrypted_data = await key.decryptData(...encrypted_data);

        expect(Buffer.from(decrypted_data).toString("utf8")).toEqual("Hello World!");
    });

    test("spec", async () => {
        let key = await provider.createKey(spec);
        expect(await key.spec()).toEqual(spec);
    });
});
