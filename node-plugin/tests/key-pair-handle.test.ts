import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, Provider, KeySpec, KeyHandle, KeyPairSpec } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test key pair handle methods", () => {
    const KEY_HANDLE_DB_DIR_PATH = DB_DIR_PATH + "/key_pair_handle";

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

    let spec: KeyPairSpec = {
        asym_spec: "P256",
        cipher: null,
        signing_hash: "Sha2_256",
        ephemeral: false,
        non_exportable: false,
    };

    test("id", async () => {
        expect((await provider.createKeyPair(spec)).id()).toBeTruthy();
    });

    test("delete", async () => {
        let key_pair = await provider.createKeyPair(spec);
        await key_pair.delete();
    });

    test("spec", async () => {
        let key_pair = await provider.createKeyPair(spec);
        expect(await key_pair.spec()).toEqual(spec);
    });

    test("getPublicKey", async () => {
        let key_pair = await provider.createKeyPair(spec);
        await key_pair.getPublicKey()
    })

    test("extractKey", async () => {
        let key_pair = await provider.createKeyPair(spec);
        await key_pair.extractKey()
    })

    test("sign and verify data", async () => {
        let key_pair = await provider.createKeyPair(spec);
        let data = Uint8Array.from([1, 2, 3, 4]);

        let signature = await key_pair.signData(data);
        expect(await key_pair.verifySignature(data, signature)).toBeTruthy()
    })

    // TODO: not yet implemented for software provider.
    /* test("encrypt and decrypt data", () => {
        let key = provider.createKeyPair(spec);
        let hello_msg: Uint8Array = Buffer.from("Hello World!");

        let encrypted_data = key.encryptData(hello_msg);

        let decrypted_data = key.decryptData(encrypted_data);

        expect(decrypted_data).toEqual(hello_msg);
    }); */
});
