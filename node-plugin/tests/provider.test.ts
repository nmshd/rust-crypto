import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, Provider, KeySpec, KeyHandle, KeyPairSpec } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test provider methods", () => {
    const PROVIDER_DB_DIR_PATH = DB_DIR_PATH + "/provider";

    let providerImplConfigWithFileStore: ProviderImplConfig = {
        additional_config: [{ FileStoreConfig: { db_dir: PROVIDER_DB_DIR_PATH } }, { StorageConfigPass: "1234" }]
    };

    let provider = createProviderFromName(SOFTWARE_PROVIDER_NAME, providerImplConfigWithFileStore);
    if (!provider) {
        throw Error("Failed initializing simple software provider.");
    }

    test("create aes gcm ephemeral key", () => {
        let spec: KeySpec = {
            cipher: "AesGcm256",
            signing_hash: "Sha2_256",
            ephemeral: true
        };

        let _key = provider.createKey(spec);
    });

    test("create aes gcm ephemeral key and failed load", () => {
        let id: string;
        {
            let spec: KeySpec = {
                cipher: "AesGcm256",
                signing_hash: "Sha2_256",
                ephemeral: true
            };

            let key = provider.createKey(spec);
            id = key.id();
        }
        expect(() => {
            provider.loadKey(id);
        }).toThrow();
    });

    test("create aes gcm key and load", () => {
        let id: string;
        {
            let spec: KeySpec = {
                cipher: "AesGcm256",
                signing_hash: "Sha2_256",
                ephemeral: false
            };

            let key = provider.createKey(spec);
            id = key.id();
        }
        expect(provider.loadKey(id).id()).toEqual(id);
    });

    // TODO: Extraction of symmetric keys is not implemented yet.
    /* test("create aes gcm key, export, delete and import", () => {
        let spec: KeySpec = {
            cipher: "AesGcm256",
            signing_hash: "Sha2_256",
            ephemeral: false
        };

        let key = provider.createKey(spec);
        let hello_msg: Uint8Array = Buffer.from("Hello World!");

        let encrypted_data = key.encryptData(hello_msg);
        let exported_key = key.extractKey();

        key.delete();

        expect(() => {
            key.id();
        }).toThrow();

        let imported_key = provider.importKey(spec, exported_key);
        let decrypted_data = imported_key.decryptData(...encrypted_data);
        expect(decrypted_data).toEqual(hello_msg);
    }); */

    test("create P256 key pair and load", () => {
        let spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_256",
            ephemeral: false,
            non_exportable: false,
        };

        let key_pair = provider.createKeyPair(spec);

        let id = key_pair.id();

        let loaded_key_pair = provider.loadKeyPair(id);

        expect(loaded_key_pair.id()).toEqual(id);
    });

    test("create P256 key pair, export and import public key", () => {
        let spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_256",
            ephemeral: false,
            non_exportable: false,
        };

        let key_pair = provider.createKeyPair(spec);

        let raw_public_key = key_pair.getPublicKey();

        let public_key = provider.importPublicKey(spec, raw_public_key);
    });

    test("get provider name", () => {
        expect(provider.providerName()).toEqual(SOFTWARE_PROVIDER_NAME);
    });

    test("get provider capabilities", () => {
        expect(provider.getCapabilities()).toBeTruthy();
    });
});
