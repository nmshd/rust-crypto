import { test, expect, describe } from "@jest/globals";

import { ProviderConfig, ProviderImplConfig, Provider, KeySpec, KeyHandle, KeyPairSpec } from "crypto-layer-ts-types";
import { createProvider, getAllProviders, createProviderFromName } from "../lib/index.cjs";

import { DB_DIR_PATH, SOFTWARE_PROVIDER_NAME } from "./common";

describe("test provider methods", () => {
    const PROVIDER_DB_DIR_PATH = DB_DIR_PATH + "/provider";

    let providerImplConfigWithFileStore: ProviderImplConfig = {
        additional_config: [{ FileStoreConfig: { db_dir: PROVIDER_DB_DIR_PATH } }, { StorageConfigPass: "1234" }]
    };

    let provider: Provider;
    beforeAll(async () => {
        let provider_or_null = await createProviderFromName(SOFTWARE_PROVIDER_NAME, providerImplConfigWithFileStore);
        if (!provider_or_null) {
            throw Error("Failed initializing simple software provider.");
        }
        provider = provider_or_null
    })

    test("create aes gcm ephemeral key", async () => {
        let spec: KeySpec = {
            cipher: "AesGcm256",
            signing_hash: "Sha2_256",
            ephemeral: true
        };

        let _key = await provider.createKey(spec);
    });

    test("create aes gcm ephemeral key and failed load", async () => {
        let id: string;
        {
            let spec: KeySpec = {
                cipher: "AesGcm256",
                signing_hash: "Sha2_256",
                ephemeral: true
            };

            let key = await provider.createKey(spec);
            id = await key.id();

            console.log("id:", id);
        }
        await expect(async () => {
            await provider.loadKey(id);
        }).rejects.toThrow();
    });

    test("create aes gcm key and load", async () => {
        let id: string;
        {
            let spec: KeySpec = {
                cipher: "AesGcm256",
                signing_hash: "Sha2_256",
                ephemeral: false
            };

            let key = await provider.createKey(spec);
            id = await key.id();
        }
        expect(await (await provider.loadKey(id)).id()).toEqual(id);
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

    test("create P256 key pair and load", async () => {
        let spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_256",
            ephemeral: false,
            non_exportable: false,
        };

        let keyPair = await provider.createKeyPair(spec);

        let id = await keyPair.id();

        let loadedKeyPair = await provider.loadKeyPair(id);

        expect(await loadedKeyPair.id()).toEqual(id);
    });

    test("create P256 key pair, export and import public key", async () => {
        let spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_256",
            ephemeral: false,
            non_exportable: false,
        };

        let keyPair = await provider.createKeyPair(spec);

        let rawPublicKey = await keyPair.getPublicKey();

        let publicKey = await provider.importPublicKey(spec, rawPublicKey);
    });

    test("create P256 key pair, export and import key pair", async () => {
        let spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_256",
            ephemeral: false,
            non_exportable: false,
        };

        let keyPair = await provider.createKeyPair(spec);

        let rawPublicKey = await keyPair.getPublicKey();
        let rawPrivateKey = await keyPair.extractKey();

        let importedKeyPair = await provider.importKeyPair(spec, rawPublicKey,rawPrivateKey);
    });

    test("create P256 key pair, export and import private key", async () => {
        let spec: KeyPairSpec = {
            asym_spec: "P256",
            cipher: null,
            signing_hash: "Sha2_256",
            ephemeral: false,
            non_exportable: false,
        };

        let keyPair = await provider.createKeyPair(spec);

        let rawPrivateKey = await keyPair.extractKey();

        let importedKeyPair = await provider.importKeyPair(spec, new Uint8Array(0),rawPrivateKey);
    });

    test("get provider name", async () => {
        expect(await provider.providerName()).toEqual(SOFTWARE_PROVIDER_NAME);
    });

    test("get provider capabilities", async () => {
        expect(await provider.getCapabilities()).toBeTruthy();
    });
});
