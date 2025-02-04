// This module is the CJS entry point for the library.

// The Rust addon.
export { getAllProviders } from "./load.cjs";

import {
    type Provider,
    type ProviderConfig,
    type ProviderImplConfig,
    type KeyHandle,
    type KeyPairHandle,
    type KeyPairSpec,
    type KeySpec,
    type DHExchange
} from "crypto-layer-ts-types";
import {
    createBareProvider,
    providerName,
    signData,
    verifySignature,
    idForKeyHandle,
    idForKeyPair,
    deleteForKeyHandle,
    deleteForKeyPair,
    decryptDataForKeyHandle,
    decryptDataForKeyPairHandle,
    encryptDataForKeyHandle,
    encryptDataForKeyPairHandle,
    extractKeyForKeyHandle,
    getPublicKey,
    createBareKey,
    createBareKeyPair,
    loadBareKey,
    loadBareKeyPair,
    importBareKey,
    importBareKeyPair,
    importBarePublicKey,
    createBareProviderFromName,
    getCapabilities,
    startEphemeralDhExchange,
    getPublicKeyForDHExchange,
    addExternalFinalForDHExchange,
    addExternalForDHExchange,
    specForKeyHandle,
    specForKeyPairHandle,
    extractKeyForKeyPairHandle
} from "./load.cjs";

type BareProvider = {};
type BareKeyHandle = {};
type BareKeyPairHandle = {};
type BareDHExchange = {};

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
    export function getAllProviders(): Promise<string[]>;
    function createBareProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Promise<BareProvider | undefined>;
    function createBareProviderFromName(name: string, impl_config: ProviderImplConfig): Promise<BareProvider | undefined>;

    function providerName(this: BareProvider): Promise<string>;
    function createBareKey(this: BareProvider, spec: KeySpec): Promise<BareKeyHandle>;
    function createBareKeyPair(this: BareProvider, spec: KeyPairSpec): Promise<BareKeyPairHandle>;
    function loadBareKey(this: BareProvider, id: string): Promise<BareKeyHandle>;
    function loadBareKeyPair(this: BareProvider, id: string): Promise<BareKeyPairHandle>;
    function importBareKey(this: BareProvider, spec: KeySpec, key: Uint8Array): Promise<BareKeyHandle>;
    function importBareKeyPair(this: BareProvider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): Promise<BareKeyPairHandle>;
    function importBarePublicKey(this: BareProvider, spec: KeyPairSpec, publicKey: Uint8Array): Promise<BareKeyPairHandle>;
    function getCapabilities(this: BareProvider): Promise<ProviderConfig | undefined>;
    function startEphemeralDhExchange(this: BareProvider, spec: KeyPairSpec): Promise<BareDHExchange>;

    function signData(this: BareKeyPairHandle, data: Uint8Array): Promise<Uint8Array>;
    function verifySignature(this: BareKeyPairHandle, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
    function idForKeyPair(this: BareKeyPairHandle): Promise<string>;
    function deleteForKeyPair(this: BareKeyPairHandle): Promise<undefined>;
    function getPublicKey(this: BareKeyPairHandle): Promise<Uint8Array>;
    function extractKeyForKeyPairHandle(this: BareKeyPairHandle): Promise<Uint8Array>;
    function encryptDataForKeyPairHandle(this: BareKeyPairHandle, data: Uint8Array): Promise<Uint8Array>;
    function decryptDataForKeyPairHandle(this: BareKeyPairHandle, data: Uint8Array): Promise<Uint8Array>;
    function specForKeyPairHandle(this: BareKeyPairHandle): Promise<KeyPairSpec>;

    function idForKeyHandle(this: BareKeyHandle): Promise<string>;
    function deleteForKeyHandle(this: BareKeyHandle): Promise<undefined>;
    function extractKeyForKeyHandle(this: BareKeyHandle): Promise<Uint8Array>;
    function encryptDataForKeyHandle(this: BareKeyHandle, data: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
    function decryptDataForKeyHandle(this: BareKeyHandle, data: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
    function specForKeyHandle(this: BareKeyHandle): Promise<KeySpec>;

    function getPublicKeyForDHExchange(this: BareDHExchange): Promise<Uint8Array>;
    function addExternalForDHExchange(this: BareDHExchange, key: Uint8Array): Promise<Uint8Array>;
    function addExternalFinalForDHExchange(this: BareDHExchange, key: Uint8Array): Promise<BareKeyHandle>;
}

class NodeProvider implements Provider {
    private provider: BareProvider;

    constructor(bareProvider: BareProvider) {
        this.provider = bareProvider;
    }

    async providerName(): Promise<string> {
        return await providerName.call(this.provider);
    }

    async createKey(spec: KeySpec): Promise<KeyHandle> {
        return new NodeKeyHandle(await createBareKey.call(this.provider, spec));
    }

    async createKeyPair(spec: KeyPairSpec): Promise<KeyPairHandle> {
        return new NodeKeyPairHandle(await createBareKeyPair.call(this.provider, spec));
    }

    async loadKey(id: string): Promise<KeyHandle> {
        return new NodeKeyHandle(await loadBareKey.call(this.provider, id));
    }

    async loadKeyPair(id: string): Promise<KeyPairHandle> {
        return new NodeKeyPairHandle(await loadBareKeyPair.call(this.provider, id));
    }

    async importKey(spec: KeySpec, key: Uint8Array): Promise<KeyHandle> {
        return new NodeKeyHandle(await importBareKey.call(this.provider, spec, key));
    }

    async importKeyPair(spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): Promise<KeyPairHandle> {
        return new NodeKeyPairHandle(await importBareKeyPair.call(this.provider, spec, publicKey, privateKey));
    }

    async importPublicKey(spec: KeyPairSpec, publicKey: Uint8Array): Promise<KeyPairHandle> {
        return new NodeKeyPairHandle(await importBarePublicKey.call(this.provider, spec, publicKey));
    }

    async startEphemeralDhExchange(spec: KeyPairSpec): Promise<DHExchange> {
        return new NodeDHExchange(await startEphemeralDhExchange.call(this.provider, spec));
    }

    async getCapabilities(): Promise<ProviderConfig | undefined> {
        return await getCapabilities.call(this.provider);
    }
}

class NodeKeyHandle implements KeyHandle {
    private keyHandle: BareKeyHandle;

    constructor(bareKeyHandle: BareKeyHandle) {
        this.keyHandle = bareKeyHandle;
    }

    async id(): Promise<string> {
        return await idForKeyHandle.call(this.keyHandle);
    }

    async delete(): Promise<undefined> {
        return await deleteForKeyHandle.call(this.keyHandle);
    }

    async extractKey(): Promise<Uint8Array> {
        return await extractKeyForKeyHandle.call(this.keyHandle);
    }

    async encryptData(data: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
        return await encryptDataForKeyHandle.call(this.keyHandle, data);
    }

    async decryptData(encryptedData: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
        return await decryptDataForKeyHandle.call(this.keyHandle, encryptedData, iv);
    }

    async spec(): Promise<KeySpec> {
        return await specForKeyHandle.call(this.keyHandle);
    }
}

class NodeKeyPairHandle implements KeyPairHandle {
    private keyPairHandle: BareKeyPairHandle;

    constructor(bareKeyPairHandle: BareKeyPairHandle) {
        this.keyPairHandle = bareKeyPairHandle;
    }

    async id(): Promise<string> {
        return await idForKeyPair.call(this.keyPairHandle);
    }

    async delete(): Promise<undefined> {
        return await deleteForKeyPair.call(this.keyPairHandle);
    }

    async signData(data: Uint8Array): Promise<Uint8Array> {
        return await signData.call(this.keyPairHandle, data);
    }

    async verifySignature(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
        return await verifySignature.call(this.keyPairHandle, data, signature);
    }

    async encryptData(data: Uint8Array): Promise<Uint8Array> {
        return await encryptDataForKeyPairHandle.call(this.keyPairHandle, data);
    }

    async decryptData(encryptedData: Uint8Array): Promise<Uint8Array> {
        return await decryptDataForKeyPairHandle.call(this.keyPairHandle, encryptedData);
    }

    async getPublicKey(): Promise<Uint8Array> {
        return await getPublicKey.call(this.keyPairHandle);
    }

    async extractKey(): Promise<Uint8Array> {
        return await extractKeyForKeyPairHandle.call(this.keyPairHandle);
    }

    async spec(): Promise<KeyPairSpec> {
        return await specForKeyPairHandle.call(this.keyPairHandle);
    }
}

class NodeDHExchange implements DHExchange {
    private dhExchange: BareDHExchange;

    constructor(bareDHExchange: BareDHExchange) {
        this.dhExchange = bareDHExchange;
    }

    async getPublicKey(): Promise<Uint8Array> {
        return await getPublicKeyForDHExchange.call(this.dhExchange);
    }
    async addExternal(externalKey: Uint8Array): Promise<Uint8Array> {
        return await addExternalForDHExchange.call(this.dhExchange, externalKey);
    }
    async addExternalFinal(externalKey: Uint8Array): Promise<KeyHandle> {
        return new NodeKeyHandle(await addExternalFinalForDHExchange.call(this.dhExchange, externalKey));
    }
}

export async function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Promise<Provider | undefined> {
    let provider = await createBareProvider(config, impl_config);
    if (!provider) {
        return undefined;
    }
    return new NodeProvider(provider);
}

export async function createProviderFromName(name: string, impl_config: ProviderImplConfig): Promise<Provider | undefined> {
    let provider = await createBareProviderFromName(name, impl_config);
    if (!provider) {
        return undefined;
    }
    return new NodeProvider(provider);
}
