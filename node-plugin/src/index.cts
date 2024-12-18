// This module is the CJS entry point for the library.

// The Rust addon.
export { getAllProviders } from "./load.cjs";

import { type Provider, type ProviderConfig, type ProviderImplConfig, KeyHandle, KeyPairHandle, KeyPairSpec, KeySpec, DHExchange } from "crypto-layer-ts-types";
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
    extractKey,
    getPublicKey,
    createBareKey,
    createBareKeyPair,
    loadBareKey,
    loadBareKeyPair,
    importBareKey,
    importBareKeyPair,
    importBarePublicKey,
    createBareProviderFromName
} from "./load.cjs";

type BareProvider = {};
type BareKeyHandle = {};
type BareKeyPairHandle = {};

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
    export function getAllProviders(): string[];
    function createBareProvider(config: ProviderConfig, impl_config: ProviderImplConfig): BareProvider | undefined;
    function createBareProviderFromName(name: string, impl_config: ProviderImplConfig): BareProvider | undefined;

    function providerName(this: BareProvider): string;
    function createBareKey(this: BareProvider, spec: KeySpec): BareKeyHandle;
    function createBareKeyPair(this: BareProvider, spec: KeyPairSpec): BareKeyPairHandle;
    function loadBareKey(this: BareProvider, id: string): BareKeyHandle;
    function loadBareKeyPair(this: BareProvider, id: string): BareKeyPairHandle;
    function importBareKey(this: BareProvider, spec: KeySpec, key: Uint8Array): BareKeyHandle;
    function importBareKeyPair(this: BareProvider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): BareKeyPairHandle;
    function importBarePublicKey(this: BareProvider, spec: KeyPairSpec, publicKey: Uint8Array): BareKeyPairHandle;

    function signData(this: BareKeyPairHandle, data: Uint8Array): Uint8Array;
    function verifySignature(this: BareKeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
    function idForKeyPair(this: BareKeyPairHandle): string;
    function deleteForKeyPair(this: BareKeyPairHandle): undefined;
    function getPublicKey(this: BareKeyPairHandle): Uint8Array;
    function encryptDataForKeyPairHandle(this: BareKeyPairHandle, data: Uint8Array): Uint8Array;
    function decryptDataForKeyPairHandle(this: BareKeyPairHandle, data: Uint8Array): Uint8Array;

    function idForKeyHandle(this: BareKeyHandle): string;
    function deleteForKeyHandle(this: BareKeyHandle): undefined;
    function extractKey(this: BareKeyHandle): Uint8Array;
    function encryptDataForKeyHandle(this: BareKeyHandle, data: Uint8Array): [Uint8Array, Uint8Array];
    function decryptDataForKeyHandle(this: BareKeyHandle, data: Uint8Array, iv: Uint8Array): Uint8Array;
}

class NodeProvider implements Provider {
    private provider: BareProvider;

    constructor(bareProvider: BareProvider) {
        this.provider = bareProvider;
    }

    providerName(): string {
        return providerName.call(this.provider);
    }

    createKey(spec: KeySpec): KeyHandle {
        return new NodeKeyHandle(createBareKey.call(this.provider, spec));
    }

    createKeyPair(spec: KeyPairSpec): KeyPairHandle {
        return new NodeKeyPairHandle(createBareKeyPair.call(this.provider, spec));
    }

    loadKey(id: string): KeyHandle {
        return new NodeKeyHandle(loadBareKey.call(this.provider, id));
    }

    loadKeyPair(id: string): KeyPairHandle {
        return new NodeKeyPairHandle(loadBareKeyPair.call(this.provider, id));
    }

    importKey(spec: KeySpec, key: Uint8Array): KeyHandle {
        return new NodeKeyHandle(importBareKey.call(this.provider, spec, key));
    }

    importKeyPair(spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): KeyPairHandle {
        return new NodeKeyPairHandle(importBareKeyPair.call(this.provider, spec, publicKey, privateKey));
    }

    importPublicKey(spec: KeyPairSpec, publicKey: Uint8Array): KeyPairHandle {
        return new NodeKeyPairHandle(importBarePublicKey.call(this.provider, spec, publicKey));
    }

    startEphemeralDhExchange(spec: KeyPairSpec): DHExchange {
        throw Error("Not yet implemented.");
    }

    getCapabilities(): ProviderConfig | undefined {
        throw Error("Not yet implemented.");
    }
}

class NodeKeyHandle implements KeyHandle {
    private keyHandle: BareKeyHandle;

    constructor(bareKeyHandle: BareKeyHandle) {
        this.keyHandle = bareKeyHandle;
    }

    id(): string {
        return idForKeyHandle.call(this.keyHandle);
    }

    delete(): undefined {
        deleteForKeyHandle.call(this.keyHandle);
    }

    extractKey(): Uint8Array {
        return extractKey.call(this.keyHandle);
    }

    encryptData(data: Uint8Array): [Uint8Array, Uint8Array] {
        return encryptDataForKeyHandle.call(this.keyHandle, data);
    }

    decryptData(encryptedData: Uint8Array, iv: Uint8Array): Uint8Array {
        return decryptDataForKeyHandle.call(this.keyHandle, encryptedData, iv);
    }
}

class NodeKeyPairHandle implements KeyPairHandle {
    private keyPairHandle: {};

    constructor(bareKeyPairHandle: {}) {
        this.keyPairHandle = bareKeyPairHandle;
    }

    id(): string {
        return idForKeyHandle.call(this.keyPairHandle);
    }

    delete(): undefined {
        deleteForKeyHandle.call(this.keyPairHandle);
    }

    signData(data: Uint8Array): Uint8Array {
        return signData.call(this.keyPairHandle, data);
    }

    verifySignature(data: Uint8Array, signature: Uint8Array): boolean {
        return verifySignature.call(this.keyPairHandle, data, signature);
    }

    encryptData(data: Uint8Array): Uint8Array {
        return encryptDataForKeyPairHandle.call(this.keyPairHandle, data);
    }

    decryptData(encryptedData: Uint8Array): Uint8Array {
        return decryptDataForKeyPairHandle.call(this.keyPairHandle, encryptedData);
    }

    getPublicKey(): Uint8Array {
        return getPublicKey.call(this.keyPairHandle);
    }
}

export function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Provider | undefined {
    let provider = createBareProvider(config, impl_config);
    if (!provider) {
        return undefined;
    }
    return new NodeProvider(provider);
}

export function createProviderFromName(name: string, impl_config: ProviderImplConfig): Provider | undefined {
    let provider = createBareProviderFromName(name, impl_config);
    if (!provider) {
        return undefined;
    }
    return new NodeProvider(provider);
}
