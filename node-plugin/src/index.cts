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
    extractKey,
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
    specForKeyPairHandle
} from "./load.cjs";

type BareProvider = {};
type BareKeyHandle = {};
type BareKeyPairHandle = {};
type BareDHExchange = {};

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
    function getCapabilities(this: BareProvider): ProviderConfig | undefined;
    function startEphemeralDhExchange(this: BareProvider, spec: KeyPairSpec): BareDHExchange;

    function signData(this: BareKeyPairHandle, data: Uint8Array): Uint8Array;
    function verifySignature(this: BareKeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
    function idForKeyPair(this: BareKeyPairHandle): string;
    function deleteForKeyPair(this: BareKeyPairHandle): undefined;
    function getPublicKey(this: BareKeyPairHandle): Uint8Array;
    function encryptDataForKeyPairHandle(this: BareKeyPairHandle, data: Uint8Array): Uint8Array;
    function decryptDataForKeyPairHandle(this: BareKeyPairHandle, data: Uint8Array): Uint8Array;
    function specForKeyPairHandle(this: BareKeyPairHandle): KeyPairSpec;

    function idForKeyHandle(this: BareKeyHandle): string;
    function deleteForKeyHandle(this: BareKeyHandle): undefined;
    function extractKey(this: BareKeyHandle): Uint8Array;
    function encryptDataForKeyHandle(this: BareKeyHandle, data: Uint8Array): [Uint8Array, Uint8Array];
    function decryptDataForKeyHandle(this: BareKeyHandle, data: Uint8Array, iv: Uint8Array): Uint8Array;
    function specForKeyHandle(this: BareKeyHandle): KeySpec;

    function getPublicKeyForDHExchange(this: BareDHExchange): Uint8Array;
    function addExternalForDHExchange(this: BareDHExchange, key: Uint8Array): Uint8Array;
    function addExternalFinalForDHExchange(this: BareDHExchange, key: Uint8Array): BareKeyHandle;
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
        return new NodeDHExchange(startEphemeralDhExchange.call(this.provider, spec));
    }

    getCapabilities(): ProviderConfig | undefined {
        return getCapabilities.call(this.provider);
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

    spec(): KeySpec {
        return specForKeyHandle.call(this.keyHandle);
    }
}

class NodeKeyPairHandle implements KeyPairHandle {
    private keyPairHandle: BareKeyPairHandle;

    constructor(bareKeyPairHandle: BareKeyPairHandle) {
        this.keyPairHandle = bareKeyPairHandle;
    }

    id(): string {
        return idForKeyPair.call(this.keyPairHandle);
    }

    delete(): undefined {
        deleteForKeyPair.call(this.keyPairHandle);
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

    spec(): KeyPairSpec {
        return specForKeyPairHandle.call(this.keyPairHandle);
    }
}

class NodeDHExchange implements DHExchange {
    private dhExchange: BareDHExchange;

    constructor(bareDHExchange: BareDHExchange) {
        this.dhExchange = bareDHExchange;
    }

    getPublicKey(): Uint8Array {
        return getPublicKeyForDHExchange.call(this.dhExchange);
    }
    addExternal(externalKey: Uint8Array): Uint8Array {
        return addExternalForDHExchange.call(this.dhExchange, externalKey);
    }
    addExternalFinal(externalKey: Uint8Array): KeyHandle {
        return new NodeKeyHandle(addExternalFinalForDHExchange.call(this.dhExchange, externalKey));
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
