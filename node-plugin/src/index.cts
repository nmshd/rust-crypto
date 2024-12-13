// This module is the CJS entry point for the library.

// The Rust addon.
export * from "./load.cjs";

//export * from "crypto-layer-ts-types";

import { type Provider, type ProviderConfig, type ProviderImplConfig, KeyHandle, KeyPairHandle, KeyPairSpec, KeySpec } from "crypto-layer-ts-types";
import {
    createBareProvider,
    providerName,
    signData,
    verifyData,
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
    loadBareKey,
    loadBareKeyPair,
    importBareKey,
    importBareKeyPair,
    importBarePublicKey
} from "./load.cjs";

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
    export function getAllProviders(): string[];
    export function createBareProvider(config: ProviderConfig, impl_config: ProviderImplConfig): {} | undefined;
    export function createProviderFromName(name: string, impl_config: ProviderImplConfig): Provider | undefined;

    export function providerName(this: Provider): string;
    export function createBareKey(this: Provider, spec: KeySpec): {};
    export function createBareKeyPair(this: Provider, spec: KeyPairSpec): {};
    export function loadBareKey(this: Provider, id: string): {};
    export function loadBareKeyPair(this: Provider, id: string): {};
    export function importBareKey(this: Provider, spec: KeyPairSpec, key: Uint8Array): {};
    export function importBareKeyPair(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): {};
    export function importBarePublicKey(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array): {};

    export function signData(this: KeyPairHandle, data: Uint8Array): Uint8Array;
    export function verifyData(this: KeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
    export function idForKeyPair(this: KeyPairHandle): string;
    export function deleteForKeyPair(this: KeyPairHandle): undefined;
    export function getPublicKey(this: KeyPairHandle): Uint8Array;
    export function encryptDataForKeyPairHandle(this: KeyPairHandle, data: Uint8Array): Uint8Array;
    export function decryptDataForKeyPairHandle(this: KeyPairHandle, data: Uint8Array): Uint8Array;

    export function idForKeyHandle(this: KeyPairHandle): string;
    export function deleteForKeyHandle(this: KeyPairHandle): undefined;
    export function extractKey(this: KeyPairHandle): Uint8Array;
    export function encryptDataForKeyHandle(this: KeyPairHandle, data: Uint8Array): [Uint8Array, Uint8Array];
    export function decryptDataForKeyHandle(this: KeyPairHandle, data: Uint8Array, iv: Uint8Array): Uint8Array;
}

const providerFunctions = {
    providerName: providerName,
    createKey: createKey,
    createKeyPair: createKeyPair,
    loadKey: loadBareKey,
    loadKeyPair: loadBareKeyPair,
    importKey: importBareKey,
    importKeyPair: importBareKeyPair,
    importPublicKey: importBarePublicKey
};

export function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Provider | undefined {
    let provider = createBareProvider(config, impl_config);
    if (!provider) {
        return undefined;
    }
    Object.assign(provider, providerFunctions);
    return provider;
}

const keyHandleFunctions = {
    id: idForKeyHandle,
    delete: deleteForKeyHandle,
    extractKey: extractKey,
    encryptData: encryptDataForKeyHandle,
    decryptData: decryptDataForKeyHandle
};

export function createKey(this: Provider, spec: KeySpec): KeyHandle {
    let keyHandle = this.createBareKey(spec);
    Object.assign(keyHandle, keyHandleFunctions);
    return keyHandle;
}

export function loadKey(this: Provider, id: string): KeyHandle {
    let keyHandle = this.loadBareKey(id);
    Object.assign(keyHandle, keyHandleFunctions);
    return keyHandle;
}

export function importKey(this: Provider, spec: KeySpec, rawKey: Uint8Array): KeyHandle {
    let keyHandle = this.importBareKey(spec, rawKey);
    Object.assign(keyHandle, keyHandleFunctions);
    return keyHandle;
}

const keyPairHandleFunctions = {
    signData: signData,
    verifyData: verifyData,
    id: idForKeyPair,
    delete: deleteForKeyPair,
    getPublicKey: getPublicKey,
    encryptData: encryptDataForKeyPairHandle,
    decryptData: decryptDataForKeyPairHandle
};

export function createKeyPair(this: Provider, spec: KeyPairSpec): KeyPairHandle {
    let keyPairHandle = this.createBareKeyPair(spec);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle;
}

export function loadKeyPair(this: Provider, id: string): KeyPairHandle {
    let keyPairHandle = this.loadBareKeyPair(id);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle;
}

export function importKeyPair(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): KeyPairHandle {
    let keyPairHandle = this.importBareKeyPair(spec, publicKey, privateKey);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle;
}

export function importPublicKey(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array): KeyPairHandle {
    let keyPairHandle = this.importBarePublicKey(spec, publicKey);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle;
}
