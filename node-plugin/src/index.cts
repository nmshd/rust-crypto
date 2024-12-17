// This module is the CJS entry point for the library.

// The Rust addon.
export { getAllProviders } from "./load.cjs";

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
    createBareKey,
    createBareKeyPair,
    loadBareKey,
    loadBareKeyPair,
    importBareKey,
    importBareKeyPair,
    importBarePublicKey,
    createBareProviderFromName
} from "./load.cjs";

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
    export function getAllProviders(): string[];
    function createBareProvider(config: ProviderConfig, impl_config: ProviderImplConfig): {} | undefined;
    function createBareProviderFromName(name: string, impl_config: ProviderImplConfig): Provider | undefined;

    function providerName(this: Provider): string;
    function createBareKey(this: Provider, spec: KeySpec): {};
    function createBareKeyPair(this: Provider, spec: KeyPairSpec): {};
    function loadBareKey(this: Provider, id: string): {};
    function loadBareKeyPair(this: Provider, id: string): {};
    function importBareKey(this: Provider, spec: KeySpec, key: Uint8Array): {};
    function importBareKeyPair(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): {};
    function importBarePublicKey(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array): {};

    function signData(this: KeyPairHandle, data: Uint8Array): Uint8Array;
    function verifyData(this: KeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
    function idForKeyPair(this: KeyPairHandle): string;
    function deleteForKeyPair(this: KeyPairHandle): undefined;
    function getPublicKey(this: KeyPairHandle): Uint8Array;
    function encryptDataForKeyPairHandle(this: KeyPairHandle, data: Uint8Array): Uint8Array;
    function decryptDataForKeyPairHandle(this: KeyPairHandle, data: Uint8Array): Uint8Array;

    function idForKeyHandle(this: KeyPairHandle): string;
    function deleteForKeyHandle(this: KeyPairHandle): undefined;
    function extractKey(this: KeyPairHandle): Uint8Array;
    function encryptDataForKeyHandle(this: KeyPairHandle, data: Uint8Array): [Uint8Array, Uint8Array];
    function decryptDataForKeyHandle(this: KeyPairHandle, data: Uint8Array, iv: Uint8Array): Uint8Array;
}

const providerFunctions = {
    providerName: providerName,
    createKey: createKey,
    createKeyPair: createKeyPair,
    loadKey: loadKey,
    loadKeyPair: loadKeyPair,
    importKey: importKey,
    importKeyPair: importKeyPair,
    importPublicKey: importPublicKey
};

export function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Provider | undefined {
    let provider = createBareProvider(config, impl_config);
    if (!provider) {
        return undefined;
    }
    Object.assign(provider, providerFunctions);
    return provider as Provider;
}

export function createProviderFromName(name: string, impl_config: ProviderImplConfig): Provider | undefined {
    let provider = createBareProviderFromName(name, impl_config);
    if (!provider) {
        return undefined;
    }
    Object.assign(provider, providerFunctions);
    return provider as Provider;
}

const keyHandleFunctions = {
    id: idForKeyHandle,
    delete: deleteForKeyHandle,
    extractKey: extractKey,
    encryptData: encryptDataForKeyHandle,
    decryptData: decryptDataForKeyHandle
};

export function createKey(this: Provider, spec: KeySpec): KeyHandle {
    let keyHandle = createBareKey.call(this, spec);
    Object.assign(keyHandle, keyHandleFunctions);
    return keyHandle as KeyHandle;
}

export function loadKey(this: Provider, id: string): KeyHandle {
    let keyHandle = loadBareKey.call(this, id);
    Object.assign(keyHandle, keyHandleFunctions);
    return keyHandle as KeyHandle;
}

export function importKey(this: Provider, spec: KeySpec, rawKey: Uint8Array): KeyHandle {
    let keyHandle = importBareKey.call(this, spec, rawKey);
    Object.assign(keyHandle, keyHandleFunctions);
    return keyHandle as KeyHandle;
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
    let keyPairHandle = createBareKeyPair.call(this, spec);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle as KeyPairHandle;
}

export function loadKeyPair(this: Provider, id: string): KeyPairHandle {
    let keyPairHandle = loadBareKeyPair.call(this, id);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle as KeyPairHandle;
}

export function importKeyPair(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): KeyPairHandle {
    let keyPairHandle = importBareKeyPair.call(this, spec, publicKey, privateKey);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle as KeyPairHandle;
}

export function importPublicKey(this: Provider, spec: KeyPairSpec, publicKey: Uint8Array): KeyPairHandle {
    let keyPairHandle = importBarePublicKey.call(this, spec, publicKey);
    Object.assign(keyPairHandle, keyHandleFunctions);
    return keyPairHandle as KeyPairHandle;
}
