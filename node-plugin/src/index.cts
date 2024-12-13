// This module is the CJS entry point for the library.

// The Rust addon.
export * from './load.cjs';

//export * from "crypto-layer-ts-types";

import { type Provider, type ProviderConfig, type ProviderImplConfig, KeyHandle, KeyPairHandle, KeyPairSpec, KeySpec } from "crypto-layer-ts-types";
import { createBareProvider, providerName, signData, verifyData } from './load.cjs';

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
  export function getAllProviders(): string[];
  export function createBareProvider(config: ProviderConfig, impl_config: ProviderImplConfig): {} | undefined;
  export function createProviderFromName(name: string, impl_config: ProviderImplConfig): Provider | undefined;
  export function providerName(this: Provider): string;
  export function createBareKey(this: Provider, spec: KeySpec): {};
  export function createBareKeyPair(this: Provider, spec: KeyPairSpec): {};
  export function signData(this: KeyPairHandle, data: Uint8Array): Uint8Array;
  export function verifyData(this: KeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
}


const providerFunctions = {
  providerName: providerName,
  createKey: createKey,
  createKeyPair: createKeyPair,
}

export function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Provider | undefined {
  let provider = createBareProvider(config, impl_config);
  if (!provider) {
    return undefined;
  }
  Object.assign(provider, providerFunctions);
  return provider;
}


const sharedKeyFunctions = {};
const keyHandleFunctions = {};

export function createKey(this: Provider, spec: KeySpec): KeyHandle {
  let keyHandle = this.createBareKey(spec);
  Object.assign(keyHandle, sharedKeyFunctions);
  Object.assign(keyHandle, keyHandleFunctions);
  return keyHandle;
}


const keyPairHandleFunctions = {
  signData: signData,
  verifyData: verifyData,
};

export function createKeyPair(this: Provider, spec: KeyPairSpec): KeyPairHandle {
  let keyPairHandle = this.createBareKeyPair(spec);
  Object.assign(keyPairHandle, sharedKeyFunctions);
  Object.assign(keyPairHandle, keyHandleFunctions);
  return keyPairHandle;
}