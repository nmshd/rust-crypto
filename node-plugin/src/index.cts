// This module is the CJS entry point for the library.

// The Rust addon.
export * from './load.cjs';

//export * from "crypto-layer-ts-types";

import { type ProviderConfig, type ProviderImplConfig, type Provider, CreateProviderFunc, GetAllProvidersFunc, KeySpec, KeyHandle, KeyPairHandle, KeyPairSpec } from "crypto-layer-ts-types";

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
  export function getAllProviders(): string[];
  export function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Provider | undefined;
  export function createProviderFromName(name: string, impl_config: ProviderImplConfig): Provider | undefined;
  export function providerName(provider: Provider): string;
  export function createKey(provider: Provider, spec: KeySpec): KeyHandle;
  export function createKeyPair(provider: Provider, spec: KeyPairSpec): KeyPairHandle;
  export function signDataWithKeyPairHandle(handle: KeyPairHandle, data: Uint8Array): Uint8Array;
  export function verifyDataWithKeyPairHandle(handle: KeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
}

