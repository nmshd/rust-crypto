// This module is the CJS entry point for the library.

// The Rust addon.
export * from './load.cjs';

//export * from "crypto-layer-ts-types";

import { type ProviderConfig, type ProviderImplConfig, type Provider, CreateProviderFunc, GetAllProvidersFunc } from "crypto-layer-ts-types";

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
  export function getAllProviders(): string[];
  export function createProvider(config: ProviderConfig, impl_config: ProviderImplConfig): Provider | undefined;
}

