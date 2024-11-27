import { DHExchange, KeyHandle, KeyPairHandle, KeyPairSpec, KeySpec, Provider, ProviderConfig } from "../generated";

export interface CreateKeyFunc {
    (self: Provider, spec: KeySpec): KeyHandle;
}

export interface LoadKeyFunc {
    (self: Provider, id: string): KeyHandle;
}

export interface ImportKeyFunc {
    (self: Provider, spec: KeySpec, data: Uint8Array): KeyHandle;
}

export interface CreateKeyPairFunc {
    (self: Provider, spec: KeyPairSpec): KeyPairHandle;
}

export interface LoadKeyPairFunc {
    (self: Provider, id: string): KeyPairHandle;
}

export interface ImportKeyPairFunc {
    (self: Provider, spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array): KeyPairHandle;
}

export interface ImportPublicKeyFunc {
    (self: Provider, spec: KeyPairSpec, publicKey: Uint8Array): KeyPairHandle;
}

export interface StartEphemeralDhExchangeFunc {
    (self: Provider, spec: KeyPairSpec): DHExchange;
}

export interface ProviderNameFunc {
    (self: Provider): string;
}

export interface GetCapabilitiesFunc {
    (self: Provider): ProviderConfig | undefined;
}