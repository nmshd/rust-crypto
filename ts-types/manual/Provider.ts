import { KeyPairSpec, KeySpec, ProviderConfig } from "../generated";
import { KeyHandle, KeyPairHandle, DHExchange } from "./";

export type Provider = {
    createKey: (spec: KeySpec) => Promise<KeyHandle>;
    loadKey: (id: string) => Promise<KeyHandle>;
    importKey: (spec: KeySpec, data: Uint8Array) => Promise<KeyHandle>;
    createKeyPair: (spec: KeyPairSpec) => Promise<KeyPairHandle>;
    loadKeyPair: (id: string) => Promise<KeyPairHandle>;
    importKeyPair: (spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array) => Promise<KeyPairHandle>;
    importPublicKey: (spec: KeyPairSpec, publicKey: Uint8Array) => Promise<KeyPairHandle>;
    startEphemeralDhExchange: (spec: KeyPairSpec) => Promise<DHExchange>;
    providerName: () => Promise<string>;
    getCapabilities: () => Promise<ProviderConfig | undefined>;
};
