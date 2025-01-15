import { KeyHandle, KeyPairHandle } from "./";
import { DHExchange, KeyPairSpec, ProviderConfig, KeySpec } from "../generated";
export type Provider = {
    createKey: (spec: KeySpec) => KeyHandle;
    loadKey: (id: string) => KeyHandle;
    importKey: (spec: KeySpec, data: Uint8Array) => KeyHandle;
    createKeyPair: (spec: KeyPairSpec) => KeyPairHandle;
    loadKeyPair: (id: string) => KeyPairHandle;
    importKeyPair: (spec: KeyPairSpec, publicKey: Uint8Array, privateKey: Uint8Array) => KeyPairHandle;
    importPublicKey: (spec: KeyPairSpec, publicKey: Uint8Array) => KeyPairHandle;
    startEphemeralDhExchange: (spec: KeyPairSpec) => DHExchange;
    providerName: () => string;
    getCapabilities: () => ProviderConfig | undefined;
};
//# sourceMappingURL=Provider.d.ts.map