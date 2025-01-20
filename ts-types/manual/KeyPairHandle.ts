import { KeyPairSpec } from "../generated";

export type KeyPairHandle = {
    encryptData: (data: Uint8Array) => Promise<Uint8Array>;
    decryptData: (encryptedData: Uint8Array) => Promise<Uint8Array>;
    signData: (data: Uint8Array) => Promise<Uint8Array>;
    verifySignature: (data: Uint8Array, signature: Uint8Array) => Promise<boolean>;
    getPublicKey: () => Promise<Uint8Array>;
    id: () => Promise<string>;
    delete: () => Promise<void>;
    spec: () => Promise<KeyPairSpec>;
};
