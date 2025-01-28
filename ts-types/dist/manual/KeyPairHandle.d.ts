import { KeyPairSpec } from "../generated";
export type KeyPairHandle = {
    encryptData: (data: Uint8Array) => Uint8Array;
    decryptData: (encryptedData: Uint8Array) => Uint8Array;
    signData: (data: Uint8Array) => Uint8Array;
    verifySignature: (data: Uint8Array, signature: Uint8Array) => boolean;
    getPublicKey: () => Uint8Array;
    extractKey: () => Uint8Array;
    id: () => string;
    delete: () => void;
    spec: () => KeyPairSpec;
};
//# sourceMappingURL=KeyPairHandle.d.ts.map