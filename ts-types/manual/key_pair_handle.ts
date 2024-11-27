import { KeyPairHandle } from "../generated";

export namespace KeyPairHandleNs {
    export interface EncryptDataFunc {
        (self: KeyPairHandle, data: Uint8Array): Uint8Array;
    }

    export interface DecryptDataFunc {
        (self: KeyPairHandle, encryptedData: Uint8Array): Uint8Array;
    }

    export interface SignDataFunc {
        (self: KeyPairHandle, data: Uint8Array): Uint8Array;
    }

    export interface VerifySignatureFunc {
        (self: KeyPairHandle, data: Uint8Array, signature: Uint8Array): boolean;
    }

    export interface GetPublicKeyFunc {
        (self: KeyPairHandle): Uint8Array;
    }

    export interface IdFunc {
        (self: KeyPairHandle): string;
    }

    export interface DeleteFunc {
        (self: KeyPairHandle): undefined;
    }
}