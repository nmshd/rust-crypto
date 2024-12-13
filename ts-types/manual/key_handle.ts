import { KeyHandle } from "../generated";

export namespace KeyHandleNS {
    export interface ExtractKeyFunc {
        (self: KeyHandle): Uint8Array;
    }

    export interface EncryptDataFunc {
        (self: KeyHandle, data: Uint8Array): [Uint8Array, Uint8Array];
    }

    export interface DecryptDataFunc {
        (self: KeyHandle, encryptedData: Uint8Array, iv: Uint8Array): Uint8Array;
    }

    export interface IdFunc {
        (self: KeyHandle): string;
    }

    export interface DeleteFunc {
        (self: KeyHandle): undefined;
    }
}