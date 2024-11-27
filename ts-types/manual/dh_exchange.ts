import { DHExchange, KeyHandle } from "../generated";

export namespace DhExchangeNs {
    export interface GetPublicKeyFunc {
        (self: DHExchange): Uint8Array;
    }

    export interface AddExternalFunc {
        (self: DHExchange, externalKey: Uint8Array): Uint8Array;
    }

    export interface AddExternalFinalFunc {
        (self: DHExchange, externalKey: Uint8Array): KeyHandle;
    }
}