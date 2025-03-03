import { KeyHandle } from "./";

export type DHExchange = {
    getPublicKey: () => Promise<Uint8Array>;
    addExternal: (externalKey: Uint8Array) => Promise<Uint8Array>;
    addExternalFinal: (externalKey: Uint8Array) => Promise<KeyHandle>;
};
