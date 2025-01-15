import { KeyHandle } from "../generated";
export type DHExchange = {
    getPublicKey: () => Uint8Array;
    addExternal: (externalKey: Uint8Array) => Uint8Array;
    addExternalFinal: (externalKey: Uint8Array) => KeyHandle;
};
//# sourceMappingURL=DHExchange.d.ts.map