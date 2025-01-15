export type KeyHandle = {
    extractKey: () => Uint8Array;
    encryptData: (data: Uint8Array) => [Uint8Array, Uint8Array];
    decryptData: (encryptedData: Uint8Array, iv: Uint8Array) => Uint8Array;
    id: () => string;
    delete: () => undefined;
};
//# sourceMappingURL=KeyHandle.d.ts.map