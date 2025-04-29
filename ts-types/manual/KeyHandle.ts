import type { KeySpec } from "../generated/index.ts";

export type KeyHandle = {
	extractKey: () => Promise<Uint8Array>;
	encryptData: (data: Uint8Array, iv: Uint8Array) => Promise<[Uint8Array, Uint8Array]>;
	decryptData: (
		encryptedData: Uint8Array,
		iv: Uint8Array,
	) => Promise<Uint8Array>;
	id: () => Promise<string>;
	delete: () => Promise<void>;
	spec: () => Promise<KeySpec>;
};
