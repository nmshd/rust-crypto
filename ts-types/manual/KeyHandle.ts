import type { KeySpec } from "../generated/index.ts";

export type KeyHandle = {
	extractKey: () => Promise<Uint8Array>;
	/** @deprecated In favor of the more explicit {@link KeyHandle.encrypt} and {@link KeyHandle.encryptWithIv} methods. */
	encryptData: (data: Uint8Array, iv: Uint8Array) => Promise<[Uint8Array, Uint8Array]>;
	encrypt: (data: Uint8Array) => Promise<[Uint8Array, Uint8Array]>;
	encryptWithIv: (data: Uint8Array, iv: Uint8Array) => Promise<Uint8Array>;
	decryptData: (
		encryptedData: Uint8Array,
		iv: Uint8Array,
	) => Promise<Uint8Array>;
	id: () => Promise<string>;
	delete: () => Promise<void>;
	spec: () => Promise<KeySpec>;
	deriveKey: (nonce: Uint8Array) => Promise<KeyHandle>;
};
