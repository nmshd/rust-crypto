import type { KeyHandle } from "./index.ts";

// biome-ignore lint/style/useNamingConvention: <explanation>
export type DHExchange = {
	getPublicKey: () => Promise<Uint8Array>;
	// addExternal: (externalKey: Uint8Array) => Promise<Uint8Array>;
	// addExternalFinal: (externalKey: Uint8Array) => Promise<KeyHandle>;
	deriveClientSessionKeys: (
		serverPk: Uint8Array,
	) => Promise<[Uint8Array, Uint8Array]>;
	deriveServerSessionKeys: (
		clientPk: Uint8Array,
	) => Promise<[Uint8Array, Uint8Array]>;
	deriveClientKeyHandles: (
		serverPk: Uint8Array,
	) => Promise<[KeyHandle, KeyHandle]>;
	deriveServerKeyHandles: (
		clientPk: Uint8Array,
	) => Promise<[KeyHandle, KeyHandle]>;
};
