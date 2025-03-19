import type {
	CryptoHash,
	KDF,
	KeyPairSpec,
	KeySpec,
	ProviderConfig,
} from "../generated/index.ts";
import type { DHExchange, KeyHandle, KeyPairHandle } from "./index.ts";

export type Provider = {
	createKey: (spec: KeySpec) => Promise<KeyHandle>;
	loadKey: (id: string) => Promise<KeyHandle>;
	importKey: (spec: KeySpec, data: Uint8Array) => Promise<KeyHandle>;
	createKeyPair: (spec: KeyPairSpec) => Promise<KeyPairHandle>;
	loadKeyPair: (id: string) => Promise<KeyPairHandle>;
	importKeyPair: (
		spec: KeyPairSpec,
		publicKey: Uint8Array,
		privateKey: Uint8Array,
	) => Promise<KeyPairHandle>;
	importPublicKey: (
		spec: KeyPairSpec,
		publicKey: Uint8Array,
	) => Promise<KeyPairHandle>;
	startEphemeralDhExchange: (spec: KeyPairSpec) => Promise<DHExchange>;
	providerName: () => Promise<string>;
	getCapabilities: () => Promise<ProviderConfig | undefined>;
	deriveKeyFromPassword: (
		password: string,
		salt: Uint8Array,
		algorithm: KeySpec,
		kdf: KDF,
	) => Promise<KeyHandle>;
	deriveKeyFromBase(
		baseKey: Uint8Array,
		keyId: number,
		context: string,
		spec: KeySpec,
	): Promise<KeyHandle>;
	getRandom: (len: number) => Promise<Uint8Array>;
	hash: (input: Uint8Array, hash: CryptoHash) => Promise<Uint8Array>;
};
