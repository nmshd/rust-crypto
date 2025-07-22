import { createAssertGuard, createIs } from "typia";
import type {
	AdditionalConfig,
	Argon2Options,
	AsymmetricKeySpec,
	CalError,
	CalErrorKind,
	Cipher,
	CryptoHash,
	KDF,
	KeyPairSpec,
	KeySpec,
	KeyType,
	ProviderConfig,
	ProviderImplConfig,
	SecurityLevel,
	Spec,
} from "../generated/index.js";
import type {
	DHExchange,
	KeyHandle,
	KeyPairHandle,
	Provider,
} from "../manual/index.ts";

export const isKeyHandle = createIs<KeyHandle>();
export const assertKeyHandle = createAssertGuard<KeyHandle>();

export const isProvider = createIs<Provider>();
export const assertProvider = createAssertGuard<Provider>();

export const isKeyPairHandle = createIs<KeyPairHandle>();
export const assertKeyPairHandle = createAssertGuard<KeyPairHandle>();

// biome-ignore lint/style/useNamingConvention: <explanation>
export const isDHExchange = createIs<DHExchange>();
// biome-ignore lint/style/useNamingConvention: <explanation>
export const assertDHExchange = createAssertGuard<DHExchange>();

export const isAdditionalConfig = createIs<AdditionalConfig>();
export const assertAdditionalConfig = createAssertGuard<AdditionalConfig>();

export const isArgon2Options = createIs<Argon2Options>();
export const assertArgon2Options = createAssertGuard<Argon2Options>();

export const isAsymmetricKeySpec = createIs<AsymmetricKeySpec>();
export const assertAsymmetricKeySpec = createAssertGuard<AsymmetricKeySpec>();

export const isCalError = createIs<CalError>();
export const assertCalError = createAssertGuard<CalError>();

export const isCalErrorKind = createIs<CalErrorKind>();
export const assertCalErrorKind = createAssertGuard<CalErrorKind>();

export const isCipher = createIs<Cipher>();
export const assertCipher = createAssertGuard<Cipher>();

export const isCryptoHash = createIs<CryptoHash>();
export const assertCryptoHash = createAssertGuard<CryptoHash>();

// biome-ignore lint/style/useNamingConvention: <explanation>
export const isKDF = createIs<KDF>();
// biome-ignore lint/style/useNamingConvention: <explanation>
export const assertKDF = createAssertGuard<KDF>();

export const isKeyPairSpec = createIs<KeyPairSpec>();
export const assertKeyPairSpec = createAssertGuard<KeyPairSpec>();

export const isKeySpec = createIs<KeySpec>();
export const assertKeySpec = createAssertGuard<KeySpec>();

export const isSpec = createIs<Spec>();
export const assertSpec = createAssertGuard<Spec>();

export const isKeyType = createIs<KeyType>();
export const assertKeyType = createAssertGuard<KeyType>();

export const isProviderConfig = createIs<ProviderConfig>();
export const assertProviderConfig = createAssertGuard<ProviderConfig>();

export const isProviderImplConfig = createIs<ProviderImplConfig>();
export const assertProviderImplConfig = createAssertGuard<ProviderImplConfig>();

export const isSecurityLevel = createIs<SecurityLevel>();
export const assertSecurityLevel = createAssertGuard<SecurityLevel>();
