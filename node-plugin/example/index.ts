import { createKeyPair, createProvider, getAllProviders, providerName, signDataWithKeyPairHandle, verifyDataWithKeyPairHandle } from "crypto-layer-node";
import { type KeyPairSpec, type ProviderConfig, type ProviderImplConfig } from "crypto-layer-ts-types";
import { exit } from "process";



console.log("Providers: ", getAllProviders())


let kvStore: Map<string, Uint8Array> = new Map();

let providerConfig: ProviderConfig = {
    max_security_level: "Software",
    min_security_level: "Software",
    supported_asym_spec: ["P256"],
    supported_ciphers: [],
    supported_hashes: ["Sha2_256", "Sha2_384"]
}

let providerImplConfig: ProviderImplConfig = {
    additional_config: [
        {
            "KVStoreConfig": {
                get_fn: (id: string): Uint8Array | undefined => { return kvStore.get(id); },
                store_fn: (id: string, data: Uint8Array): boolean => { kvStore.set(id, data); return true; },
                all_keys_fn: (): string[] => { return Array.from(kvStore.keys()); },
                delete_fn: (id: string): undefined => { kvStore.delete(id) }
            }
        }
    ]
}

let provider = createProvider(providerConfig, providerImplConfig);

if (!provider) {
    console.log("Failed creating provider.");
    exit(1);
}

console.log("Provider initialized: ", providerName(provider))

let keypairspec: KeyPairSpec = {
    asym_spec: "P256",
    cipher: null,
    signing_hash: "Sha2_224",
}

console.log("Creating KeyPair");

let keypair = createKeyPair(provider, keypairspec);

console.log("Created KeyPair");

let data = Uint8Array.from([1, 2, 3, 4]);

console.log("Data: ", data);

let signature = signDataWithKeyPairHandle(keypair, data);

console.log("Signature: ", signature);

console.log("Verified: ", verifyDataWithKeyPairHandle(keypair, data, signature) ? "OK" : "FAILURE")

exit(0)
