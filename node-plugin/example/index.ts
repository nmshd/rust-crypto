import { createProvider, getAllProviders } from "crypto-layer-node";
import { type ProviderConfig, type ProviderImplConfig, type KeyPairSpec, type KeyPairHandle } from "crypto-layer-ts-types";
import { exit } from "process";

console.log("Providers: ", getAllProviders());

let providerConfig: ProviderConfig = {
    max_security_level: "Software",
    min_security_level: "Software",
    supported_asym_spec: ["P256"],
    supported_ciphers: [],
    supported_hashes: ["Sha2_256", "Sha2_384"]
};

let providerImplConfig: ProviderImplConfig = {
    additional_config: [{ FileStoreConfig: { db_dir: "./db" } }, { StorageConfigPass: "1234" }]
};

let provider = createProvider(providerConfig, providerImplConfig);

if (!provider) {
    console.log("Failed creating provider.");
    exit(1);
}

console.log("Provider initialized: ", provider.providerName());
console.log("Capabilities: ", provider.getCapabilities());

let keypairspec: KeyPairSpec = {
    asym_spec: "P256",
    cipher: null,
    signing_hash: "Sha2_224",
    ephemeral: true
};

console.log("Creating KeyPair");

let keypair = provider.createKeyPair(keypairspec) as KeyPairHandle;

console.log("Created KeyPair");

let data = Uint8Array.from([1, 2, 3, 4]);

console.log("Data: ", data);

let signature = keypair.signData(data);

console.log("Signature: ", signature);

try {
    console.log("Verified: ", keypair.verifySignature(data, signature) ? "OK" : "FAILURE");
} catch (e) {
    console.log("Error while verifying:\n", e);
}

exit(0);
