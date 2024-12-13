import { createProvider, getAllProviders } from "crypto-layer-node";
import { type ProviderConfig, type ProviderImplConfig } from "crypto-layer-ts-types";
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
        
    ]
}

let provider = createProvider(providerConfig, providerImplConfig);

if (!provider) {
    console.log("Failed creating provider.");
    exit(1);
}

console.log("Provider initialized: ", provider.providerName())

/* let keypairspec: KeyPairSpec = {
    asym_spec: "P256",
    cipher: null,
    signing_hash: "Sha2_224",
}

console.log("Creating KeyPair");

let keypair = provider.createKeyPair(keypairspec);

console.log("Created KeyPair");

let data = Uint8Array.from([1, 2, 3, 4]);

console.log("Data: ", data);

let signature = keypair.signData(data);

console.log("Signature: ", signature);

console.log("Verified: ", keypair.verifyData(data, signature) ? "OK" : "FAILURE") */

exit(0)
