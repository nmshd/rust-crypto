"use strict";
// This module is the CJS entry point for the library.
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAllProviders = void 0;
exports.createProvider = createProvider;
exports.createProviderFromName = createProviderFromName;
// The Rust addon.
var load_cjs_1 = require("./load.cjs");
Object.defineProperty(exports, "getAllProviders", { enumerable: true, get: function () { return load_cjs_1.getAllProviders; } });
const load_cjs_2 = require("./load.cjs");
class NodeProvider {
    provider;
    constructor(bareProvider) {
        this.provider = bareProvider;
    }
    providerName() {
        return load_cjs_2.providerName.call(this.provider);
    }
    createKey(spec) {
        return new NodeKeyHandle(load_cjs_2.createBareKey.call(this.provider, spec));
    }
    createKeyPair(spec) {
        return new NodeKeyPairHandle(load_cjs_2.createBareKeyPair.call(this.provider, spec));
    }
    loadKey(id) {
        return new NodeKeyHandle(load_cjs_2.loadBareKey.call(this.provider, id));
    }
    loadKeyPair(id) {
        return new NodeKeyPairHandle(load_cjs_2.loadBareKeyPair.call(this.provider, id));
    }
    importKey(spec, key) {
        return new NodeKeyHandle(load_cjs_2.importBareKey.call(this.provider, spec, key));
    }
    importKeyPair(spec, publicKey, privateKey) {
        return new NodeKeyPairHandle(load_cjs_2.importBareKeyPair.call(this.provider, spec, publicKey, privateKey));
    }
    importPublicKey(spec, publicKey) {
        return new NodeKeyPairHandle(load_cjs_2.importBarePublicKey.call(this.provider, spec, publicKey));
    }
    startEphemeralDhExchange(spec) {
        return new NodeDHExchange(load_cjs_2.startEphemeralDhExchange.call(this.provider, spec));
    }
    getCapabilities() {
        return load_cjs_2.getCapabilities.call(this.provider);
    }
}
class NodeKeyHandle {
    keyHandle;
    constructor(bareKeyHandle) {
        this.keyHandle = bareKeyHandle;
    }
    id() {
        return load_cjs_2.idForKeyHandle.call(this.keyHandle);
    }
    delete() {
        load_cjs_2.deleteForKeyHandle.call(this.keyHandle);
    }
    extractKey() {
        return load_cjs_2.extractKey.call(this.keyHandle);
    }
    encryptData(data) {
        return load_cjs_2.encryptDataForKeyHandle.call(this.keyHandle, data);
    }
    decryptData(encryptedData, iv) {
        return load_cjs_2.decryptDataForKeyHandle.call(this.keyHandle, encryptedData, iv);
    }
}
class NodeKeyPairHandle {
    keyPairHandle;
    constructor(bareKeyPairHandle) {
        this.keyPairHandle = bareKeyPairHandle;
    }
    id() {
        return load_cjs_2.idForKeyPair.call(this.keyPairHandle);
    }
    delete() {
        load_cjs_2.deleteForKeyPair.call(this.keyPairHandle);
    }
    signData(data) {
        return load_cjs_2.signData.call(this.keyPairHandle, data);
    }
    verifySignature(data, signature) {
        return load_cjs_2.verifySignature.call(this.keyPairHandle, data, signature);
    }
    encryptData(data) {
        return load_cjs_2.encryptDataForKeyPairHandle.call(this.keyPairHandle, data);
    }
    decryptData(encryptedData) {
        return load_cjs_2.decryptDataForKeyPairHandle.call(this.keyPairHandle, encryptedData);
    }
    getPublicKey() {
        return load_cjs_2.getPublicKey.call(this.keyPairHandle);
    }
}
class NodeDHExchange {
    dhExchange;
    constructor(bareDHExchange) {
        this.dhExchange = bareDHExchange;
    }
    getPublicKey() {
        return load_cjs_2.getPublicKeyForDHExchange.call(this.dhExchange);
    }
    addExternal(externalKey) {
        return load_cjs_2.addExternalForDHExchange.call(this.dhExchange, externalKey);
    }
    addExternalFinal(externalKey) {
        return new NodeKeyHandle(load_cjs_2.addExternalFinalForDHExchange.call(this.dhExchange, externalKey));
    }
}
function createProvider(config, impl_config) {
    let provider = (0, load_cjs_2.createBareProvider)(config, impl_config);
    if (!provider) {
        return undefined;
    }
    return new NodeProvider(provider);
}
function createProviderFromName(name, impl_config) {
    let provider = (0, load_cjs_2.createBareProviderFromName)(name, impl_config);
    if (!provider) {
        return undefined;
    }
    return new NodeProvider(provider);
}
