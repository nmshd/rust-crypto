import { ProviderConfig, ProviderImplConfig } from "../generated";
import { Provider } from "./Provider";

export type GetAllProvidersFunc = {
    (): Promise<string[]>;
};

export type GetProviderCapabilitiesFunc = {
    (implConf: ProviderImplConfig): Promise<[string, ProviderConfig][]>;
}

export type CreateProviderFunc = {
    (conf: ProviderConfig, implConf: ProviderImplConfig): Promise<Provider | undefined>;
};

export type CreateProviderFromNameFunc = {
    (name: string, implConf: ProviderImplConfig): Promise<Provider | undefined>;
};

export type ProviderFactoryFunctions = {
    getAllProviders: GetAllProvidersFunc,
    getProviderCapabilities: GetProviderCapabilitiesFunc,
    createProvider: CreateProviderFunc,
    createProviderFromName: CreateProviderFromNameFunc,
}
