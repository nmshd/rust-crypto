import { Provider, ProviderConfig, ProviderImplConfig } from "../generated";

export interface GetAllProvidersFunc {
    (): string[];
}

export interface CreateProviderFunc {
    (conf: ProviderConfig, implConf: ProviderImplConfig): Provider | undefined;
}

export interface CreateProviderFromNameFunc {
    (name: string, implConf: ProviderImplConfig): Provider | undefined;
}