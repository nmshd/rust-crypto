import { Provider } from "./Provider";
import { ProviderConfig, ProviderImplConfig } from "../generated";

export type GetAllProvidersFunc = {
    (): string[];
};

export type CreateProviderFunc = {
    (conf: ProviderConfig, implConf: ProviderImplConfig): Provider | undefined;
};

export type CreateProviderFromNameFunc = {
    (name: string, implConf: ProviderImplConfig): Provider | undefined;
};
