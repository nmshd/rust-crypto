import { ProviderConfig, ProviderImplConfig } from "../generated";
import { Provider } from "./Provider";

export type GetAllProvidersFunc = {
    (): Promise<string[]>;
};

export type CreateProviderFunc = {
    (conf: ProviderConfig, implConf: ProviderImplConfig): Promise<Provider | undefined>;
};

export type CreateProviderFromNameFunc = {
    (name: string, implConf: ProviderImplConfig): Promise<Provider | undefined>;
};
