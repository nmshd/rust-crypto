use config::{KeyPairSpec, KeySpec, ProviderConfig};
use error::CalError;
use tracing::error;
use traits::key_handle::{
    DHKeyExchangeImplEnum, KeyHandleImpl, KeyHandleImplEnum, KeyPairHandleImpl,
    KeyPairHandleImplEnum,
};
use traits::module_provider::{ProviderImpl, ProviderImplEnum};

pub mod config;
pub mod crypto;
pub mod error;
pub mod factory;
pub(crate) mod traits;

macro_rules! delegate_enum {
    ($(pub fn $method:ident(&self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub fn $method(&self $(,$arg: $type)*) $(-> $ret)? {
                match self.implementation.$method($($arg),*) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        error!("Error in {}: {:?}", stringify!($method), e);
                        Err(e)
                    }
                }
            }
        )+
    };
    ($(pub fn $method:ident(&mut self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub fn $method(&mut self $(,$arg: $type)*) $(-> $ret)? {
                match self.implementation.$method($($arg),*) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        error!("Error in {}: {}", stringify!($method), e);
                        Err(e)
                    }
                }
            }
        )+
    };
}

macro_rules! delegate_enum_bare {
    ($(pub fn $method:ident(&self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub fn $method(&self $(,$arg: $type)*) $(-> $ret)? {
                self.implementation.$method($($arg),*)
            }
        )+
    };
    ($(pub fn $method:ident(&mut self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub fn $method(&mut self $(,$arg: $type)*) $(-> $ret)? {
                self.implementation.$method($($arg),*)
            }
        )+
    };
}

/// Abstraction of cryptographic providers.
///
/// [Provider] abstracts hardware, software and network based keystores.
pub struct Provider {
    pub(crate) implementation: ProviderImplEnum,
}

impl Provider {
    delegate_enum! {
        pub fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError>;
    }

    delegate_enum! {
        pub fn load_key(&mut self, id: String) -> Result<KeyHandle, CalError>;
    }

    delegate_enum! {
        pub fn import_key(
            &mut self,
            spec: KeySpec,
            data: &[u8],
        ) -> Result<KeyHandle, CalError>;
    }

    delegate_enum! {
        pub fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        pub fn load_key_pair(&mut self, id: String) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        pub fn import_key_pair(
            &mut self,
            spec: KeyPairSpec,
            public_key: &[u8],
            private_key: &[u8],
        ) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        pub fn import_public_key(
            &mut self,
            spec: KeyPairSpec,
            public_key: &[u8],
        ) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        pub fn start_ephemeral_dh_exchange(
            &mut self,
            spec: KeyPairSpec,
        ) -> Result<DHExchange, CalError>;
    }

    delegate_enum_bare! {
        pub fn provider_name(&self) -> String;
    }

    delegate_enum_bare! {
        pub fn get_capabilities(&self) -> ProviderConfig;
    }
}

pub struct KeyPairHandle {
    pub(crate) implementation: KeyPairHandleImplEnum,
}

/// Abstraction of asymmetric key pair handles.
impl KeyPairHandle {
    delegate_enum! {
        pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        pub fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        pub fn verify_signature(
            &self,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, CalError>;
    }

    delegate_enum! {
        pub fn get_public_key(&self) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        pub fn id(&self) -> Result<String, CalError>;
    }

    /// Returns the id of the key pair, which can be used with [Provider::load_key_pair].
    pub fn id(&self) -> Result<String, SecurityModuleError> {
        self.implementation.id()
    }
}

pub struct KeyHandle {
    pub(crate) implementation: KeyHandleImplEnum,
}

impl KeyHandle {
    delegate_enum! {
        pub fn extract_key(&self) -> Result<Vec<u8>, CalError>;
    }
    delegate_enum! {
        pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }
    delegate_enum! {
        pub fn decrypt_data(
            &self,
            encrypted_data: &[u8],
        ) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        pub fn id(&self) -> Result<String, CalError>;
    }

    /// Returns the id of the key, which can be used with [Provider::load_key].
    pub fn id(&self) -> Result<String, SecurityModuleError> {
        self.implementation.id()
    }
}

#[allow(dead_code)]
pub struct DHExchange {
    pub(crate) implementation: DHKeyExchangeImplEnum,
}
