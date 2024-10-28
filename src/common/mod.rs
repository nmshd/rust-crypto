#![allow(unused)]
#![allow(dead_code)]

use config::{KeyPairSpec, KeySpec};
use error::CalError;
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

macro_rules! delegate {
    ($(pub async fn $method:ident(&self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub async fn $method(&self $(,$arg: $type)*) $(-> $ret)? {
                self.implementation.$method($($arg),*).await
            }
        )+
    };
    ($(pub async fn $method:ident(&mut self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub async fn $method(&mut self $(,$arg: $type)*) $(-> $ret)? {
                #[cfg(feature = "flutter")]
                {
                    self.implementation.write().await.$method($($arg),*).await
                }
                #[cfg(not(feature = "flutter"))]
                self.implementation.$method($($arg),*).await
            }
        )+
    };
}

macro_rules! delegate_enum {
    ($enum_type:ty, $(pub fn $method:ident(&self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
        $(
            pub fn $method(&self $(,$arg: $type)*) $(-> $ret)? {
                self.implementation.$method($($arg),*)
            }
        )+
    };
    ($enum_type:ty, $(pub fn $method:ident(&mut self $(,$arg:ident: $type:ty)* $(,)?) $(-> $ret:ty)?;)+) => {
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
        Provider,
        pub fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn load_key(&mut self, id: String) -> Result<KeyHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn import_key(
            &mut self,
            spec: KeySpec,
            data: &[u8],
        ) -> Result<KeyHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn load_key_pair(&mut self, id: String) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn import_key_pair(
            &mut self,
            spec: KeyPairSpec,
            public_key: &[u8],
            private_key: &[u8],
        ) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn import_public_key(
            &mut self,
            spec: KeyPairSpec,
            public_key: &[u8],
        ) -> Result<KeyPairHandle, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn start_ephemeral_dh_exchange(
            &mut self,
            spec: KeyPairSpec,
        ) -> Result<DHExchange, CalError>;
    }

    delegate_enum! {
        Provider,
        pub fn provider_name(&self) -> String;
    }
}

pub struct KeyPairHandle {
    pub(crate) implementation: KeyPairHandleImplEnum,
}

/// Abstraction of asymmetric key pair handles.
impl KeyPairHandle {
    delegate_enum! {
        KeyPairHandle,
        pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        KeyPairHandle,
        pub fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        KeyPairHandle,
        pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }

    delegate_enum! {
        KeyPairHandle,
        pub fn verify_signature(
            &self,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, CalError>;
    }

    delegate_enum! {
        KeyPairHandle,
        pub fn get_public_key(&self) -> Result<Vec<u8>, CalError>;
    }

    /// Returns the id of the key pair, which can be used with [Provider::load_key_pair].
    delegate_enum! {
        KeyPairHandle,
        pub fn id(&self) -> Result<String, CalError>;
    }
}

pub struct KeyHandle {
    pub(crate) implementation: KeyHandleImplEnum,
}

impl KeyHandle {
    delegate_enum! {
        KeyHandle,
        pub fn extract_key(&self) -> Result<Vec<u8>, CalError>;
    }
    delegate_enum! {
        KeyHandle,
        pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;
    }
    delegate_enum! {
        KeyHandle,
        pub fn decrypt_data(
            &self,
            encrypted_data: &[u8],
        ) -> Result<Vec<u8>, CalError>;
    }

    /// Returns the id of the key, which can be used with [Provider::load_key].
    delegate_enum! {
        KeyHandle,
        pub fn id(&self) -> Result<String, CalError>;
    }
}

pub struct DHExchange {
    pub(crate) implementation: DHKeyExchangeImplEnum,
}
