use config::{KeyPairSpec, KeySpec};
use error::SecurityModuleError;
use traits::key_handle::{DHKeyExchangeImpl, KeyHandleImpl, KeyPairHandleImpl};
use traits::module_provider::ProviderImpl;

pub mod config;
pub mod crypto;
pub mod error;
pub mod factory;
pub mod traits;

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
                self.implementation.$method($($arg),*).await
            }
        )+
    };
}

/// Abstraction of cryptographic providers.
///
/// [Provider] abstracts hardware, software and network based keystores.
/// [Provider] itself is a wrapper around the structs which implement [ProviderImpl].
/// This is done for compatibility with other programming languages (mainly dart).
pub struct Provider {
    implementation: Box<dyn ProviderImpl>,
}

impl Provider {
    pub async fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError> {
        self.implementation.create_key(spec).await
    }

    pub async fn load_key(&mut self, id: String) -> Result<KeyHandle, SecurityModuleError> {
        self.implementation.load_key(id).await
    }

    delegate! {
        pub async fn import_key(
            &mut self,
            spec: KeySpec,
            data: &[u8],
        ) -> Result<KeyHandle, SecurityModuleError>;
    }

    delegate! {
        pub async fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, SecurityModuleError>;
    }

    delegate! {
        pub async fn load_key_pair(&mut self, id: String) -> Result<KeyPairHandle, SecurityModuleError>;
    }

    delegate! {
        pub async fn import_key_pair(
            &mut self,
            spec: KeyPairSpec,
            public_key: &[u8],
            private_key: &[u8],
        ) -> Result<KeyPairHandle, SecurityModuleError>;
    }

    delegate! {
        pub async fn import_public_key(
            &mut self,
            spec: KeyPairSpec,
            public_key: &[u8],
        ) -> Result<KeyPairHandle, SecurityModuleError>;
    }

    delegate! {
        pub async fn start_ephemeral_dh_exchange(
            &mut self,
            spec: KeyPairSpec,
        ) -> Result<DHExchange, SecurityModuleError>;
    }

    pub fn provider_name(&self) -> String {
        self.implementation.provider_name()
    }
}

pub struct KeyPairHandle {
    implementation: Box<dyn KeyPairHandleImpl>,
}

/// Abstraction of asymmetric key pair handles.
impl KeyPairHandle {
    pub async fn encrypt_data(&self, data: Vec<u8>) -> Result<Vec<u8>, SecurityModuleError> {
        self.implementation.encrypt_data(&data).await
    }
    pub async fn decrypt_data(&self, data: Vec<u8>) -> Result<Vec<u8>, SecurityModuleError> {
        self.implementation.decrypt_data(&data).await
    }
    pub async fn sign_data(&self, data: Vec<u8>) -> Result<Vec<u8>, SecurityModuleError> {
        self.implementation.sign_data(&data).await
    }
    pub async fn verify_signature(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, SecurityModuleError> {
        self.implementation
            .verify_signature(&data, &signature)
            .await
    }
    pub async fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        self.implementation.get_public_key().await
    }
}

pub struct KeyHandle {
    implementation: Box<dyn KeyHandleImpl>,
}

impl KeyHandle {
    delegate! {
        pub async fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError>;
    }
    delegate! {
        pub async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;
    }
    delegate! {
        pub async fn decrypt_data(
            &self,
            encrypted_data: &[u8],
        ) -> Result<Vec<u8>, SecurityModuleError>;
    }
}

pub struct DHExchange {
    implementation: Box<dyn DHKeyExchangeImpl>,
}
