#![allow(static_mut_refs, dead_code, unused_variables)]
#[cfg(feature = "hsm")]
mod hsm;

#[cfg(any(feature = "apple-secure-enclave", feature = "win", feature = "linux"))]
mod tpm;

#[cfg(feature = "nks")]
mod nks;

#[cfg(feature = "software")]
mod software;

use std::collections::HashMap;
use std::sync::Once;
use std::sync::{Arc, RwLock};
use std::{io, vec};

use color_eyre::install;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    fmt::format::FmtSpan,
};

use crate::common::config::{AdditionalConfig, ProviderImplConfig};
use crate::common::KeyPairHandle;

static SETUP_INITIALIZATION: Once = Once::new();

/// When going out of scope, deletes the key pair it holds.
struct CleanupKeyPair {
    key_pair_handle: KeyPairHandle,
}

impl Drop for CleanupKeyPair {
    fn drop(&mut self) {
        self.key_pair_handle
            .clone()
            .delete()
            .expect("Failed cleanup of key.");
    }
}

impl CleanupKeyPair {
    #[allow(dead_code)]
    fn new(key_pair_handle: KeyPairHandle) -> Self {
        Self { key_pair_handle }
    }
}

fn setup() {
    SETUP_INITIALIZATION.call_once(|| {
        install().unwrap();

        // Please change this subscriber as you see fit.
        fmt()
            .with_max_level(LevelFilter::DEBUG)
            .compact()
            .with_span_events(FmtSpan::ACTIVE)
            .with_writer(io::stderr)
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    });
}

struct TestStore {
    store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl TestStore {
    fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn impl_config<'a: 'static>(&'a self) -> ProviderImplConfig {
        let kv_store = AdditionalConfig::KVStoreConfig {
            get_fn: Arc::new(|key| Box::pin(self.get(key))),
            store_fn: Arc::new(|key, value| Box::pin(self.store(key, value))),
            delete_fn: Arc::new(|key| Box::pin(self.delete(key))),
            all_keys_fn: Arc::new(|| Box::pin(self.keys())),
        };

        let hmac = AdditionalConfig::StorageConfigPass("TestHMAC".to_owned());

        ProviderImplConfig {
            additional_config: vec![kv_store, hmac],
        }
    }

    async fn get(&self, key: String) -> Option<Vec<u8>> {
        let r = self.store.read().unwrap();
        r.get(&key).cloned()
    }

    async fn store(&self, key: String, value: Vec<u8>) -> bool {
        let mut w = self.store.write().unwrap();
        w.insert(key, value);
        true
    }

    async fn delete(&self, key: String) {
        let mut r = self.store.write().unwrap();
        r.remove(&key).unwrap();
    }

    async fn keys(&self) -> Vec<String> {
        let r = self.store.read().unwrap();
        r.keys().cloned().collect()
    }
}
