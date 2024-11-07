//mod common;
#[cfg(feature = "hsm")]
mod hsm;

#[cfg(feature = "tpm")]
mod tpm;

#[cfg(feature = "nks")]
mod nks;

use std::collections::HashMap;
use std::sync::Once;
use std::sync::{Arc, RwLock};

use color_eyre::install;

use crate::common::config::ProviderImplConfig;
use crate::common::KeyPairHandle;

static COLOR_EYRE_INITIALIZATIOIN: Once = Once::new();

/// When going out of scope, deletes the key pair it holds.
#[allow(dead_code)]
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
    COLOR_EYRE_INITIALIZATIOIN.call_once(|| install().unwrap());
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
        ProviderImplConfig {
            get_fn: Arc::new(|key| Box::pin(self.get(key))),
            store_fn: Arc::new(|key, value| Box::pin(self.store(key, value))),
            all_keys_fn: Arc::new(|| Box::pin(self.keys())),
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

    async fn keys(&self) -> Vec<String> {
        let r = self.store.read().unwrap();
        r.keys().cloned().collect()
    }
}
