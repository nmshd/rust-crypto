#![allow(static_mut_refs)]
use color_eyre::install;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use crypto_layer::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderImplConfig},
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher},
            hashes::CryptoHash,
        },
        factory, KeyPairHandle,
    },
    prelude::*,
};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Once, RwLock},
};
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    fmt::format::FmtSpan,
};

static SETUP_INITIALIZATION: Once = Once::new();

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

#[allow(unused)]
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

static mut STORE: std::sync::LazyLock<TestStore> = std::sync::LazyLock::new(TestStore::new);
const PASSWORD: &str = "test_password";
const SALT: [u8; 16] = [0u8; 16];

// Helper function to create an Ed25519 key pair in SoftwareProvider
fn create_ed25519_key_pair_software(spec: KeyPairSpec) -> KeyPairHandle {
    let impl_config = unsafe { STORE.impl_config().clone() };
    let mut provider = factory::create_provider_from_name("SoftwareProvider", impl_config)
        .expect("Failed to create provider for Ed25519");
    provider
        .create_key_pair(spec)
        .expect("Failed to create Ed25519 keypair")
}

// Helper function to create an AES-GCM-256 key in SoftwareProvider
fn create_aesgcm256_key_software(spec: KeySpec) -> KeyHandle {
    let impl_config = unsafe { STORE.impl_config().clone() };
    let mut provider = factory::create_provider_from_name("SoftwareProvider", impl_config)
        .expect("Failed to create provider");

    provider
        .create_key(spec)
        .expect("Failed to create AES-GCM-256 key in Rust")
}

// Helper function to derive a key from a password in SoftwareProvider
fn derive_key_in_rust_software(spec: KeyPairSpec) -> KeyHandle {
    let impl_config = unsafe { STORE.impl_config().clone() };
    let mut provider = factory::create_provider_from_name("SoftwareProvider", impl_config)
        .expect("Failed to create provider");

    let key_pair = provider
        .derive_key_from_password(PASSWORD, &SALT, spec)
        .expect("Failed to derive key");
    let key = key_pair.extract_key().expect("Failed to extract key");
    let sym_spec = KeySpec {
        cipher: Cipher::XChaCha20Poly1305,
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: true,
    };
    provider
        .import_key(sym_spec, &key)
        .expect("Failed to import key")
}

// ------------------------------------------------------------------------
// Benchmarks for KeyPairHandle (Ed25519) - SoftwareProvider
// ------------------------------------------------------------------------
fn bench_sign_ed25519_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_ed25519_software");

    let spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Curve25519,
        cipher: None,
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: true,
        non_exportable: false,
    };
    let key_pair = create_ed25519_key_pair_software(spec);

    for size in [1, 1024, 1024 * 1024].iter() {
        let data = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                key_pair
                    .sign_data(black_box(data))
                    .expect("Failed to sign data")
            });
        });
    }

    group.finish();
}

fn bench_verify_ed25519_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_ed25519_software");

    let spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Curve25519,
        cipher: None,
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: true,
        non_exportable: false,
    };
    let key_pair = create_ed25519_key_pair_software(spec);

    for size in [1, 1024, 1024 * 1024].iter() {
        let data = vec![0x42u8; *size];
        let signature = key_pair.sign_data(&data).expect("Failed to sign data");
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                key_pair
                    .verify_signature(black_box(data), black_box(&signature))
                    .expect("Failed to verify signature")
            });
        });
    }

    group.finish();
}

// ------------------------------------------------------------------------
// Benchmarks for KeyHandle (AES-GCM-256) - SoftwareProvider
// ------------------------------------------------------------------------
fn bench_encrypt_aesgcm256_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_aesgcm256_software");

    let spec = KeySpec {
        cipher: Cipher::AesGcm256,
        ..Default::default()
    };
    let key_handle = create_aesgcm256_key_software(spec);

    for size in [1, 1024, 1024 * 1024].iter() {
        let data = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                key_handle
                    .encrypt_data(black_box(data))
                    .expect("Failed to encrypt data");
            });
        });
    }

    group.finish();
}

fn bench_decrypt_aesgcm256_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_aesgcm256_software");

    let spec = KeySpec {
        cipher: Cipher::AesGcm256,
        ..Default::default()
    };
    let key_handle = create_aesgcm256_key_software(spec);

    for size in [1, 1024, 1024 * 1024].iter() {
        let data = vec![0x42u8; *size];
        let (ciphertext, nonce) = key_handle
            .encrypt_data(&data)
            .expect("Failed to encrypt data");

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, _| {
            b.iter(|| {
                key_handle
                    .decrypt_data(black_box(&ciphertext), black_box(&nonce))
                    .expect("Failed to decrypt data");
            });
        });
    }

    group.finish();
}

// ------------------------------------------------------------------------
// Benchmarks for Key Derivation (XChaCha20Poly1305) - SoftwareProvider
// ------------------------------------------------------------------------
fn bench_derive_key_xchacha20poly1305_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("derive_key_xchacha20poly1305_software");

    let spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Curve25519,
        cipher: Some(Cipher::XChaCha20Poly1305),
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: true,
        non_exportable: false,
    };
    group.bench_function("derive_key", |b| {
        b.iter(|| derive_key_in_rust_software(spec))
    });
    group.finish();
}

fn bench_encrypt_xchacha20poly1305_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_xchacha20poly1305_software");

    let spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Curve25519,
        cipher: Some(Cipher::XChaCha20Poly1305),
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: true,
        non_exportable: false,
    };
    let key_handle = derive_key_in_rust_software(spec);

    for size in [1, 1024, 1024 * 1024].iter() {
        let data = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                key_handle
                    .encrypt_data(black_box(data))
                    .expect("Failed to encrypt data");
            });
        });
    }

    group.finish();
}

fn bench_decrypt_xchacha20poly1305_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_xchacha20poly1305_software");

    let spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Curve25519,
        cipher: Some(Cipher::XChaCha20Poly1305),
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: true,
        non_exportable: false,
    };
    let key_handle = derive_key_in_rust_software(spec);

    for size in [1, 1024, 1024 * 1024].iter() {
        let data = vec![0x42u8; *size];
        let (ciphertext, nonce) = key_handle
            .encrypt_data(&data)
            .expect("Failed to encrypt data");

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, _| {
            b.iter(|| {
                key_handle
                    .decrypt_data(black_box(&ciphertext), black_box(&nonce))
                    .expect("Failed to decrypt data");
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sign_ed25519_software,
    bench_verify_ed25519_software,
    bench_encrypt_aesgcm256_software,
    bench_decrypt_aesgcm256_software,
    bench_derive_key_xchacha20poly1305_software,
    bench_encrypt_xchacha20poly1305_software,
    bench_decrypt_xchacha20poly1305_software,
);
criterion_main!(benches);
