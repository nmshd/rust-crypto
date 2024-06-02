use crate::common::crypto::{
    algorithms::{
        encryption::{AsymmetricEncryption, BlockCiphers, EccSchemeAlgorithm},
        hashes::{Hash, Sha2Bits},
    },
    KeyUsage,
};
use crate::common::traits::log_config::LogConfig;

use tracing::{instrument, Level};
use tracing_appender::rolling;
use tracing_subscriber::FmtSubscriber;

pub mod key_handle;
pub mod logger;
pub mod provider;

/// `SEProvider` is a structure representing a TPM (Trusted Platform Module) provider, here the Secure Enclave,
/// which manages cryptographic keys and algorithms.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SEProvider {
    /// Unique identifier for the key.
    key_id: String,
    // pub(super) key_handle: Option<String>, // Placeholder for key handle (optional, not used here).
    // pub(super) handle: Option<String>, // Placeholder for handle (optional, not used here).
    
    /// Optional asymmetric encryption algorithm used by the provider.
    pub(super) key_algorithm: Option<AsymmetricEncryption>,
    
    /// Optional symmetric block cipher algorithm used by the provider.
    pub(super) sym_algorithm: Option<BlockCiphers>,
    
    /// Optional hash algorithm used by the provider.
    pub(super) hash: Option<Hash>,
    
    /// Optional list of key usages associated with the provider.
    pub(super) key_usages: Option<Vec<KeyUsage>>,
}

impl SEProvider {
    /// Creates a new `SEProvider` instance with the specified key identifier.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string representing the unique identifier for the key.
    ///
    /// # Returns
    ///
    /// A new instance of `SEProvider`.
    #[instrument]
    pub fn new(key_id: String) -> Self {
        tracing::info!("Creating new SEProvider with key_id: {}", key_id);
        Self {
            key_id,
            // key_handle: None,
            // handle: None,
            key_algorithm: None,
            sym_algorithm: None,
            hash: None,
            key_usages: None,
        }
    }
}

/// `Logger` is a structure implementing the `LogConfig` trait to configure logging
/// for the application.
#[derive(Debug, Clone, Copy)]
struct Logger {}

impl Logger {
    /// Creates a new boxed instance of `Logger` that implements the `LogConfig` trait.
    ///
    /// # Returns
    ///
    /// A boxed instance of `Logger`.
    fn new_boxed() -> Box<dyn LogConfig> {
        Box::new(Self {})
    }
}
impl LogConfig for Logger {
    /// Sets up logging using the `tracing` crate with a daily rolling file appender.
    ///
    /// The logs are written to `./logs/secureenclave_output.log` with a maximum log level
    /// of `TRACE`. This method ensures that the global subscriber for tracing is set.
    fn setup_logging(&self) {
        // Create a file appender that rolls over daily.
        let file_appender = rolling::daily("./logs", "secureenclave_output.log");
        
        // Create a non-blocking, thread-safe writer for the log file.
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        
        // Build a subscriber with the specified maximum log level and writer.
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::TRACE)
            .with_writer(non_blocking)
            .finish();
        
        // Set the subscriber as the global default for tracing.
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}

#[derive(Debug, Clone, Default)]
pub struct SEConfig {
    pub key_algorithm: AsymmetricEncryption,
    pub sym_algorithm: BlockCiphers,
    pub hash: Hash,
    pub key_usages: Vec<KeyUsage>,
}

impl ProviderConfig for SEConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}


impl SEConfig {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: BlockCiphers,
        hash: Hash,
        key_usages: Vec<KeyUsage>,
    ) -> Box<dyn ProviderConfig> {
        Box::new(Self {
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        })
    }
}
