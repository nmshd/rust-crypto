/// A module that provides logging and security module setup functionalities.
///
/// This module contains the implementation of a `Logger` struct for setting up
/// logging and a function for setting up different types of security modules.

use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::FmtSubscriber;

#[cfg(feature = "tpm")]
use crate::tpm::core::instance::TpmType;
#[cfg(feature = "tpm")]
use crate::tpm::linux::TpmProvider;
use crate::{
    common::{
        factory::SecurityModule,
        traits::{log_config::LogConfig, module_provider::Provider},
    },
    // tpm::core::instance::TpmType,
    SecModules,
};
use std::sync::{Arc, Mutex};

pub mod key_handle;
pub mod module_provider;

#[derive(Debug, Clone, Copy)]
struct Logger {}

impl Logger {
    /// Creates a new boxed `Logger` instance.
    ///
    /// # Returns
    ///
    /// A boxed `Logger` instance implementing the `LogConfig` trait.
    fn new_boxed() -> Box<dyn LogConfig> {
        Box::new(Self {})
    }
}

impl LogConfig for Logger {
    /// Sets up the logging configuration.
    ///
    /// This method configures the logger to write logs to a daily rotating file
    /// located in the `./logs` directory with the filename `output.log`.
    /// It sets the logging level to `TRACE` and sets this configuration as the
    /// global default subscriber.
    fn setup_logging(&self) {
        let file_appender = rolling::daily("./logs", "output.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::TRACE)
            .with_writer(non_blocking)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}

/// Sets up a security module based on the given `SecurityModule` variant.
///
/// This function takes a `SecurityModule` enum variant and initializes the
/// corresponding security module. The function supports TPM, HSM, and NKS security
/// modules, and uses the `Logger` for logging configuration.
///
/// # Arguments
///
/// * `module` - A `SecurityModule` enum variant representing the type of security
///   module to set up.
///
/// # Returns
///
/// An `Arc<Mutex<dyn Provider>>` representing the initialized security module.
///
/// # Panics
///
/// This function will panic if the security module initialization fails or if the
/// logging configuration cannot be set as the global default.
///
/// # Example
///
/// ```rust
/// let security_module = setup_security_module(SecurityModule::Tpm(TpmType::Linux));
/// ```
fn setup_security_module(module: SecurityModule) -> Arc<Mutex<dyn Provider>> {
    let log = Logger::new_boxed();
    match module {
        #[cfg(feature = "hsm")]
        SecurityModule::Hsm(_hsm_type) => {
            unimplemented!()
        }
        #[cfg(feature = "tpm")]
        SecurityModule::Tpm(tpm_type) => match tpm_type {
            TpmType::Linux => SecModules::get_instance(
                "test_key".to_owned(),
                SecurityModule::Tpm(TpmType::Linux),
                Some(log),
            )
            .unwrap(),
            TpmType::Windows => SecModules::get_instance(
                "test_key".to_owned(),
                SecurityModule::Tpm(TpmType::Windows),
                Some(log),
            )
            .unwrap(),
            TpmType::None => unimplemented!(),
            _ => unimplemented!(),
        },
        #[cfg(feature = "nks")]
        SecurityModule::Nks => SecModules::get_instance(
            "test_key".to_owned(),
            SecurityModule::Nks,
            Some(log),
        )
            .unwrap(),
        _ => unimplemented!(), // Add this line to handle all other cases
    }
}
