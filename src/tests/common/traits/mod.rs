use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::FmtSubscriber;

use crate::{
    common::{
        factory::SecurityModule,
        traits::{log_config::LogConfig, module_provider::Provider},
    },
    tpm::core::instance::TpmType,
    SecModules,
};
use std::sync::{Arc, Mutex};

pub mod key_handle;
pub mod module_provider;

#[derive(Debug, Clone, Copy)]
struct Logger {}

impl Logger {
    fn new_boxed() -> Box<dyn LogConfig> {
        Box::new(Self {})
    }
}

impl LogConfig for Logger {
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
            TpmType::Android(_) => unimplemented!(),
        },
        #[cfg(feature = "nks")]
        SecurityModule::Nks => unimplemented!(),
        // _ => unimplemented!(),
    }
}
