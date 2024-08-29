mod key_handle;
mod module_provider;
#[cfg(feature = "tpm")]
use crate::tpm::core::instance::TpmType;
use crate::{
    common::{
        factory::SecurityModule,
        traits::{log_config::LogConfig, module_provider::Provider},
    },
    SecModules,
};
use async_std::sync::Mutex;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, Clone, Copy)]
struct Logger {}

impl Logger {
    fn new_boxed() -> Box<dyn LogConfig> {
        Box::new(Self {})
    }
}

#[async_trait]
impl LogConfig for Logger {
    async fn setup_logging(&self) {
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

pub async fn setup_security_module(module: SecurityModule) -> Arc<Mutex<dyn Provider>> {
    let log = Logger::new_boxed();
    match module {
        #[cfg(feature = "hsm")]
        SecurityModule::Hsm(_hsm_type) => {
            unimplemented!()
        }
        #[cfg(feature = "tpm")]
        SecurityModule::Tpm(tpm_type) => match tpm_type {
            #[cfg(feature = "linux")]
            TpmType::Linux => SecModules::get_instance(
                "test_key".to_owned(),
                SecurityModule::Tpm(TpmType::Linux),
                Some(log),
            )
            .await
            .unwrap(),
            #[cfg(feature = "win")]
            TpmType::Windows => SecModules::get_instance(
                "test_key".to_owned(),
                SecurityModule::Tpm(TpmType::Windows),
                Some(log),
            )
            .await
            .unwrap(),
            TpmType::None => unimplemented!(),
            #[cfg(feature = "android")]
            TpmType::Android(_) => todo!(),
        },
        #[cfg(feature = "nks")]
        SecurityModule::Nks => todo!(),
        #[cfg(feature = "android")]
        SecurityModule::Android => todo!(),
    }
}
