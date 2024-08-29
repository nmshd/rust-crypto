use async_trait::async_trait;
use tracing_subscriber::{layer::SubscriberExt, Registry};

use crate::common::traits::log_config::LogConfig;

#[derive(Debug)]
pub struct DefaultAndroidLogger;

#[async_trait]
impl LogConfig for DefaultAndroidLogger {
    async fn setup_logging(&self) {
        let subscriber = Registry::default().with(tracing_android::layer("RUST").unwrap());
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}
