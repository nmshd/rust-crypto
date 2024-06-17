use tracing_subscriber::{layer::SubscriberExt, Registry};

use crate::common::traits::log_config::LogConfig;

#[derive(Debug)]
pub struct DefaultAndroidLogger;

/// Implements the `LogConfig` trait for the default Android logger.
/// This logger uses the `tracing-android` crate to log messages to the Android logcat.
impl LogConfig for DefaultAndroidLogger {
    fn setup_logging(&self) {
        let subscriber = Registry::default().with(tracing_android::layer("RUST").unwrap());
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}
