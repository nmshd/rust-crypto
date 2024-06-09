use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::FmtSubscriber;
use crate::common::traits::log_config::LogConfig;


#[derive(Debug, Clone, Copy)]
pub struct Logger {}

impl LogConfig for Logger{
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

impl Logger {
    pub fn new_boxed() -> Box<dyn LogConfig> {
        Box::new(Self {})
    }
}

