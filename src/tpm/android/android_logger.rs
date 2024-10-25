use tracing_subscriber::{layer::SubscriberExt, Registry};

pub(crate) fn setup_logging() {
    let subscriber = Registry::default().with(tracing_android::layer("RUST").unwrap());
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}
