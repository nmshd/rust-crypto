#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // Default utilities - feel free to customize
    flutter_rust_bridge::setup_default_user_utils();
    set_up_logging();
}

use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::Registry;

pub(super) fn set_up_logging() {
    #[cfg(target_os = "android")]
    let subscriber = Registry::default()
        .with(tracing_android::layer("RUST").expect("could not create android logger"));
    #[cfg(not(target_os = "android"))]
    let subscriber = Registry::default();
    let _ = tracing::subscriber::set_global_default(subscriber);
}
