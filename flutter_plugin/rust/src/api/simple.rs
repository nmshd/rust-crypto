#[cfg(target_os = "android")]
use super::android::set_up_logging;

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // Default utilities - feel free to customize
    flutter_rust_bridge::setup_default_user_utils();
    #[cfg(target_os = "android")]
    set_up_logging();
}
