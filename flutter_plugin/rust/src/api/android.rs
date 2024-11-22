use robusta_jni::jni::sys::{jint, jsize};
use robusta_jni::jni::{self, JavaVM};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

pub(super) fn set_up_logging() {
    let subscriber = Registry::default()
        .with(tracing_android::layer("RUST").expect("could not create android logger"));
    let _ = tracing::subscriber::set_global_default(subscriber);
}
