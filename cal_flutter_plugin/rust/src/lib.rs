pub mod api;
mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

pub use crypto_layer;
#[cfg(target_os = "android")]
use crypto_layer::common::initialize_android_context;

#[cfg(target_os = "android")]
use {
    jni::{objects::JClass, objects::JObject, sys::jint, JNIEnv, JNIVersion, JavaVM},
    std::ffi::c_void,
};

#[cfg(target_os = "android")]
static INITIALIZED: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: JavaVM, res: *mut std::os::raw::c_void) -> jint {
    INITIALIZED.call_once(|| {
        let vm = vm.get_java_vm_pointer().cast::<c_void>();
        unsafe {
            initialize_android_context(vm, res);
        }
    });

    JNIVersion::V6.into()
}
