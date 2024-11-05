use core::panic;
use std::sync::Arc;

use crypto_layer::common::config::ProviderImplConfig;

use flutter_rust_bridge::DartFnFuture;
use robusta_jni::jni;
use robusta_jni::jni::sys::jint;
use robusta_jni::jni::sys::jsize;
use robusta_jni::jni::JavaVM;
use std::sync::Mutex;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

pub async fn get_android_config(
    get_fn: impl Fn(String) -> DartFnFuture<Option<Vec<u8>>> + 'static + Send + Sync,
    store_fn: impl Fn(String, Vec<u8>) -> DartFnFuture<bool> + 'static + Send + Sync,
    all_keys_fn: impl Fn() -> DartFnFuture<Vec<String>> + 'static + Send + Sync,
) -> ProviderImplConfig {
    ProviderImplConfig::new(Arc::new(Mutex::new(get_java_vm())), get_fn, store_fn, all_keys_fn)
}

pub(super) fn set_up_logging() {
    let subscriber = Registry::default().with(tracing_android::layer("RUST").unwrap());
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// This function gets the current Java VM running for the Android app.
/// Every Android app can have only 1 JVM running, so we can't just create a new one.
/// Normally it would be possible to just call the "JNI_GetCreatedJavaVMs" C function, but we can't link against it for some reason
/// so we have to load the symbol manually using the libloading crate.
pub(super) fn get_java_vm() -> JavaVM {
    // using jni_sys::JNI_GetCreatedJavaVMs crashes, bc the symbol is not loaded into the process for some reason
    // instead we use libloading to load the symbol ourselves
    pub type JniGetCreatedJavaVms = unsafe extern "system" fn(
        vmBuf: *mut *mut jni::sys::JavaVM,
        bufLen: jsize,
        nVMs: *mut jsize,
    ) -> jint;
    pub const JNI_GET_JAVA_VMS_NAME: &[u8] = b"JNI_GetCreatedJavaVMs";

    let lib = libloading::os::unix::Library::this();
    // let lib = unsafe { libloading::os::unix::Library::new("libart.so") }
    // .map_err(|e| TpmError::InitializationError(format!("could not find libart.so: {e}")))?;

    let get_created_java_vms: JniGetCreatedJavaVms =
        unsafe { *lib.get(JNI_GET_JAVA_VMS_NAME).unwrap() };

    // now that we have the function, we can call it
    let mut buffer = [std::ptr::null_mut::<jni::sys::JavaVM>(); 1];
    let buffer_ptr = buffer.as_mut_ptr();
    let mut found_vms = 0;
    let found_vm_ptr = &mut found_vms as *mut i32;
    let res = unsafe { get_created_java_vms(buffer_ptr, 1, found_vm_ptr) };

    if res != jni::sys::JNI_OK {
        panic!("JNI_GetCreatedJavaVMs failed with code {}", res);
    }

    if found_vms == 0 {
        panic!("No Java VM found");
    }

    let jvm = unsafe { JavaVM::from_raw(buffer[0]).unwrap() };
    jvm.attach_current_thread().unwrap();
    jvm
}
