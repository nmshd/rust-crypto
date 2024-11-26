pub mod api;
mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

pub use crypto_layer;

#[cfg(target_os = "android")]
use {
    jni::{objects::JClass, objects::JObject, JNIEnv},
    std::ffi::c_void,
};

#[cfg(target_os = "android")]
static INITIALIZED: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_example_cal_1flutter_1app_MyPlugin_init_1android(
    env: JNIEnv,
    _class: JClass,
    ctx: JObject,
) {
    use std::ffi::c_void;
    INITIALIZED.call_once(|| {
        let global_ctx = env
            .new_global_ref(ctx)
            .expect("Failed to create global ref");

        env.get_java_vm().and_then(|vm| {
            let vm = vm.get_java_vm_pointer().cast::<c_void>();
            unsafe {
                ndk_context::initialize_android_context(
                    vm,
                    global_ctx.as_obj().into_inner().cast::<c_void>(),
                );
            }
            std::mem::forget(global_ctx);
            Ok(())
        });
    })
}
