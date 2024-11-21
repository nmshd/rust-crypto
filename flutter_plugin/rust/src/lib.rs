mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */
pub mod api;

pub use crypto_layer;

// #[cfg(target_os = "android")]
// #[no_mangle]
// pub extern "C" fn JNI_OnLoad(vm: jni::JavaVM, res: *mut std::os::raw::c_void) -> jni::sys::jint {
//     let env = vm.attach_current_thread().expect("Failed to attach to current thread");
//     let class = env.find_class("com/example/cal_flutter_app/MyPlugin").expect("Failed to find class");

//     jni::JNIVersion::V6.into()
// }

#[cfg(target_os = "android")]
use {
    jni::{objects::JClass, objects::JObject, JNIEnv},
    std::ffi::c_void,
};

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_example_cal_1flutter_1app_MyPlugin_init_1android(
    env: JNIEnv,
    _class: JClass,
    ctx: JObject,
) {
    use std::ffi::c_void;

    let global_ctx = env.new_global_ref(ctx).expect("Failed to create global ref");

    env.get_java_vm().and_then( |vm| {
        let vm = vm.get_java_vm_pointer().cast::<c_void>();
        unsafe {
            ndk_context::initialize_android_context(vm, global_ctx.as_obj().into_inner().cast::<c_void>());
        }
        std::mem::forget(global_ctx);
        Ok(())
    });
    
}
