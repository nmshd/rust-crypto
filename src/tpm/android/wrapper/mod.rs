use robusta_jni::jni::{
    self,
    sys::{jint, jsize},
    JavaVM,
};

use crate::tpm::core::error::TpmError;

pub(crate) mod key_generation;
pub(crate) mod key_store;

/// This function gets the current Java VM running for the Android app.
/// Every Android app can have only 1 JVM running, so we can't just create a new one.
/// Normally it would be possible to just call the "JNI_GetCreatedJavaVMs" C function, but we can't link against it for some reason
/// so we have to load the symbol manually using the libloading crate.
pub(super) fn get_java_vm() -> Result<JavaVM, TpmError> {
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

    let get_created_java_vms: JniGetCreatedJavaVms = unsafe {
        *lib.get(JNI_GET_JAVA_VMS_NAME).map_err(|e| {
            TpmError::InitializationError(format!("function JNI_GET_JAVA_VMS_NAME not loaded: {e}"))
        })?
    };

    // now that we have the function, we can call it
    let mut buffer = [std::ptr::null_mut::<jni::sys::JavaVM>(); 1];
    let buffer_ptr = buffer.as_mut_ptr();
    let mut found_vms = 0;
    let found_vm_ptr = &mut found_vms as *mut i32;
    let res = unsafe { get_created_java_vms(buffer_ptr, 1, found_vm_ptr) };

    if res != jni::sys::JNI_OK {
        return Err(TpmError::InitializationError(
            "Unable to get existing JVMs".to_owned(),
        ));
    }

    if found_vms == 0 {
        return Err(TpmError::InitializationError(
            "No running JVMs found".to_owned(),
        ));
    }

    let jvm = unsafe {
        JavaVM::from_raw(buffer[0]).map_err(|e| TpmError::InitializationError(e.to_string()))?
    };
    jvm.attach_current_thread()
        .map_err(|e| TpmError::InitializationError(e.to_string()))?;
    Ok(jvm)
}
