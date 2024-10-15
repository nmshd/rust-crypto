use core::panic;
use std::collections::HashSet;
use std::sync::Arc;

use async_std::sync::Mutex;
use crypto_layer::common::config::KeyPairSpec;
use crypto_layer::common::crypto::algorithms::hashes::Sha2Bits;
use crypto_layer::common::factory::create_provider;
use crypto_layer::common::KeyPairHandle;
use crypto_layer::common::Provider;
use crypto_layer::common::config::ProviderConfig;
use crypto_layer::common::config::ProviderImplConfig;
use crypto_layer::common::crypto::algorithms::encryption::{Cipher, AsymmetricKeySpec, SymmetricMode};
use crypto_layer::common::crypto::algorithms::KeyBits;
use crypto_layer::common::crypto::algorithms::hashes::CryptoHash;
use robusta_jni::jni;
use robusta_jni::jni::sys::jint;
use robusta_jni::jni::sys::jsize;
use robusta_jni::jni::JavaVM;

pub async fn get_provider() -> Provider {

    let config = ProviderConfig {
        min_security_level: crypto_layer::common::config::SecurityLevel::Hardware,
        max_security_level: crypto_layer::common::config::SecurityLevel::Hardware,
        supported_ciphers: HashSet::new(),
        supported_hashes: HashSet::new(),
        supported_asym_spec: HashSet::new(),
    };

    let impl_config = ProviderImplConfig::Android { vm: Arc::new(Mutex::new(get_java_vm())) };

    create_provider(config, vec![impl_config]).await.unwrap()
}

pub async fn create_key_pair(provider: &mut Provider) -> Result<KeyPairHandle, crypto_layer::common::error::SecurityModuleError> {
    let key_pair_spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Rsa(KeyBits::Bits2048),
        cipher: Some(Cipher::Aes(SymmetricMode::Cbc, KeyBits::Bits128)),
        signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
    };

    provider.create_key_pair(key_pair_spec).await
}

pub async fn sign(key_pair_handle: &KeyPairHandle, data: Vec<u8>) -> Result<Vec<u8>, crypto_layer::common::error::SecurityModuleError> {
    key_pair_handle.sign_data(data).await
}

pub async fn verify(key_pair_handle: &KeyPairHandle, data: Vec<u8>, signature: Vec<u8>) -> Result<bool, crypto_layer::common::error::SecurityModuleError> {
    key_pair_handle.verify_signature(data, signature).await
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

    let get_created_java_vms: JniGetCreatedJavaVms = unsafe {
        *lib.get(JNI_GET_JAVA_VMS_NAME).unwrap()
    };

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

    let jvm = unsafe {
        JavaVM::from_raw(buffer[0]).unwrap()
    };
    jvm.attach_current_thread()
        .unwrap();
    jvm
}