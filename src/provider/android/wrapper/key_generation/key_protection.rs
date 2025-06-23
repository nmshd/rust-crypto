use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the KeyProtection struct/class.
pub(crate) mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    /// Represents the KeyGenParameterSpec struct in the android.security.keystore package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(android.security.keystore)]
    pub(crate) struct KeyProtection<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyProtection<'env, 'borrow> {
        /// Retrieves the supported digest algorithms for the key generation.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// A Result containing a vector of strings representing the supported digest algorithms,
        /// or an error if the JNI call fails.
        pub(crate) extern "java" fn getDigests(&self, env: &JNIEnv) -> JniResult<Vec<String>> {}
    }
}
