use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the KeyGenParameterSpec struct/class.
pub mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    /// Represents the KeyGenParameterSpec struct in the android.security.keystore package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(android.security.keystore)]
    pub struct KeyGenParameterSpec<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyGenParameterSpec<'env, 'borrow> {
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
        pub extern "java" fn getDigests(&self, env: &JNIEnv) -> JniResult<Vec<String>> {}

        /// Checks if the key generation is backed by a StrongBox.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// A Result containing a boolean value indicating whether the key generation is backed by a StrongBox,
        /// or an error if the JNI call fails.
        pub extern "java" fn isStrongBoxBacked(&self, env: &JNIEnv) -> JniResult<bool> {}
    }
}
