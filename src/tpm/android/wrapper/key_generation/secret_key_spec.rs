use robusta_jni::bridge;

#[bridge]
pub(crate) mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::errors::Result as JniResult,
        jni::objects::AutoLocal,
        jni::JNIEnv,
    };

    /// Represents the `SecretKeySpec` class in Java.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto.spec)]
    pub struct SecretKeySpec<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> SecretKeySpec<'env, 'borrow> {
        /// Constructs a new `SecretKeySpec` instance.
        #[constructor]
        pub extern "java" fn new(
            env: &'borrow JNIEnv<'env>,
            key: Vec<u8>,
            algorithm: String,
        ) -> JniResult<Self> {
        }

        /// Returns the algorithm name of the `SecretKeySpec` instance.
        pub extern "java" fn getAlgorithm(&self, env: &JNIEnv<'env>) -> JniResult<String> {}

        /// Returns the Key material of the `SecretKeySpec` instance.
        pub extern "java" fn getEncoded(&self, env: &JNIEnv<'env>) -> JniResult<Vec<u8>> {}
    }
}
