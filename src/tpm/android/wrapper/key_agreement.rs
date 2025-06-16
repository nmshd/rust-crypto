use robusta_jni::bridge;

#[bridge]
pub(crate) mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    use crate::tpm::android::wrapper::key_generation::key::jni::Key;

    /// Represents a key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto)]
    pub(crate) struct KeyAgreement<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyAgreement<'env, 'borrow> {
        pub(crate) extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            algorithm: String,
            provider: String,
        ) -> JniResult<Self> {
        }

        pub(crate) extern "java" fn doPhase(
            &self,
            env: &'borrow JNIEnv<'env>,
            key: Key,
            lastPhase: bool,
        ) -> JniResult<Key> {
        }

        pub(crate) extern "java" fn generateSecret(&self, _env: &JNIEnv) -> JniResult<Vec<u8>> {}

        pub(crate) extern "java" fn init(&self, _env: &JNIEnv, key: Key) -> JniResult<()> {}
    }
}
