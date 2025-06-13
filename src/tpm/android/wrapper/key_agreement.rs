use robusta_jni::bridge;

#[bridge]
pub(crate) mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JObject},
            JNIEnv,
        },
    };

    use crate::tpm::android::wrapper::key_generation::key::jni::{Key, SecretKey};

    /// Represents a key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto)]
    pub(crate) struct KeyAgreement<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyAgreement<'env, 'borrow> {
        pub(crate) extern "java" fn doPhase(
            &self,
            _env: &JNIEnv,
            key: Key,
            lastPhase: bool,
        ) -> JniResult<Option<Key>> {
        }

        pub(crate) extern "java" fn generateSecret(
            &self,
            _env: &JNIEnv,
            algorithm: String,
        ) -> JniResult<SecretKey> {
        }

        pub(crate) extern "java" fn init(
            &self,
            _env: &JNIEnv,
            key: Key,
            params: JObject,
        ) -> JniResult<()> {
        }
    }
}
