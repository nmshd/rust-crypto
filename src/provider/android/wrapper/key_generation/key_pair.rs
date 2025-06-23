use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the `KeyPair` struct used in Android TPM key generation.
pub(crate) mod jni {
    use crate::provider::android::wrapper::key_generation::key::jni::{Key, PrivateKey, PublicKey};
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    /// Represents a Java `KeyPair` object.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub(crate) struct KeyPair<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyPair<'env, 'borrow> {
        /// Returns a string representation of the `KeyPair` object.
        pub(crate) extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}

        /// Returns the public key associated with the `KeyPair` object.
        pub(crate) extern "java" fn getPublic(
            &self,
            _env: &'borrow JNIEnv,
        ) -> JniResult<PublicKey> {
        }

        /// Returns the private key associated with the `KeyPair` object.
        pub(crate) extern "java" fn getPrivate(
            &self,
            _env: &'borrow JNIEnv,
        ) -> JniResult<PrivateKey> {
        }

        pub(crate) fn from_key(key: Key<'env, 'borrow>) -> Self {
            Self { raw: key.raw }
        }
    }
}
