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

    use crate::tpm::android::wrapper::key_generation::key::jni::PublicKey;

    /// Represents a key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub(crate) struct KeyFactory<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyFactory<'env, 'borrow> {
        pub(crate) extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            algorithm: String,
        ) -> JniResult<Self> {
        }

        pub(crate) extern "java" fn generatePublic(
            &self,
            env: &'borrow JNIEnv<'env>,
            #[input_type("Ljava/security/spec/KeySpec;")] keySpec: JObject,
        ) -> JniResult<PublicKey> {
        }
    }
}
