use robusta_jni::bridge;

#[bridge]
pub mod jni {
    use crate::tpm::android::wrapper::key_generation::key::jni::SecretKey;
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JObject},
            JNIEnv,
        },
    };

    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto)]
    pub struct KeyGenerator<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyGenerator<'env, 'borrow> {
        pub extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            algorithm: String,
            provider: String,
        ) -> JniResult<Self> {
        }

        pub extern "java" fn init(
            &self,
            env: &JNIEnv,
            #[input_type("Ljava/security/spec/AlgorithmParameterSpec;")] params: JObject,
        ) -> JniResult<()> {
        }

        pub extern "java" fn generateKey(&self, _env: &'borrow JNIEnv) -> JniResult<SecretKey> {}
    }
}
