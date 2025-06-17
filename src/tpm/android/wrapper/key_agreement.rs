use robusta_jni::bridge;

#[bridge]
pub(crate) mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JValue},
            JNIEnv,
        },
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

        pub(crate) fn doPhase(
            &self,
            env: &'borrow JNIEnv<'env>,
            key: Key,
            lastPhase: bool,
        ) -> JniResult<Key> {
            let reskey = env.call_method(
                self.raw.as_obj(),
                "doPhase",
                "(Ljava/security/Key;Z)Ljava/security/Key;",
                &[
                    JValue::Object(key.raw.as_obj()),
                    JValue::Bool(Into::into(lastPhase)),
                ],
            )?;

            Ok(Key {
                raw: AutoLocal::new(env, Into::into(reskey.l()?)),
            })
        }

        pub(crate) fn generateSecret(&self, env: &JNIEnv) -> JniResult<Vec<u8>> {
            let res = env
                .call_method(self.raw.as_obj(), "generateSecret", "()[B", &[])?
                .l()?;
            env.convert_byte_array(*res)
        }

        pub(crate) fn init(&self, env: &JNIEnv, key: Key) -> JniResult<()> {
            env.call_method(
                self.raw.as_obj(),
                "init",
                "(Ljava/security/Key;)V",
                &[JValue::Object(key.raw.as_obj())],
            )?;
            Ok(())
        }
    }
}
