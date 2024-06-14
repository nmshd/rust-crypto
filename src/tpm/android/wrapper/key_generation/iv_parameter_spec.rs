use robusta_jni::bridge;

#[bridge]
pub mod jni {
    use robusta_jni::jni::errors::Result as JniResult;
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            objects::{AutoLocal, JObject},
            JNIEnv,
        },
    };

    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto.spec)]
    pub struct IvParameterSpec<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> IvParameterSpec<'env, 'borrow> {
        /// Creates a new `IvParameterSpec` instance.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `iv` - The IV.
        ///
        /// # Returns
        ///
        /// A `JniResult` containing the new `IvParameterSpec` instance.
        pub fn new(env: &'borrow JNIEnv<'env>, iv: &[u8]) -> JniResult<Self> {
            let class = env.find_class("javax/crypto/spec/IvParameterSpec")?;
            let array = env.byte_array_from_slice(iv)?;
            let args = [Into::into(array)];
            let obj = env.new_object(class, "([B)V", &args)?;
            Ok(Self {
                raw: AutoLocal::new(env, Into::<JObject>::into(obj)),
            })
        }
    }
}
