use robusta_jni::bridge;

#[bridge]
pub(crate) mod jni {
    use robusta_jni::jni::errors::Result as JniResult;
    use robusta_jni::jni::objects::JObject;
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{objects::AutoLocal, JNIEnv},
    };

    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto.spec)]
    pub(crate) struct GcmParameterSpec<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> GcmParameterSpec<'env, 'borrow> {
        /// Creates a new `GcmParameterSpec` instance.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `tag_length` - The tag length in bits.
        /// * `iv` - The IV.
        ///
        /// # Returns
        ///
        /// A `JniResult` containing the new `GcmParameterSpec` instance.
        pub(crate) fn new(
            env: &'borrow JNIEnv<'env>,
            tag_length: i32,
            iv: &[u8],
        ) -> JniResult<Self> {
            let class = env.find_class("javax/crypto/spec/GCMParameterSpec")?;
            let array = env.byte_array_from_slice(iv)?;
            let args = [Into::into(tag_length), Into::into(array)];
            let obj = env.new_object(class, "(I[B)V", &args)?;
            Ok(Self {
                raw: AutoLocal::new(env, Into::<JObject>::into(obj)),
            })
        }
    }
}
