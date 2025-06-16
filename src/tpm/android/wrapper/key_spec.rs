use robusta_jni::bridge;

#[bridge]
pub(crate) mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    /// Represents a key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security.spec)]
    pub(crate) struct X509EncodedKeySpec<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> X509EncodedKeySpec<'env, 'borrow> {
        #[constructor]
        pub(crate) extern "java" fn new(
            env: &'borrow JNIEnv<'env>,
            encodedKey: Vec<u8>,
        ) -> JniResult<Self> {
        }
    }
}
