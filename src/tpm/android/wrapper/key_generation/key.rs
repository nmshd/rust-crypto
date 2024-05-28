use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for key generation in Android.
pub mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    /// Represents a key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub struct Key<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto)]
    pub struct SecretKey<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    /// Represents a public key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub struct PublicKey<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> PublicKey<'env, 'borrow> {
        /// Converts the public key to its string representation.
        pub extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}

        /// Retrieves the algorithm used by the public key.
        pub extern "java" fn getAlgorithm(&self, _env: &JNIEnv) -> JniResult<String> {}
    }

    /// Represents a private key in Java's `java.security` package.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub struct PrivateKey<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> PrivateKey<'env, 'borrow> {
        /// Converts the private key to its string representation.
        pub extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}

        /// Retrieves the algorithm used by the private key.
        pub extern "java" fn getAlgorithm(&self, _env: &JNIEnv) -> JniResult<String> {}
    }
}
