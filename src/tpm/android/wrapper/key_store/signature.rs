use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the Signature class in the Java security package.
pub mod jni {
    use crate::tpm::android::wrapper::key_store::key_store::jni::Certificate;
    use robusta_jni::{
        convert::{IntoJavaValue, Signature as JavaSignature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JObject, JValue},
            JNIEnv,
        },
    };

    /// Represents a Signature object in Java.
    #[derive(JavaSignature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub struct Signature<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> Signature<'env, 'borrow> {
        /// Creates a new instance of the Signature class with the specified algorithm.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `algorithm` - The algorithm to use for the Signature instance.
        ///
        /// # Returns
        ///
        /// Returns a Result containing the Signature instance if successful, or an error if it fails.
        pub extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            algorithm: String,
        ) -> JniResult<Self> {
        }

        /// Signs the data using the Signature instance.
        ///
        /// Could not be implemented using `robusta_jni` because the Java method returns a byte array,
        /// and byte arrays are not supported as a return value by `robusta_jni`.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// Returns a Result containing the signed data as a Vec<u8> if successful, or an error if it fails.
        pub fn sign(&self, env: &JNIEnv) -> JniResult<Vec<u8>> {
            let result = env.call_method(self.raw.as_obj(), "sign", "()[B", &[])?;

            let byte_array = result.l()?.into_inner();
            let output = env.convert_byte_array(byte_array)?;

            Ok(output)
        }

        /// Initializes the Signature instance for signing with the specified private key.
        ///         
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `privateKey` - The private key to use for signing.
        ///
        /// # Returns
        ///
        /// Returns a Result indicating success or failure.
        pub extern "java" fn initSign(
            &self,
            env: &JNIEnv,
            #[input_type("Ljava/security/PrivateKey;")] privateKey: JObject,
        ) -> JniResult<()> {
        }

        /// Initializes the Signature instance for verification with the specified certificate.
        ///
        /// Could not be implemented using `robusta_jni` because for some reason it doesn't
        /// recognize the `Certificate` signature correctly.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `certificate` - The certificate to use for verification.
        ///
        /// # Returns
        ///
        /// Returns a Result indicating success or failure.
        pub fn initVerify(&self, env: &JNIEnv, certificate: Certificate) -> JniResult<()> {
            let certificate_obj = certificate.raw.as_obj();

            env.call_method(
                self.raw.as_obj(),
                "initVerify",
                "(Ljava/security/cert/Certificate;)V",
                &[JValue::from(certificate_obj)],
            )?;

            Ok(())
        }

        /// Verifies the signature against the specified data.
        ///
        /// # Arguments
        ///
        /// * `_env` - The JNI environment.
        /// * `signature` - The signature to verify.
        ///
        /// # Returns
        ///
        /// Returns a Result indicating whether the signature is valid or not.
        pub extern "java" fn verify(&self, _env: &JNIEnv, signature: Box<[u8]>) -> JniResult<bool> {
        }

        /// Updates the Signature instance with additional data to be signed or verified.
        ///
        /// # Arguments
        ///
        /// * `_env` - The JNI environment.
        /// * `data` - The data to update the Signature instance with.
        ///
        /// # Returns
        ///
        /// Returns a Result indicating success or failure.
        pub extern "java" fn update(&self, _env: &JNIEnv, data: Box<[u8]>) -> JniResult<()> {}

        /// toString Java method of the Signature class.
        pub extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}
    }
}
