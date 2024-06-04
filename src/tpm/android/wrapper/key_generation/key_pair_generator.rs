use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the `KeyPairGenerator` class in the Android TPM wrapper.
pub mod jni {
    use crate::tpm::android::wrapper::key_generation::key_pair::jni::KeyPair;
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JObject},
            JNIEnv,
        },
    };

    /// Represents a Java `KeyPairGenerator` object.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub struct KeyPairGenerator<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyPairGenerator<'env, 'borrow> {
        /// Returns an instance of `KeyPairGenerator` for the specified algorithm and provider.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `algorithm` - The name of the algorithm.
        /// * `provider` - The name of the provider.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the `KeyPairGenerator` instance.
        pub extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            algorithm: String,
            provider: String,
        ) -> JniResult<Self> {
        }

        /// Returns a string representation of the `KeyPairGenerator` object.
        ///
        /// # Arguments
        ///
        /// * `_env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the string representation.
        pub extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}

        /// Returns the algorithm name associated with the `KeyPairGenerator` object.
        ///
        /// # Arguments
        ///
        /// * `_env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the algorithm name.
        pub extern "java" fn getAlgorithm(&self, _env: &JNIEnv) -> JniResult<String> {}

        /// Initializes the `KeyPairGenerator` object with the specified algorithm parameters.
        ///
        /// Initializes the key pair generator using the specified parameter set and the SecureRandom
        /// implementation of the highest-priority installed provider as the source of randomness.
        /// (If none of the installed providers supply an implementation of SecureRandom, a system-provided source of randomness is used.)
        ///
        /// Could not be implemented using `robusta_jni` because the params parameter is the class
        /// AlgorithmParameterSpec. AlgorithmParameterSpec is an interface and we need to pass an object
        /// of type KeyGenParameterSpec. This causes the signatures to not match, meaning the jni call fails.
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `params` - The algorithm parameter specification.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` indicating success or failure.
        pub extern "java" fn initialize(
            &self,
            env: &JNIEnv,
            #[input_type("Ljava/security/spec/AlgorithmParameterSpec;")] params: JObject,
        ) -> JniResult<()> {
        }

        /// Generates a key pair using the `KeyPairGenerator` object.
        ///
        /// If this KeyPairGenerator has not been initialized explicitly, provider-specific defaults
        /// will be used for the size and other (algorithm-specific) values of the generated keys.
        /// This will generate a new key pair every time it is called.
        ///
        /// # Arguments
        ///
        /// * `_env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the generated `KeyPair`.
        pub extern "java" fn generateKeyPair(&self, _env: &'borrow JNIEnv) -> JniResult<KeyPair> {}
    }
}
