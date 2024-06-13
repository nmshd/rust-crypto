use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the Cipher class in the javax.crypto package.
pub mod jni {
    use crate::tpm::android::wrapper::key_generation::key::jni::Key;
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JObject, JValue},
            sys::jbyteArray,
            JNIEnv,
        },
    };

    /// Represents a Cipher object in Java.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(javax.crypto)]
    pub struct Cipher<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> Cipher<'env, 'borrow> {
        /// Creates a new instance of the Cipher class.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNIEnv object.
        /// * `transformation` - the name of the transformation, e.g., DES/CBC/PKCS5Padding. See the Cipher section in the Java Cryptography Architecture Standard Algorithm Name Documentation for information about standard transformation names.
        ///
        /// # Returns
        ///
        /// Returns a Cipher object that implements the specified transformation.
        pub extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            transformation: String,
        ) -> JniResult<Self> {
        }

        /// Initializes the Cipher object with the specified operation mode and key.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNIEnv object.
        /// * `opmode` - The operation mode.
        /// * `key` - The key object.
        ///
        /// # Returns
        ///
        /// Returns a JniResult indicating success or failure.
        pub extern "java" fn init(
            &self,
            env: &'borrow JNIEnv<'env>,
            opmode: i32,
            #[input_type("Ljava/security/Key;")] key: JObject,
        ) -> JniResult<()> {
        }

        pub fn init2(
            &self,
            env: &'borrow JNIEnv<'env>,
            opmode: i32,
            key: Key,
            params: JObject,
        ) -> JniResult<()> {
            env.call_method(
                self.raw.as_obj(),
                "init",
                "(ILjava/security/Key;Ljava/security/AlgorithmParameters;)V",
                &[
                    JValue::Int(opmode),
                    JValue::Object(key.raw.as_obj()),
                    JValue::Object(params),
                ],
            )?;
            Ok(())
        }

        pub fn getIV(&self, env: &JNIEnv) -> JniResult<Vec<u8>> {
            let output = env.call_method(self.raw.as_obj(), "getIV", "()[B", &[])?;

            let output_array = output.l()?.into_inner() as jbyteArray;
            let output_vec = env.convert_byte_array(output_array).unwrap();

            Ok(output_vec)
        }

        /// Performs the final operation of the Cipher, processing any remaining data.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNIEnv object.
        /// * `input` - The input data.
        ///
        /// # Returns
        ///
        /// Returns a JniResult containing the output data.
        pub fn doFinal(&self, env: &JNIEnv, input: Vec<u8>) -> JniResult<Vec<u8>> {
            let input_array = env.byte_array_from_slice(&input)?;

            let output = env.call_method(
                self.raw.as_obj(),
                "doFinal",
                "([B)[B",
                &[JValue::from(input_array)],
            )?;

            let output_array = output.l()?.into_inner() as jbyteArray;
            let output_vec = env.convert_byte_array(output_array).unwrap();

            Ok(output_vec)
        }
    }
}
