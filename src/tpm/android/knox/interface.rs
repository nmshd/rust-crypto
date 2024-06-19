use robusta_jni::bridge;


#[bridge]
pub mod jni {
    #[allow(unused_imports)] //the bridge import is marked as unused, but if removed the compiler throws an error
    use robusta_jni::{
        bridge,
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Error,
            JNIEnv,
            objects::{
                AutoLocal,
                JValue
            },
            sys::jbyteArray
        },
    };

    use crate::SecurityModuleError;

    const CLASS_SIGNATURE: &str = "com/example/vulcans_limes/RustDef";

    /// Contains all methods related to Rust - Java communication and the JNI
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(com.example.vulcans_1limes)]  //the 1 after the "_" is an escape character for the "_"
    pub struct RustDef<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }


    /// This Implementation provides the method declarations that are the interface for the JNI.
    /// The first part contains Java-methods that can be called from Rust.
    /// The second part contains some utility methods.
    ///
    /// All method signatures have to correspond to their counterparts in RustDef.java, with the
    /// same method name and corresponding parameters according to this table:
    /// | **Rust**                                           | **Java**                          |
    /// |----------------------------------------------------|-----------------------------------|
    /// | i32                                                | int                               |
    /// | bool                                               | boolean                           |
    /// | char                                               | char                              |
    /// | i8                                                 | byte                              |
    /// | f32                                                | float                             |
    /// | f64                                                | double                            |
    /// | i64                                                | long                              |
    /// | i16                                                | short                             |
    /// | String                                             | String                            |
    /// | Vec\<T\>                                           | ArrayList\<T\>                    |
    /// | Box\<[u8]\>                                        | byte[]                            |
    /// | [jni::JObject<'env>](jni::objects::JObject)        | *(any Java object as input type)* |
    /// | [jni::jobject](jni::sys::jobject)                  | *(any Java object as output)*     |
    /// |----------------------------------------------------------------------------------------|
    #[allow(non_snake_case)]
    impl<'env: 'borrow, 'borrow> RustDef<'env, 'borrow> {
        //------------------------------------------------------------------------------------------
        // Java methods that can be called from rust

        ///Proof of concept method - shows call from Rust to a java method
        /// in order to find the signatures of the class and method, use
        /// `javap -s -p file/path/to/compiled/java/class`
        ///
        ///  DO NOT USE THIS METHOD
        #[allow(dead_code)]
        fn callback(environment: &JNIEnv) -> () {
            //This calls a method in Java in the Class RustDef, with the method name "callback"
            //and no arguments
            environment.call_static_method(
                CLASS_SIGNATURE, //Class signature
                "callback", //method name signature
                "()V", //parameter types of the method
                &[], //parameters to be passed to the method
            ).expect("Java func call failed");
        }

        /// Creates a new cryptographic key identified by `key_id`.
        ///
        /// This method generates a new cryptographic key within the TPM.
        /// The key is made persistent and associated with the provided `key_id`.
        ///
        /// # Arguments
        /// `key_id` - String that uniquely identifies the key so that it can be retrieved later
        ///
        /// `key_gen_info` - A string that contains all relevant parameters for the key. Expected format depends on the algorithm:
        ///
        ///  RSA: "KEY_ALGORITHM;KEY_SIZE;HASH;PADDING",
        ///
        ///  EC: "KEY_ALGORITHM;CURVE;HASH"
        ///
        ///  AES + DES: KEY_ALGORITHM;KEY_SIZE;BLOCK_MODE;PADDING"
        pub fn create_key(environment: &JNIEnv, key_id: String, key_gen_info: String) -> Result<(), SecurityModuleError> {
            RustDef::initialize_module(environment)?;
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "create_key",
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[JValue::from(environment.new_string(key_id).unwrap()),
                  JValue::from(environment.new_string(key_gen_info).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(_) => Ok(()),
                Err(Error::WrongJValueType(_, _)) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to create key: Wrong Arguments passed"))),
                Err(Error::JavaException) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to create key: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to call Java methods"))),
            };
        }

        /// Loads an existing cryptographic key identified by `key_id`.
        /// This key can then be used for cryptographic operations such as encryption or signing.
        ///
        /// # Arguments
        /// `key_id` - String that uniquely identifies the key so that it can be retrieved later
        pub fn load_key(environment: &JNIEnv, key_id: String) -> Result<(), SecurityModuleError> {
            RustDef::initialize_module(environment)?;
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "load_key",
                "(Ljava/lang/String;)V",
                &[JValue::from(environment.new_string(key_id).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(_) => Ok(()),
                Err(Error::WrongJValueType(_, _)) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to load key: Wrong Arguments passed"))),
                Err(Error::JavaException) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to load key: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to call Java methods"))),
            };
        }


        /// Initializes the TPM module.
        ///
        /// This method initializes the TPM context and prepares it for use. It should be called
        /// before performing any other operations with the TPM.
        ///
        /// # Returns
        ///
        /// A `Result` that, on success, contains `()`,
        /// indicating that the module was initialized successfully.
        /// On failure, it returns an Error
        pub fn initialize_module(environment: &JNIEnv)
                                 -> Result<(), SecurityModuleError> {
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "initialize_module",
                "()V",
                &[],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(_) => Ok(()),
                Err(Error::JavaException) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to initialise Module: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::InitializationError(
                    String::from("Failed to call Java methods"))),
            };
        }

        /// Signs the given data using the cryptographic key managed by the TPM provider.
        ///
        /// # Arguments
        ///
        /// * `data` - A byte slice representing the data to be signed.
        ///
        /// # Returns
        ///
        /// A `Result` containing the signature as a `Vec<u8>` on success,
        /// or an `Error` on failure.
        pub fn sign_data(environment: &JNIEnv, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "sign_data",
                "([B)[B",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(value) => {
                    let vector = Self::convert_to_Vec_u8(environment, value);
                    match vector {
                        Ok(v) => Ok(v),
                        Err(_) => Err(SecurityModuleError::SigningError(
                            String::from("Failed to convert return type to rust-compatible format"))),
                    }
                },
                Err(Error::WrongJValueType(_, _)) => Err(SecurityModuleError::SigningError(
                    String::from("Failed to sign data: Wrong Arguments passed"))),
                Err(Error::JavaException) => Err(SecurityModuleError::SigningError(
                    String::from("Failed to sign data: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::SigningError(
                    String::from("Failed to call Java methods"))),
            };
        }

        /// Verifies the signature of the given data using the key managed by the TPM
        ///
        /// # Arguments
        ///
        /// * `data` - A byte slice representing the data whose signature is to be verified
        /// * `signature` - A byte slice representing the signature to be verified.
        ///
        /// # Returns
        ///
        /// A `Result` containing a `bool` signifying whether the signature is valid,
        /// or an `Error` on failure to determine the validity.
        pub fn verify_signature(environment: &JNIEnv, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "verify_signature",
                "([B[B)Z",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap()),
                    JValue::from(environment.byte_array_from_slice(signature).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(res) => match res.z() {
                    Ok(value) => Ok(value),
                    Err(_) => Err(SecurityModuleError::SignatureVerificationError(
                        String::from("Failed to convert return type to rust-compatible format"))),
                },
                Err(Error::WrongJValueType(_, _)) => Err(SecurityModuleError::SignatureVerificationError(
                    String::from("Failed to verify signature: Wrong Arguments passed"))),
                Err(Error::JavaException) => Err(SecurityModuleError::SignatureVerificationError(
                    String::from("Failed to verify signature: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::SignatureVerificationError(
                    String::from("Failed to call Java methods"))),
            };
        }

        /// Encrypts the given data using the key managed by the TPM
        ///
        /// # Arguments
        ///
        /// * `data` - A byte slice representing the data to be encrypted.
        ///
        /// # Returns
        ///
        /// A `Result` containing the encrypted data as a `Vec<u8>` on success,
        /// or an `Error` on failure.
        pub fn encrypt_data(environment: &JNIEnv, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "encrypt_data",
                "([B)[B",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(value) => {
                    let vector = Self::convert_to_Vec_u8(environment, value);
                    match vector {
                        Ok(v) => Ok(v),
                        Err(_) => Err(SecurityModuleError::EncryptionError(
                            String::from("Failed to convert return type to rust-compatible format"))),
                    }
                },
                Err(Error::WrongJValueType(_, _)) => Err(SecurityModuleError::EncryptionError(
                    String::from("Failed to encrypt data: Wrong Arguments passed"))),
                Err(Error::JavaException) => Err(SecurityModuleError::EncryptionError(
                    String::from("Failed to encrypt data: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::EncryptionError(
                    String::from("Failed to call Java methods"))),
            };
        }


        /// Decrypts the given data using the key managed by the TPM
        ///
        /// # Arguments
        ///
        /// * `data` - A byte slice representing the data to be Decrypted.
        ///
        /// # Returns
        ///
        /// A `Result` containing the Decrypted data as a `Vec<u8>` on success,
        /// or an `Error` on failure.
        pub fn decrypt_data(environment: &JNIEnv, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
            let result = environment.call_static_method(
                CLASS_SIGNATURE,
                "decrypt_data",
                "([B)[B",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(value) => {
                    let vector = Self::convert_to_Vec_u8(environment, value);
                    match vector {
                        Ok(v) => Ok(v),
                        Err(_) => Err(SecurityModuleError::DecryptionError(
                            String::from("Failed to convert return type to rust-compatible format"))),
                    }
                },
                Err(Error::WrongJValueType(_, _)) => Err(SecurityModuleError::DecryptionError(
                    String::from("Failed to decrypt data: Wrong Arguments passed"))),
                Err(Error::JavaException) => Err(SecurityModuleError::DecryptionError(
                    String::from("Failed to decrypt data: Some exception occurred in Java. Check console for details"))),
                Err(_) => Err(SecurityModuleError::DecryptionError(
                    String::from("Failed to call Java methods"))),
            };
        }

        //------------------------------------------------------------------------------------------
        // Utility Functions that are only used by other Rust functions.
        // These functions have no relation to RustDef.java

        /// Converts a `JValue` representing a Java byte array (`jbyteArray`) to a Rust `Vec<u8>`.
        ///
        /// # Parameters
        /// - `environment`: A reference to the JNI environment. This is required for JNI operations.
        /// - `result`: The `JValue` that is expected to be a `jbyteArray`.
        ///
        /// # Returns
        /// - `Ok(Vec<u8>)` if the conversion is successful.
        /// - `Err(String)` if there is an error during the conversion process, with a description of the error.
        ///
        /// # Errors
        /// This method can fail in the following cases:
        /// - If there is a pending Java exception. In this case, an appropriate error message is returned.
        /// - If the `JValue` cannot be converted to a `Vec<u8>`.
        /// # Safety
        /// Ensure that the `JValue` passed is indeed a `jbyteArray` to avoid undefined behavior or unexpected errors.
        fn convert_to_Vec_u8(environment: &JNIEnv, result: JValue) -> Result<Vec<u8>, String> {
            Self::check_java_exceptions(environment)?;
            let jobj = result
                .l()
                .map_err(|_| String::from("Type conversion from JValue to JObject failed"))?
                .into_inner() as jbyteArray;

            let output_vec = environment
                .convert_byte_array(jobj)
                .map_err(|_| String::from("Conversion from jbyteArray to Vec<u8> failed"))?;
            Self::check_java_exceptions(environment)?;
            Ok(output_vec)
        }

        /// Checks for any pending Java exceptions in the provided Java environment (`JNIEnv`).
        /// If one is detected, it is printed to console and cleared so the program doesn't crash.
        /// # Arguments
        /// * `environment` - A reference to the Java environment (`JNIEnv`)
        /// # Returns
        /// * `Result<(), String>` - A Result type representing either success (if no exceptions
        ///                            are found) or an error (if exceptions are found).
        /// # Errors
        /// This method may return an error of type `JniError` if:
        /// * Any pending Java exceptions are found in the provided Java environment.
        pub fn check_java_exceptions(environment: &JNIEnv) -> Result<(), String> {
            if environment.exception_check().unwrap_or(true) {
                let _ = environment.exception_describe();
                let _ = environment.exception_clear();
                return Err(String::from("A Java exception occurred, check console for details"));
            } else {
                Ok(())
            }
        }
    }
}