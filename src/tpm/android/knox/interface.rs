use robusta_jni::bridge;

#[bridge]
pub mod jni {
    #[allow(unused_imports)]
    use robusta_jni::bridge;
    use robusta_jni::convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue};
    use robusta_jni::jni::errors::Error;
    use robusta_jni::jni::JNIEnv;
    use robusta_jni::jni::objects::{AutoLocal, JValue};
    use robusta_jni::jni::sys::jbyteArray;
    use crate::SecurityModuleError;

    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(com.example.vulcans_1limes)]
    pub struct RustDef<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    /// This Implementation provides the method declarations that are the interface for the JNI.
    /// The first part are Rust-methods that can be called from other Java-classes,
    /// while the second part contains Java-methods that can be called from Rust.
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
        // Rust methods that can be called from Java

        ///Proof of concept - shows type conversion
        ///     DO NOT USE
        pub extern "jni" fn special(mut input1: Vec<i32>, input2: i32) -> Vec<String> {
            input1.push(input2);
            input1.push(42);
            input1.iter().map(ToString::to_string).collect()
        }

        ///Proof of concept method - shows callback from Rust to a java method
        ///     ONLY USE FOR TESTING
        pub extern "jni" fn callRust(environment: &JNIEnv) -> String {

            //example usage of a java method call from rust
            Self::create_key(environment, String::from("moin")).unwrap();
            String::from("Success")
        }

        ///Demo method used to call functions in Rust from the Java app while testing
        pub extern "jni" fn demoCreate(environment: &JNIEnv, key_id: String) -> () {
            Self::create_key(environment, key_id).unwrap();
        }

        ///Demo method used to call functions in Rust from the Java app while testing
        pub extern "jni" fn demoInit(environment: &JNIEnv,
                                     key_algorithm: String,
                                     sym_algorithm: String,
                                     hash: String,
                                     key_usages: String)
                                     -> () {
            let _ = Self::initialize_module(environment, key_algorithm, sym_algorithm, hash, key_usages);
        }

        ///Demo method used to call functions in Rust from the Java app while testing
        pub extern "jni" fn demoEncrypt(environment: &JNIEnv, data: Box<[u8]>) -> Box<[u8]> {
            let result = Self::encrypt_data(environment, data.as_ref())
                .expect("Sign_data failed");
            result.into_boxed_slice()
        }

        ///Demo method used to call functions in Rust from the Java app while testing
        pub extern "jni" fn demoDecrypt(environment: &JNIEnv, data: Box<[u8]>) -> Box<[u8]> {
            let result = Self::decrypt_data(environment, data.as_ref());
            return match result {
                Ok(res) => { res.into_boxed_slice() }
                Err(_) => { Vec::new().into_boxed_slice() }
            };
        }

        ///Demo method used to call functions in Rust from the Java app while testing
        pub extern "jni" fn demoSign(environment: &JNIEnv, data: Box<[u8]>) -> Box<[u8]> {
            let result = Self::sign_data(environment, data.as_ref())
                .expect("Sign_data failed");
            result.into_boxed_slice()
        }

        ///Demo method used to call functions in Rust from the Java app while testing
        pub extern "jni" fn demoVerify(environment: &JNIEnv, data: Box<[u8]>) -> bool {
            let result = Self::verify_signature(environment, data.as_ref(), data.as_ref());
            return match result {
                Ok(value) => { value }
                Err(_) => { false }
            };
        }


        //------------------------------------------------------------------------------------------
        // Java methods that can be called from rust

        ///Proof of concept method - shows callback from Rust to a java method
        ///     DO NOT USE
        pub fn callback(environment: &JNIEnv) -> () {
            //This calls a method in Java in the Class RustDef, with the method name "callback"
            //and no arguments
            environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "callback",
                "()V",
                &[],
            ).expect("Java func call failed");
        }

        /// Creates a new cryptographic key identified by `key_id`.
        ///
        /// This method generates a new cryptographic key within the TPM.
        /// The key is made persistent and associated with the provided `key_id`.
        ///
        /// # Arguments
        /// `key_id` - String that uniquely identifies the key so that it can be retrieved later
        pub fn create_key(environment: &JNIEnv, key_id: String) -> Result<(), SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "create_key",
                "(Ljava/lang/String;)V",
                &[JValue::from(environment.new_string(key_id).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(..) => Ok(()),
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to create key: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to create key: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
            };
        }

        /// Loads an existing cryptographic key identified by `key_id`.
        ///
        /// This method generates a new cryptographic key within the TPM.
        ///  The loaded key is associated with the provided `key_id`.
        ///
        /// # Arguments
        /// `key_id` - String that uniquely identifies the key so that it can be retrieved later
        pub fn load_key(environment: &JNIEnv, key_id: String) -> Result<(), SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "create_key",
                "(Ljava/lang/String;)V",
                &[JValue::from(environment.new_string(key_id).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(..) => Ok(()),
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to load key: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to load key: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
            };
        }


        /// Initializes the TPM module and returns a handle for further operations.
        ///
        /// This method initializes the TPM context and prepares it for use. It should be called
        /// before performing any other operations with the TPM.
        ///
        /// # Arguments
        ///
        /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
        /// * `key_algorithm` - The asymmetric encryption algorithm used for the key.
        /// * `sym_algorithm` - An optional symmetric encryption algorithm used with the key.
        /// * `hash` - An optional hash algorithm used with the key.
        /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
        ///
        /// # Returns
        ///
        /// A `Result` that, on success, contains `()`,
        /// indicating that the module was initialized successfully.
        /// On failure, it returns an Error
        pub fn initialize_module(environment: &JNIEnv,
                                 key_algorithm: String,
                                 sym_algorithm: String,
                                 hash: String,
                                 key_usages: String)
                                 -> Result<(), SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "initialize_module",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[JValue::from(environment.new_string(key_algorithm).unwrap()),
                    JValue::from(environment.new_string(sym_algorithm).unwrap()),
                    JValue::from(environment.new_string(hash).unwrap()),
                    JValue::from(environment.new_string(key_usages).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(..) => Ok(()),
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to initialise Module: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to initialise Module: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::InitializationError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
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
        fn sign_data(environment: &JNIEnv, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "sign_data",
                "([B)[B",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(value) => {
                    let vector = Self::convert_to_Vec_u8(environment, value);
                    match vector {
                        Ok(v) => { Ok(v) }
                        Err(_) => {Err(SecurityModuleError::SigningError(
                            String::from("Failed to convert return type to rust-compatible format")
                        ))}
                    }
                },
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::SigningError(
                                String::from("Failed to sign data: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::SigningError(
                                String::from("Failed to sign data: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::SigningError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
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
        fn verify_signature(environment: &JNIEnv, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "verify_signature",
                "([B[B)Z",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap()),
                    JValue::from(environment.byte_array_from_slice(signature).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(res) => {
                    match res.z() {
                        Ok(value) => { Ok(value) }
                        Err(_) => { Err(SecurityModuleError::SignatureVerificationError(
                            String::from("Failed to convert return type to rust-compatible format")
                        )) }
                    }
                }
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::SignatureVerificationError(
                                String::from("Failed to verify signature: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::SignatureVerificationError(
                                String::from("Failed to verify signature: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::SignatureVerificationError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
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
        fn encrypt_data(environment: &JNIEnv, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "encrypt_data",
                "([B)[B",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(value) => {
                    let vector = Self::convert_to_Vec_u8(environment, value);
                    match vector {
                        Ok(v) => { Ok(v) }
                        Err(_) => {Err(SecurityModuleError::EncryptionError(
                            String::from("Failed to convert return type to rust-compatible format")
                        ))}
                    }
                },
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::EncryptionError(
                                String::from("Failed to encrypt data: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::EncryptionError(
                                String::from("Failed to encrypt data: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::EncryptionError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
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
        fn decrypt_data(environment: &JNIEnv, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
            let result = environment.call_static_method(
                "com/example/vulcans_limes/RustDef",
                "decrypt_data",
                "([B)[B",
                &[JValue::from(environment.byte_array_from_slice(data).unwrap())],
            );
            let _ = Self::check_java_exceptions(&environment);
            return match result {
                Ok(value) => {
                    let vector = Self::convert_to_Vec_u8(environment, value);
                    match vector {
                        Ok(v) => { Ok(v) }
                        Err(_) => {Err(SecurityModuleError::DecryptionError(
                            String::from("Failed to convert return type to rust-compatible format")
                        ))}
                    }
                },
                Err(e) => {
                    match e {
                        Error::WrongJValueType(_, _) => {
                            Err(SecurityModuleError::DecryptionError(
                                String::from("Failed to decrypt data: Wrong Arguments passed")
                            ))
                        }
                        Error::JavaException => {
                            Err(SecurityModuleError::DecryptionError(
                                String::from("Failed to decrypt data: Some exception occurred in Java.
                                             Check console for details")
                            ))
                        }
                        _ => {
                            Err(SecurityModuleError::DecryptionError(
                                String::from("Failed to call Java methods")
                            ))
                        }
                    }
                }
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
            let output_array = result.l();
            let jobj;
            match output_array {
                Ok(o) => { jobj = o; }
                Err(_) => { return Err(String::from("Type conversion from JValue to JObject failed")); }
            }
            let jobj = jobj.into_inner() as jbyteArray;
            let output_vec = environment.convert_byte_array(jobj);
            Self::check_java_exceptions(environment)?;
            match output_vec {
                Ok(v) => { Ok(v) }
                Err(_) => { Err(String::from("Conversion from jbyteArray to Vec<u8> failed")) }
            }
        }

        /// Checks for any pending Java exceptions in the provided Java environment (`JNIEnv`).
        /// If one is detected, it is printed to console and cleared so the program doesn't crash.
        /// # Arguments
        /// * `environment` - A reference to the Java environment (`JNIEnv`)
        /// # Returns
        /// * `Result<(), JniError>` - A Result type representing either success (if no exceptions
        ///                            are found) or an error of type `JniError`
        ///                            (if exceptions are found).
        /// # Errors
        /// This method may return an error of type `JniError` if:
        /// * Any pending Java exceptions are found in the provided Java environment.
        /// # Panics
        /// This method does not panic under normal circumstances.
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