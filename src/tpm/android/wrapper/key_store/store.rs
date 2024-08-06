use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the KeyStore functionality in Android.
pub mod jni {
    use crate::tpm::android::wrapper::key_generation::key::jni::{Key, PublicKey};
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            errors::Result as JniResult,
            objects::{AutoLocal, JObject},
            JNIEnv,
        },
    };

    /// Represents a KeyStore object in Java.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security)]
    pub struct KeyStore<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> KeyStore<'env, 'borrow> {
        /// Retrieves an instance of the KeyStore class.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `type1` - The type of the KeyStore. In java the paramenter is just 'type', but we have to use 'type1' because 'type' is a reserved keyword in Rust.
        ///
        /// # Returns
        ///
        /// Returns a keystore object of the specified type.
        pub extern "java" fn getInstance(
            env: &'borrow JNIEnv<'env>,
            type1: String,
        ) -> JniResult<Self> {
        }

        /// Retrieves a certificate from the KeyStore.
        ///
        /// Returns the certificate associated with the given alias.
        /// If the given alias name identifies an entry created by a call to setCertificateEntry,
        /// or created by a call to setEntry with a TrustedCertificateEntry, then the trusted certificate
        /// contained in that entry is returned.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `alias` - The alias name.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the Certificate instance.
        pub extern "java" fn getCertificate(
            &self,
            env: &'borrow JNIEnv<'env>,
            alias: String,
        ) -> JniResult<Certificate> {
        }

        /// Retrieves a key from the KeyStore.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `alias` - The alias of the key.
        /// * `password` - The password for the key.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the Key instance.
        pub extern "java" fn getKey(
            &self,
            env: &'borrow JNIEnv<'env>,
            alias: String,
            #[input_type("[C")] password: JObject,
        ) -> JniResult<Key> {
        }

        /// Loads the KeyStore.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `param` - An optional parameter for loading the KeyStore.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` indicating the success or failure of the operation.
        pub fn load(&self, env: &JNIEnv, param: Option<JObject>) -> JniResult<()> {
            let param_obj = param.unwrap_or(JObject::null());
            env.call_method(
                self.raw.as_obj(),
                "load",
                "(Ljava/security/KeyStore$LoadStoreParameter;)V",
                &[Into::into(param_obj)],
            )?;
            Ok(())
        }
    }

    /// Represents a Certificate object in Java.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security.cert)]
    pub struct Certificate<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> Certificate<'env, 'borrow> {
        /// Retrieves the public key from the Certificate.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        ///
        /// # Returns
        ///
        /// Returns a `JniResult` containing the PublicKey instance.
        pub extern "java" fn getPublicKey(
            &self,
            env: &'borrow JNIEnv<'env>,
        ) -> JniResult<PublicKey<'env, 'borrow>> {
        }

        /// toString Java method of the Certificate class.
        pub extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}
    }
}
