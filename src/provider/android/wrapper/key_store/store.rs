use robusta_jni::bridge;

#[bridge]
/// This module contains the JNI bindings for the KeyStore functionality in Android.
pub(crate) mod jni {
    use crate::provider::android::wrapper::key_generation::key::jni::{Key, PublicKey};
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
    pub(crate) struct KeyStore<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
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
        pub(crate) extern "java" fn getInstance(
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
        pub(crate) extern "java" fn getCertificate(
            &self,
            env: &'borrow JNIEnv<'env>,
            alias: String,
        ) -> JniResult<Certificate> {
        }

        /// Deletes the entry identified by the given alias from this keystore.
        ///
        /// # Arguments
        ///
        /// * `env` - The JNI environment.
        /// * `alias` - The alias of the entry to be deleted.
        ///  
        /// # Returns
        ///
        /// Returns a `JniResult` indicating the success or failure of the operation.
        pub(crate) extern "java" fn deleteEntry(
            &self,
            env: &'borrow JNIEnv<'env>,
            alias: String,
        ) -> JniResult<()> {
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
        pub(crate) extern "java" fn getKey(
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
        pub(crate) fn load(&self, env: &JNIEnv, param: Option<JObject>) -> JniResult<()> {
            let param_obj = param.unwrap_or(JObject::null());
            env.call_method(
                self.raw.as_obj(),
                "load",
                "(Ljava/security/KeyStore$LoadStoreParameter;)V",
                &[Into::into(param_obj)],
            )?;
            Ok(())
        }

        pub(crate) fn getEntry<'a>(&self, env: &JNIEnv<'a>, alias: String) -> JniResult<JObject<'a>>
        where
            'env: 'a,
        {
            let result = env.call_method(
                self.raw.as_obj(),
                "getEntry",
                "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                &[Into::into(env.new_string(alias)?), Into::into(JObject::null())],
            )?;
            result.l()
        }

        pub(crate) fn set_entry(
            &self,
            env: &JNIEnv,
            alias: String,
            entry: JObject,
            param: Option<JObject>,
        ) -> JniResult<()> {
            let param_obj = param.unwrap_or(JObject::null());
            env.call_method(
                self.raw.as_obj(),
                "setEntry",
                "(Ljava/lang/String;Ljava/security/KeyStore$Entry;Ljava/security/KeyStore$ProtectionParameter;)V",
                &[Into::into(env.new_string(alias)?), Into::into(entry), Into::into(param_obj)],
            )?;
            Ok(())
        }
    }

    /// Represents a Certificate object in Java.
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(java.security.cert)]
    pub(crate) struct Certificate<'env: 'borrow, 'borrow> {
        #[instance]
        pub(crate) raw: AutoLocal<'env, 'borrow>,
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
        pub(crate) extern "java" fn getPublicKey(
            &self,
            env: &'borrow JNIEnv<'env>,
        ) -> JniResult<PublicKey<'env, 'borrow>> {
        }

        /// toString Java method of the Certificate class.
        pub(crate) extern "java" fn toString(&self, _env: &JNIEnv) -> JniResult<String> {}
    }
}
