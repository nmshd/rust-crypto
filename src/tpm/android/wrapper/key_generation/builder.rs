use crate::tpm::android::wrapper::key_generation::key_gen_parameter_spec::jni::KeyGenParameterSpec;

use robusta_jni::jni::errors::Result as JniResult;
use robusta_jni::jni::objects::{AutoLocal, JObject, JValue};
use robusta_jni::jni::sys::jsize;
use robusta_jni::jni::JNIEnv;

/// Builder for creating `KeyGenParameterSpec` objects.
/// This class is an inner class of `KeyGenParameterSpec`. For that reason, it could not
/// be implemented using the help of `robusta_jni`. `robusta_jni` does not support inner classes.
pub struct Builder<'env: 'borrow, 'borrow> {
    raw: AutoLocal<'env, 'borrow>,
}

impl<'env: 'borrow, 'borrow> Builder<'env, 'borrow> {
    /// Creates a new `Builder` instance.
    ///
    /// # Arguments
    ///
    /// * `env` - The JNI environment.
    /// * `keystore_alias` - The alias for the keystore.
    /// * `purposes` - The purposes for which the key can be used.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the new `Builder` instance.
    pub fn new(
        env: &'borrow JNIEnv<'env>,
        keystore_alias: String,
        purposes: i32,
    ) -> JniResult<Self> {
        let class = env.find_class("android/security/keystore/KeyGenParameterSpec$Builder")?;
        let jstring_keystore_alias = env.new_string(keystore_alias)?;
        let args = [Into::into(jstring_keystore_alias), JValue::from(purposes)];
        let obj = env.new_object(class, "(Ljava/lang/String;I)V", &args)?;
        Ok(Self {
            raw: AutoLocal::new(env, Into::<JObject>::into(obj)),
        })
    }

    /// Sets the digests for the key.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `digests` - The digests to set.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    pub fn set_digests(
        mut self,
        env: &'borrow JNIEnv<'env>,
        digests: Vec<String>,
    ) -> JniResult<Self> {
        let string_class = env.find_class("java/lang/String")?;
        let digest_array =
            env.new_object_array(digests.len() as jsize, string_class, JObject::null())?;
        for (i, digest) in digests.iter().enumerate() {
            let jstring_digest = env.new_string(digest)?;
            env.set_object_array_element(digest_array, i as jsize, jstring_digest)?;
        }

        let result = env.call_method(
            self.raw.as_obj(),
            "setDigests",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[digest_array.into()],
        )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Sets the encryption paddings for the key.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `paddings` - The encryption paddings to set.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    pub fn set_encryption_paddings(
        mut self,
        env: &'borrow JNIEnv<'env>,
        paddings: Vec<String>,
    ) -> JniResult<Self> {
        let string_class = env.find_class("java/lang/String")?;
        let padding_array =
            env.new_object_array(paddings.len() as jsize, string_class, JObject::null())?;
        for (i, padding) in paddings.iter().enumerate() {
            let jstring_padding = env.new_string(padding)?;
            env.set_object_array_element(padding_array, i as jsize, jstring_padding)?;
        }

        let result = env.call_method(
            self.raw.as_obj(),
            "setEncryptionPaddings",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[padding_array.into()],
        )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Sets the signature paddings for the key.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `paddings` - The signature paddings to set.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    pub fn set_signature_paddings(
        mut self,
        env: &'borrow JNIEnv<'env>,
        paddings: Vec<String>,
    ) -> JniResult<Self> {
        let string_class = env.find_class("java/lang/String")?;
        let padding_array =
            env.new_object_array(paddings.len() as jsize, string_class, JObject::null())?;
        for (i, padding) in paddings.iter().enumerate() {
            let jstring_padding = env.new_string(padding)?;
            env.set_object_array_element(padding_array, i as jsize, jstring_padding)?;
        }

        let result = env.call_method(
            self.raw.as_obj(),
            "setSignaturePaddings",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[padding_array.into()],
        )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Sets the block modes for the key.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `block_modes` - The block modes to set.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    pub fn set_block_modes(
        mut self,
        env: &'borrow JNIEnv<'env>,
        block_modes: Vec<String>,
    ) -> JniResult<Self> {
        let string_class = env.find_class("java/lang/String")?;
        let block_mode_array =
            env.new_object_array(block_modes.len() as jsize, string_class, JObject::null())?;
        for (i, block_mode) in block_modes.iter().enumerate() {
            let jstring_block_mode = env.new_string(block_mode)?;
            env.set_object_array_element(block_mode_array, i as jsize, jstring_block_mode)?;
        }

        let result = env.call_method(
            self.raw.as_obj(),
            "setBlockModes",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[block_mode_array.into()],
        )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Sets the key size for the key.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `key_size` - The key size to set.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    pub fn set_key_size(mut self, env: &'borrow JNIEnv<'env>, key_size: i32) -> JniResult<Self> {
        let result = env.call_method(
            self.raw.as_obj(),
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(key_size)],
        )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Sets the algorithm parameter specification for the key.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `spec` - The algorithm parameter specification to set.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    #[allow(dead_code)]
    pub fn set_algorithm_parameter_spec(
        mut self,
        env: &'borrow JNIEnv<'env>,
        spec: JObject,
    ) -> JniResult<Self> {
        let result = env.call_method(
        self.raw.as_obj(),
        "setAlgorithmParameterSpec",
        "(Ljavax/crypto/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(spec)],
    )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Sets whether the key is backed by a strongbox.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    /// * `is_strongbox_backed` - Whether the key is strongbox backed.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the updated `Builder` instance.
    pub fn set_is_strongbox_backed(
        mut self,
        env: &'borrow JNIEnv<'env>,
        is_strongbox_backed: bool,
    ) -> JniResult<Self> {
        let result = env.call_method(
            self.raw.as_obj(),
            "setIsStrongBoxBacked",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(is_strongbox_backed.into())],
        )?;
        self.raw = AutoLocal::new(env, result.l()?);
        Ok(self)
    }

    /// Builds the `KeyGenParameterSpec` object.
    ///
    /// # Arguments
    ///
    /// * `self` - The `Builder` instance.
    /// * `env` - The JNI environment.
    ///
    /// # Returns
    ///
    /// A `JniResult` containing the built `KeyGenParameterSpec` object.
    pub fn build(
        self,
        env: &'borrow JNIEnv<'env>,
    ) -> JniResult<KeyGenParameterSpec<'env, 'borrow>> {
        let result = env.call_method(
            self.raw.as_obj(),
            "build",
            "()Landroid/security/keystore/KeyGenParameterSpec;",
            &[],
        )?;
        Ok(KeyGenParameterSpec {
            raw: AutoLocal::new(env, result.l()?),
        })
    }
}
