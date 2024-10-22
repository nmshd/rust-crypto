use robusta_jni::jni::objects::{JObject, JValue};
use robusta_jni::jni::{errors::Result, objects::AutoLocal, JNIEnv};

use crate::tpm::android::wrapper::key_generation::secret_key_spec::jni;

pub struct SecretKeyEntry<'env: 'borrow, 'borrow> {
    raw: AutoLocal<'env, 'borrow>,
}

impl<'env: 'borrow, 'borrow> SecretKeyEntry<'env, 'borrow> {
    pub fn new(env: &'borrow JNIEnv<'env>, secret_key: JObject) -> Result<Self> {
        let class = env.find_class("java/security/KeyStore$SecretKeyEntry")?;
        let args = [JValue::Object(secret_key)];
        let obj = env.new_object(class, "(Ljavax/crypto/SecretKey;)V", &args)?;
        Ok(Self {
            raw: AutoLocal::new(env, Into::<JObject>::into(obj)),
        })
    }
}
