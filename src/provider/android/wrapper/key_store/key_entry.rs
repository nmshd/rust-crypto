use robusta_jni::jni::objects::{JObject, JValue};
use robusta_jni::jni::{errors::Result, objects::AutoLocal, JNIEnv};

use crate::provider::android::wrapper::key_store::store::jni::Certificate;

pub(crate) struct SecretKeyEntry<'env: 'borrow, 'borrow> {
    pub(crate) raw: AutoLocal<'env, 'borrow>,
}

impl<'env: 'borrow, 'borrow> SecretKeyEntry<'env, 'borrow> {
    pub(crate) fn new(env: &'borrow JNIEnv<'env>, secret_key: JObject) -> Result<Self> {
        let class = env.find_class("java/security/KeyStore$SecretKeyEntry")?;
        let args = [JValue::Object(secret_key)];
        let obj = env.new_object(class, "(Ljavax/crypto/SecretKey;)V", &args)?;
        Ok(Self {
            raw: AutoLocal::new(env, Into::<JObject>::into(obj)),
        })
    }
}

pub(crate) struct PrivateKeyEntry<'env: 'borrow, 'borrow> {
    pub(crate) raw: AutoLocal<'env, 'borrow>,
}

impl<'env: 'borrow, 'borrow> PrivateKeyEntry<'env, 'borrow> {
    pub(crate) fn get_certificate(&self, env: &'borrow JNIEnv<'env>) -> Result<Certificate> {
        env.call_method(
            self.raw.as_obj(),
            "getCertificate",
            "()Ljava/security/cert/Certificate;",
            &[],
        )
        .and_then(|result| result.l())
        .map(|obj| Certificate {
            raw: AutoLocal::new(env, Into::<JObject>::into(obj)),
        })
    }
}
