use robusta_jni::{bridge, jni::JNIEnv};

use crate::common::error::{CalError, ToCalError};

#[bridge]
/// This module contains the JNI bindings for the KeyStore functionality in Android.
pub(crate) mod jni {
    use robusta_jni::{
        convert::{FromJavaValue, IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{errors::Result as JniResult, objects::AutoLocal, JNIEnv},
    };

    #[derive(Signature, FromJavaValue, TryFromJavaValue, IntoJavaValue, TryIntoJavaValue)]
    #[package(android.content)]
    pub(crate) struct Context<'env: 'borrow, 'borrow> {
        #[instance]
        raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> Context<'borrow, 'borrow> {
        #[constructor]
        pub(crate) extern "java" fn new(env: &'borrow JNIEnv) -> JniResult<Self> {}

        pub(crate) extern "java" fn getPackageManager(
            &self,
            env: &'borrow JNIEnv<'env>,
        ) -> JniResult<PackageManager> {
        }
    }

    #[derive(Signature, FromJavaValue, TryFromJavaValue, IntoJavaValue, TryIntoJavaValue)]
    #[package(android.content.pm)]
    pub(crate) struct PackageManager<'env: 'borrow, 'borrow> {
        #[instance]
        raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> PackageManager<'env, 'borrow> {
        pub(crate) extern "java" fn hasSystemFeature(
            &self,
            env: &JNIEnv,
            featureName: String,
            version: i32,
        ) -> JniResult<bool> {
        }
    }
}

pub(crate) fn has_strong_box(env: &JNIEnv) -> Result<bool, CalError> {
    let context = jni::Context::new(env).unwrap();
    let package_manager = context.getPackageManager(env).err_internal()?;
    let has_strong_box = package_manager
        .hasSystemFeature(env, "android.hardware.strongbox_keystore".to_string(), 40)
        .err_internal()?;
    Ok(has_strong_box)
}
