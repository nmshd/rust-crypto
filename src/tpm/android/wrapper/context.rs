use robusta_jni::bridge;
use tracing::trace;

use crate::common::error::{CalError, ToCalError};
use robusta_jni::jni::objects::JObject;

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
        pub(crate) raw: AutoLocal<'env, 'borrow>,
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

#[tracing::instrument]
pub(crate) fn has_strong_box() -> Result<bool, CalError> {
    trace!("Checking if the device has a strong box");
    let ctx = ndk_context::android_context();
    trace!("Got the android context");
    let vm = unsafe { robusta_jni::jni::JavaVM::from_raw(ctx.vm().cast()) }.err_internal()?;
    trace!("Got the java vm");
    let env = vm.attach_current_thread().err_internal()?;
    trace!("Got the java env");
    let context = ctx.context();
    trace!("context pointer: {:?}", context);
    let context_objext =
        robusta_jni::jni::objects::JObject::from(context as robusta_jni::jni::sys::jobject);
    trace!("context object: {:?}", context_objext);
    let context = jni::Context {
        raw: robusta_jni::jni::objects::AutoLocal::new(
            &env,
            env.new_local_ref::<JObject>(context_objext)
                .err_internal()?,
        ),
    };

    trace!("Got the context object");
    let package_manager = context.getPackageManager(&env).err_internal()?;
    trace!("Got the package manager object");
    // let has_strong_box = package_manager
    //     .hasSystemFeature(&env, "android.hardware.strongbox_keystore".to_string(), 40)
    //     .err_internal()?;
    // trace!("Checked if the device has a strong box");
    // Ok(has_strong_box)
    Ok(true)
}
