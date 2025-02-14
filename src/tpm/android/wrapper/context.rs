use robusta_jni::bridge;
use tracing::trace;

use crate::common::error::{CalError, ToCalError};
use robusta_jni::jni::objects::JObject;

use std::ffi::c_void;

static mut ANDROID_CONTEXT: Option<AndroidContext> = None;

/// [`AndroidContext`] provides the pointers required to interface with the jni on Android
/// platforms.
#[derive(Clone, Copy, Debug)]
pub struct AndroidContext {
    java_vm: *mut c_void,
    context_jobject: *mut c_void,
}

impl AndroidContext {
    /// A handle to the `JavaVM` object.
    ///
    /// Usage with [__jni__](https://crates.io/crates/jni) crate:
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let ctx = ndk_context::android_context();
    /// let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    /// let env = vm.attach_current_thread();
    /// # Ok(())
    /// # }
    /// ```
    pub fn vm(self) -> *mut c_void {
        self.java_vm
    }

    /// A handle to an [android.content.Context](https://developer.android.com/reference/android/content/Context).
    /// In most cases this will be a ptr to an `Activity`, but this isn't guaranteed.
    ///
    /// Usage with [__jni__](https://crates.io/crates/jni) crate:
    /// ```no_run
    /// # use jni::objects::JObject;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let ctx = ndk_context::android_context();
    /// let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    /// let context = unsafe { JObject::from_raw(ctx.context().cast()) };
    /// let env = vm.attach_current_thread()?;
    /// let class_ctx = env.find_class("android/content/Context")?;
    /// let audio_service = env.get_static_field(class_ctx, "AUDIO_SERVICE", "Ljava/lang/String;")?;
    /// let audio_manager = env
    ///     .call_method(
    ///         context,
    ///         "getSystemService",
    ///         "(Ljava/lang/String;)Ljava/lang/Object;",
    ///         &[audio_service],
    ///     )?
    ///     .l()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn context(self) -> *mut c_void {
        self.context_jobject
    }
}

/// Main entry point to this crate. Returns an [`AndroidContext`].
pub fn android_context() -> Result<AndroidContext, CalError> {
    unsafe { ANDROID_CONTEXT }.ok_or(CalError::initialization_error(
        "Android context not initialized".to_string(),
    ))
}

#[allow(static_mut_refs)]
pub fn is_initialized() -> bool {
    unsafe { ANDROID_CONTEXT.is_some() }
}

/// Initializes the [`AndroidContext`]. [`AndroidContext`] is initialized by [__ndk-glue__](https://crates.io/crates/ndk-glue)
/// before `main` is called.
///
/// # Safety
///
/// The pointers must be valid and this function must be called exactly once before `main` is
/// called.
#[allow(static_mut_refs)]
pub unsafe fn initialize_android_context(java_vm: *mut c_void, context_jobject: *mut c_void) {
    let previous = ANDROID_CONTEXT.replace(AndroidContext {
        java_vm,
        context_jobject,
    });
    assert!(previous.is_none());
}

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
    let ctx = android_context()?;
    let vm = unsafe { robusta_jni::jni::JavaVM::from_raw(ctx.vm().cast()) }.err_internal()?;
    let env = vm.attach_current_thread().err_internal()?;
    let context = ctx.context();
    let context_objext =
        robusta_jni::jni::objects::JObject::from(context as robusta_jni::jni::sys::jobject);
    let context = jni::Context {
        raw: robusta_jni::jni::objects::AutoLocal::new(
            &env,
            env.new_local_ref::<JObject>(context_objext)
                .err_internal()?,
        ),
    };

    let package_manager = context.getPackageManager(&env).err_internal()?;
    let has_strong_box = package_manager
        .hasSystemFeature(&env, "android.hardware.strongbox_keystore".to_string(), 40)
        .err_internal()?;
    trace!("Device has strong box: {}", has_strong_box);
    Ok(has_strong_box)
}
