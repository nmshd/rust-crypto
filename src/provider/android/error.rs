use anyhow::{anyhow, Context};
use robusta_jni::jni::JavaVM;
use tracing::{info, warn};

use crate::{
    common::error::{CalError, ToCalError},
    provider::android::wrapper::context,
};

#[derive(Debug)]
pub(crate) struct JavaException(String);

impl std::fmt::Display for JavaException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Java Exception: {}", self.0)
    }
}

impl std::error::Error for JavaException {}

/// This allows converting the JNI result into a `TpmError` result.
impl<T> ToCalError<T> for robusta_jni::jni::errors::Result<T> {
    /// Converts the JNI result into a `TpmError` result.
    /// If a Java exception was thrown, it retrieves the exception message and puts it into the error.
    /// If no exception was thrown, it returns the JNI error as the `TpmError`.
    fn err_internal(self) -> Result<T, CalError> {
        err_internal(self)
            .context("JNI Error, try to get Exception message")
            .map_err(CalError::other)
    }
}

fn err_internal<T>(res: robusta_jni::jni::errors::Result<T>) -> Result<T, anyhow::Error> {
    match res {
        Ok(v) => Ok(v),
        Err(e) => {
            info!("err_internal: {:?}", e);
            // check if a java exception was thrown
            let vm = context::android_context()?.vm();
            let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
            let env = vm.attach_current_thread().err_internal()?;
            if env.exception_check().map_err(anyhow::Error::new)? {
                // get the exception message and put it into the error
                env.exception_describe().map_err(anyhow::Error::new)?;
                let ex = env.exception_occurred().map_err(anyhow::Error::new)?;
                env.exception_clear().map_err(anyhow::Error::new)?;
                let message = env
                    .call_method(ex, "getMessage", "()Ljava/lang/String;", &[])
                    .and_then(|v| v.l())
                    .map_err(anyhow::Error::new)?;

                let message = env
                    .get_string(Into::into(message))
                    .map_err(anyhow::Error::new)?
                    .to_str()
                    .map_err(anyhow::Error::new)?
                    .to_string();
                warn!("Java exception found: {}", message);
                Err(anyhow!(JavaException(message)))
            } else {
                // there was no exception, return the jni error
                warn!("No java exception found");
                Err(anyhow!(e).context("Not a java exception"))
            }
        }
    }
}
