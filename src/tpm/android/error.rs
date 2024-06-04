use crate::tpm::core::error::{ToTpmError, TpmError};

use super::wrapper;

#[derive(Debug)]
pub(crate) struct JavaException(String);

impl std::fmt::Display for JavaException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Java Exception: {}", self.0)
    }
}

impl std::error::Error for JavaException {}

/// This allows converting the JNI result into a `TpmError` result.
impl<T> ToTpmError<T> for robusta_jni::jni::errors::Result<T> {
    /// Converts the JNI result into a `TpmError` result.
    /// If a Java exception was thrown, it retrieves the exception message and puts it into the error.
    /// If no exception was thrown, it returns the JNI error as the `TpmError`.
    fn err_internal(self) -> Result<T, TpmError> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
                // check if a java exception was thrown
                let vm =
                    wrapper::get_java_vm().map_err(|e| TpmError::InternalError(Box::new(e)))?;
                let env = vm
                    .get_env()
                    .map_err(|e| TpmError::InternalError(Box::new(e)))?;
                if env
                    .exception_check()
                    .map_err(|e| TpmError::InternalError(Box::new(e)))?
                {
                    // get the exception message and put it into the error
                    env.exception_describe()
                        .map_err(|e| TpmError::InternalError(Box::new(e)))?;
                    let ex = env
                        .exception_occurred()
                        .map_err(|e| TpmError::InternalError(Box::new(e)))?;
                    env.exception_clear()
                        .map_err(|e| TpmError::InternalError(Box::new(e)))?;
                    let message = env
                        .call_method(ex, "getMessage", "()Ljava/lang/String;", &[])
                        .and_then(|v| v.l())
                        .map_err(|e| TpmError::InternalError(Box::new(e)))?;

                    let message = env
                        .get_string(Into::into(message))
                        .map_err(|e| TpmError::InternalError(Box::new(e)))?
                        .to_str()
                        .map_err(|e| TpmError::InternalError(Box::new(e)))?
                        .to_string();
                    Err(TpmError::InternalError(Box::new(JavaException(message))))
                } else {
                    // there was no exception, return the jni error
                    Err(TpmError::InternalError(Box::new(e)))
                }
            }
        }
    }
}
