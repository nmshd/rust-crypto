
use std::str::FromStr;
use neon::prelude::*;
use crypto_layer::prelude::*;

use super::error::{ConversionError, match_variant_result};

pub fn from_wrapped_security_level<'a>(cx: &mut impl Context<'a>, wrapped_security_level: Handle<JsString>) -> Result<SecurityLevel, ConversionError> {
    let value = wrapped_security_level.value(cx);
    match_variant_result(SecurityLevel::from_str(&value))
}