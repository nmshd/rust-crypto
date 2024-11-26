use std::str::FromStr;
use neon::prelude::*;
use crypto_layer::prelude::*;

use super::error::ConversionError;
use super::from_wrapped_enum;

pub fn from_wrapped_cipher<'a>(cx: &mut impl Context<'a>, wrapped_cipher: Handle<JsValue>) -> Result<Cipher, ConversionError> {
    let mut cipher: Cipher = from_wrapped_enum(cx, wrapped_cipher)?;

    todo!()
}