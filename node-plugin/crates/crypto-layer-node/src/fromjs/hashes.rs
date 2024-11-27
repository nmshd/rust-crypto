use crypto_layer::prelude::*;
use neon::prelude::*;
use std::str::FromStr;

use super::error::{js_result, match_variant_result, ConversionError};
use super::{from_wrapped_enum, is_pair};

pub fn from_wrapped_crypto_hash(
    cx: &mut FunctionContext,
    wrapped: Handle<JsValue>,
) -> Result<CryptoHash, ConversionError> {
    let (mut hash, value) = from_wrapped_enum::<CryptoHash>(cx, wrapped)?;

    if let Some(obj) = value {
        match hash {
            CryptoHash::Sha2(_) => {
                let (length, _) = from_wrapped_enum::<Sha2Bits>(cx, obj)?;
                hash = CryptoHash::Sha2(length);
            }
            CryptoHash::Sha3(_) => {
                let (length, _) = from_wrapped_enum::<Sha3Bits>(cx, obj)?;
                hash = CryptoHash::Sha3(length);
            }
            _ => {}
        }
    } else {
        match hash {
            CryptoHash::Sha2(_) | CryptoHash::Sha3(_) => {
                return Err(ConversionError::MissingEnumValues)
            }
            _ => {}
        }
    }

    Ok(hash)
}
