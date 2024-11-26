use std::str::FromStr;
use neon::prelude::*;
use crypto_layer::prelude::*;
use crypto_layer::common::crypto::algorithms::encryption::{TripleDesNumKeys, Rc2KeyBits};

use super::error::{js_result, match_variant_result, ConversionError};
use super::{from_wrapped_enum, is_pair};

pub fn from_wrapped_cipher<'a>(cx: &mut impl Context<'a>, wrapped_cipher: Handle<JsValue>) -> Result<Cipher, ConversionError> {
    let (mut cipher, obj_option): (Cipher, _) = from_wrapped_enum(cx, wrapped_cipher)?;

    if let Some(obj) = obj_option {
        match cipher {
            Cipher::TripleDes(_) => { let (length, _) = from_wrapped_enum::<TripleDesNumKeys>(cx, obj)? ; cipher = Cipher::TripleDes(length); },
            Cipher::Chacha20(_) => { let (length, _) = from_wrapped_enum::<ChCha20Mode>(cx, obj)? ; cipher = Cipher::Chacha20(length); },
            Cipher::Rc2(_) => { let (length, _) = from_wrapped_enum::<Rc2KeyBits>(cx, obj)? ; cipher = Cipher::Rc2(length); },
            Cipher::Camellia(_, _) => {
                let (mode, bits) = is_pair(cx, obj)?;
                let key_bits = from_wrapped_keybits(cx, bits)?;
                let (symm_mode, _) = from_wrapped_enum::<SymmetricMode>(cx, mode)?;
                cipher = Cipher::Camellia(symm_mode, key_bits);
            },
            Cipher::Aes(_, _) => {
                let (mode, bits) = is_pair(cx, obj)?;
                let key_bits = from_wrapped_keybits(cx, bits)?;
                let (symm_mode, _) = from_wrapped_enum::<SymmetricMode>(cx, mode)?;
                cipher = Cipher::Aes(symm_mode, key_bits);
            },
            _ => {},
        }
    } else {
        match cipher {
            Cipher::Des => {},
            Cipher::Rc4 => {},
            _ => return Err(ConversionError::MissingEnumValues)
        }
    }
    

    Ok(cipher)
}

pub fn from_wrapped_keybits<'a>(cx: &mut impl Context<'a>, wrapped: Handle<JsValue>) -> Result<KeyBits, ConversionError> {
    let obj = js_result(wrapped.downcast::<JsString, _>(cx))?;
    match_variant_result(KeyBits::from_str(obj.value(cx).as_str()))
}

