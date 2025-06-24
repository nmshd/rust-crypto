use crate::prelude::CryptoHash;

pub(super) fn ring_hmac_algorithm_from_signing_hash(
    hash_algorithm: CryptoHash,
) -> Option<ring::hmac::Algorithm> {
    match hash_algorithm {
        CryptoHash::Sha2_256 => Some(ring::hmac::HMAC_SHA256),
        CryptoHash::Sha2_384 => Some(ring::hmac::HMAC_SHA384),
        CryptoHash::Sha2_512 => Some(ring::hmac::HMAC_SHA512),
        _ => None,
    }
}
