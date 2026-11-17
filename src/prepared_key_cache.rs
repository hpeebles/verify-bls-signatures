//! The public keys most recently verified against, decoded and prepared for
//! the pairing (`prepared_key_cache` feature).
//!
//! Decoding a key (its decompression and subgroup check) and preparing it
//! for the Miller loop cost about a fifth of a verification, and verifiers
//! use the same few keys for nearly everything they check. An entry is
//! keyed by the key's exact encoding and holds only what decoding and
//! preparing that encoding would produce again, so a hit answers exactly as
//! doing the work again would. Encodings that fail to decode, and the
//! identity element, are never cached: they are refused as before.

extern crate alloc;
extern crate std;

use crate::PublicKey;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bls12_381::G2Prepared;
use std::sync::Mutex;

/// Keys kept. A verifier of IC certificates uses the root key and one key per
/// subnet it hears from, so a handful is plenty; past this the least recently
/// used goes.
const CAPACITY: usize = 16;

/// Most recently used first.
static CACHE: Mutex<Vec<([u8; PublicKey::BYTES], Arc<G2Prepared>)>> = Mutex::new(Vec::new());

/// `key` decoded and prepared, from the cache or freshly. Refuses, as
/// [`PublicKey::deserialize`] and [`PublicKey::verify`] do, an encoding that
/// is not a valid point or is the identity element.
pub(crate) fn prepared(key: &[u8]) -> Result<Arc<G2Prepared>, ()> {
    let key: [u8; PublicKey::BYTES] = key.try_into().map_err(|_| ())?;

    if let Some(prepared) = lookup(&key) {
        return Ok(prepared);
    }

    let pk = PublicKey::deserialize(&key).map_err(|_| ())?;
    if pk.pk.is_identity().into() {
        return Err(());
    }
    let prepared = Arc::new(G2Prepared::from(pk.pk));
    insert(key, prepared.clone());
    Ok(prepared)
}

fn lookup(key: &[u8; PublicKey::BYTES]) -> Option<Arc<G2Prepared>> {
    let mut cache = lock();
    let index = cache.iter().position(|(cached, _)| cached == key)?;
    let entry = cache.remove(index);
    let prepared = entry.1.clone();
    cache.insert(0, entry);
    Some(prepared)
}

fn insert(key: [u8; PublicKey::BYTES], prepared: Arc<G2Prepared>) {
    let mut cache = lock();
    // Two callers racing to prepare the same key each insert it; keep one.
    cache.retain(|(cached, _)| cached != &key);
    cache.insert(0, (key, prepared));
    cache.truncate(CAPACITY);
}

fn lock() -> std::sync::MutexGuard<'static, Vec<([u8; PublicKey::BYTES], Arc<G2Prepared>)>> {
    // A panic while the lock is held leaves only whole entries behind, each
    // a correct preparation of its key, so the cache stays usable.
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_bls_signature, PrivateKey};

    fn key(n: u8) -> PrivateKey {
        let mut bytes = [0u8; PrivateKey::BYTES];
        bytes[PrivateKey::BYTES - 1] = n;
        PrivateKey::deserialize(&bytes).unwrap()
    }

    fn cached(public_key: &[u8]) -> bool {
        lock()
            .iter()
            .any(|(cached, _)| cached.as_slice() == public_key)
    }

    // One test: the cache is one per process, and tests run in parallel.
    #[test]
    fn the_cache_answers_as_decoding_and_preparing_again_would() {
        let message = b"a message";

        // A key verifies the same on first use and from the cache.
        let first = key(1);
        let first_pk = first.public_key().serialize();
        let signature = first.sign(message).serialize();
        assert!(verify_bls_signature(&signature, message, &first_pk).is_ok());
        assert!(cached(&first_pk));
        assert!(verify_bls_signature(&signature, message, &first_pk).is_ok());

        // A cached key still refuses what it did not sign.
        assert!(verify_bls_signature(&signature, b"another message", &first_pk).is_err());
        let other = key(2).sign(message).serialize();
        assert!(verify_bls_signature(&other, message, &first_pk).is_err());
        let mut identity_signature = [0u8; crate::Signature::BYTES];
        identity_signature[0] = 0xc0;
        assert!(verify_bls_signature(&identity_signature, message, &first_pk).is_err());

        // The identity element and undecodable encodings are refused every
        // time, and never cached.
        let mut identity = [0u8; PublicKey::BYTES];
        identity[0] = 0xc0;
        let garbage = [0xffu8; PublicKey::BYTES];
        for refused in [identity, garbage] {
            for _ in 0..2 {
                assert!(verify_bls_signature(&signature, message, &refused).is_err());
            }
            assert!(!cached(&refused));
        }
        assert!(verify_bls_signature(&signature, message, &first_pk[..95]).is_err());

        // Past the capacity the least recently used key goes, and verifies
        // again as before once it comes back.
        for n in 10..10 + CAPACITY as u8 {
            let k = key(n);
            let pk = k.public_key().serialize();
            assert!(verify_bls_signature(&k.sign(message).serialize(), message, &pk).is_ok());
        }
        assert_eq!(lock().len(), CAPACITY);
        assert!(!cached(&first_pk));
        assert!(verify_bls_signature(&signature, message, &first_pk).is_ok());
        assert!(cached(&first_pk));
    }
}
