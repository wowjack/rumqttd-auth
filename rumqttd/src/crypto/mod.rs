use rand::{RngCore, SeedableRng};
use speck_cipher::{cipher::{BlockEncrypt, KeyInit}, Speck128_256};
use poly1305::Poly1305;
use rand_chacha::ChaCha20Rng;

use super::*;

type Key = [u8; 32]; // 256 bit / 32 byte key
type Tag = [u8; 16]; // 128 bit / 16 byte tag
type Challenge = [u8; 12]; // 96 bit / 12 byte nonce

pub fn validate_tag(
    tag: Tag,
    key: Key,
    challenge: Challenge,
    client_id: &ClientId
) -> bool {
    let Ok(hash) = Poly1305::new_from_slice(&key) else { return false };
    let Ok(cipher) = Speck128_256::new_from_slice(&key) else { return false };
    let preimage = [challenge.as_slice(), client_id.as_bytes()].concat();
    let mut digest = hash.compute_unpadded(&preimage);
    cipher.encrypt_block(digest.as_mut_slice().into());
    let Some(expected_tag): Option<Tag> = digest.as_slice().try_into().ok() else { return false };

    // constant time comparison (hopefully)
    let mut eq = true;
    for (b1, b2) in tag.iter().zip(expected_tag.iter()) {
        if b1 != b2 { eq = false }
    }
    return eq
}

pub fn compute_tag(
    key: Key,
    challenge: Challenge,
    client_id: &ClientId
) -> Option<Tag> {
    let Ok(hash) = Poly1305::new_from_slice(&key) else { return None };
    let Ok(cipher) = Speck128_256::new_from_slice(&key) else { return None };
    let preimage = [client_id.as_bytes(), challenge.as_slice()].concat();
    let mut digest = hash.compute_unpadded(&preimage);
    cipher.encrypt_block(digest.as_mut_slice().into());
    digest.as_slice().try_into().ok()
}

pub fn generate_challenge() -> Challenge {
    let mut challenge = [0u8; 12];
    ChaCha20Rng::from_entropy().fill_bytes(&mut challenge);
    return challenge;

}