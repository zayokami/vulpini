//! Shadowsocks key derivation and AEAD chunk ciphers (SIP004).
//!
//! Layout of one direction of an AEAD stream:
//!   salt (key_len, clear) — sent once at the start of the stream
//!   then repeated chunks of:
//!     encrypted u16 length block  (2 bytes plaintext -> 2 + 16 bytes)
//!     encrypted payload block     (<= 0x3FFF bytes -> len + 16 bytes)
//! Every AEAD operation consumes one nonce value: a 12-byte little-endian
//! counter starting at zero, independent per direction.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Nonce};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;

use crate::common::CoreError;
use crate::node::SsMethod;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// AEAD payload chunks must keep the top two bits of the u16 length zero.
pub const MAX_PAYLOAD_LEN: usize = 0x3FFF;
/// Wire size of an encrypted length block (u16 + tag).
pub const LENGTH_BLOCK_LEN: usize = 2 + TAG_LEN;

/// OpenSSL EVP_BytesToKey with MD5 and no salt — the shadowsocks legacy KDF
/// that turns a password into the master key.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + 16);
    let mut last: Option<[u8; 16]> = None;
    while key.len() < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last {
            m.update(digest);
        }
        m.update(password);
        let digest: [u8; 16] = m.finalize().into();
        let take = (key_len - key.len()).min(digest.len());
        key.extend_from_slice(&digest[..take]);
        last = Some(digest);
    }
    key.truncate(key_len);
    key
}

/// HKDF-SHA1(salt, master_key, "ss-subkey") — per-connection subkey,
/// output length equals the master key length.
pub fn derive_subkey(salt: &[u8], master_key: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; master_key.len()];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("hkdf output length is valid");
    okm
}

enum AeadVariant {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

/// One direction of an AEAD stream (encrypt OR decrypt). The nonce counter
/// lives inside, so each direction needs its own instance.
pub struct AeadCipher {
    variant: AeadVariant,
    nonce: [u8; NONCE_LEN],
}

impl AeadCipher {
    pub fn new(method: SsMethod, subkey: &[u8]) -> Self {
        let variant = match method {
            SsMethod::Aes128Gcm => AeadVariant::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(subkey).expect("aes-128 key length"),
            )),
            SsMethod::Aes256Gcm => AeadVariant::Aes256Gcm(Box::new(
                Aes256Gcm::new_from_slice(subkey).expect("aes-256 key length"),
            )),
            SsMethod::ChaCha20IetfPoly1305 => AeadVariant::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(subkey).expect("chacha20 key length"),
            )),
        };
        AeadCipher {
            variant,
            nonce: [0u8; NONCE_LEN],
        }
    }

    fn increase_nonce(&mut self) {
        // Little-endian increment: nonce[0] is least significant.
        let mut carry: u16 = 1;
        for byte in &mut self.nonce {
            carry += *byte as u16;
            *byte = carry as u8;
            carry >>= 8;
        }
    }

    /// Encrypt one block; returns ciphertext with the 16-byte tag appended.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce;
        self.increase_nonce();
        let result = match &self.variant {
            AeadVariant::Aes128Gcm(c) => c.encrypt(nonce_ref::<Aes128Gcm>(&nonce), plaintext),
            AeadVariant::Aes256Gcm(c) => c.encrypt(nonce_ref::<Aes256Gcm>(&nonce), plaintext),
            AeadVariant::ChaCha20Poly1305(c) => {
                c.encrypt(nonce_ref::<ChaCha20Poly1305>(&nonce), plaintext)
            }
        };
        result.expect("aead encryption cannot fail for in-range lengths")
    }

    /// Decrypt one block produced by [`AeadCipher::encrypt`].
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let nonce = self.nonce;
        self.increase_nonce();
        let result = match &self.variant {
            AeadVariant::Aes128Gcm(c) => c.decrypt(nonce_ref::<Aes128Gcm>(&nonce), ciphertext),
            AeadVariant::Aes256Gcm(c) => c.decrypt(nonce_ref::<Aes256Gcm>(&nonce), ciphertext),
            AeadVariant::ChaCha20Poly1305(c) => {
                c.decrypt(nonce_ref::<ChaCha20Poly1305>(&nonce), ciphertext)
            }
        };
        result.map_err(|_| CoreError::Protocol("shadowsocks aead decrypt failed".into()))
    }
}

fn nonce_ref<C: AeadCore>(nonce: &[u8; NONCE_LEN]) -> &Nonce<C> {
    nonce.as_slice().try_into().expect("nonce length matches")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn evp_bytes_to_key_md5_vector() {
        // For a 16-byte key, EVP_BytesToKey is exactly MD5(password).
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(key, hex("5f4dcc3b5aa765d61d8327deb882cf99"));
    }

    #[test]
    fn evp_bytes_to_key_longer_than_digest() {
        // 32-byte key = MD5(pw) || MD5(MD5(pw) || pw), truncated.
        let key = evp_bytes_to_key(b"password", 32);
        let d1: [u8; 16] = Md5::digest(b"password").into();
        let mut m = Md5::new();
        m.update(d1);
        m.update(b"password");
        let d2: [u8; 16] = m.finalize().into();
        let mut expected = d1.to_vec();
        expected.extend_from_slice(&d2);
        assert_eq!(key, expected);
    }

    #[test]
    fn evp_matches_reference_impl() {
        // Cross-check against shadowsocks-rust's own KDF.
        for password in [b"password".as_slice(), b"", b"a much longer passphrase!!"] {
            for key_len in [16usize, 24, 32] {
                let mut reference = vec![0u8; key_len];
                shadowsocks::crypto::v1::openssl_bytes_to_key(password, &mut reference);
                assert_eq!(evp_bytes_to_key(password, key_len), reference);
            }
        }
    }

    #[test]
    fn nonce_increments_little_endian() {
        let mut cipher = AeadCipher::new(SsMethod::Aes128Gcm, &[7u8; 16]);
        cipher.nonce[0] = 0xFF;
        cipher.nonce[1] = 0x01;
        cipher.increase_nonce();
        assert_eq!(cipher.nonce[0], 0x00);
        assert_eq!(cipher.nonce[1], 0x02);
        assert_eq!(cipher.nonce[2], 0x00);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_all_methods() {
        for method in [
            SsMethod::Aes128Gcm,
            SsMethod::Aes256Gcm,
            SsMethod::ChaCha20IetfPoly1305,
        ] {
            let key = evp_bytes_to_key(b"pw", method.key_len());
            let mut enc = AeadCipher::new(method, &key);
            let mut dec = AeadCipher::new(method, &key);
            for i in 0..5 {
                let payload = vec![i as u8; 100 * (i as usize + 1)];
                let ct = enc.encrypt(&payload);
                assert_eq!(ct.len(), payload.len() + TAG_LEN);
                assert_eq!(dec.decrypt(&ct).unwrap(), payload);
            }
        }
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let key = evp_bytes_to_key(b"pw", 16);
        let mut enc = AeadCipher::new(SsMethod::Aes128Gcm, &key);
        let _ = enc.encrypt(b"first");
        let ct = enc.encrypt(b"second");
        // A fresh decryptor expects nonce 0, but ct used nonce 1.
        let mut dec = AeadCipher::new(SsMethod::Aes128Gcm, &key);
        assert!(dec.decrypt(&ct).is_err());
    }
}
