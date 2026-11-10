//! AEAD primitives shared by the protocols.

use std::io;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use sybau_common::proto_err;

pub const TAG_LEN: usize = 16;

type Aes192Gcm = AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadKind {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl AeadKind {
    pub fn key_len(self) -> usize {
        match self {
            AeadKind::Aes128Gcm => 16,
            AeadKind::Aes192Gcm => 24,
            AeadKind::Aes256Gcm | AeadKind::ChaCha20Poly1305 | AeadKind::XChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            AeadKind::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
}

/// An AEAD cipher with its key schedule already expanded.
pub enum Aead {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes192Gcm(Box<Aes192Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
    XChaCha20Poly1305(Box<XChaCha20Poly1305>),
}

fn auth_failed() -> io::Error {
    proto_err("AEAD authentication failed")
}

impl Aead {
    /// Panics if `key` has the wrong length for `kind`; callers derive
    /// keys with the right size.
    pub fn new(kind: AeadKind, key: &[u8]) -> Self {
        assert_eq!(key.len(), kind.key_len(), "AEAD key length");
        match kind {
            AeadKind::Aes128Gcm => {
                Aead::Aes128Gcm(Box::new(Aes128Gcm::new_from_slice(key).unwrap()))
            }
            AeadKind::Aes192Gcm => {
                Aead::Aes192Gcm(Box::new(Aes192Gcm::new_from_slice(key).unwrap()))
            }
            AeadKind::Aes256Gcm => {
                Aead::Aes256Gcm(Box::new(Aes256Gcm::new_from_slice(key).unwrap()))
            }
            AeadKind::ChaCha20Poly1305 => {
                Aead::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new_from_slice(key).unwrap()))
            }
            AeadKind::XChaCha20Poly1305 => {
                Aead::XChaCha20Poly1305(Box::new(XChaCha20Poly1305::new_from_slice(key).unwrap()))
            }
        }
    }

    /// Encrypts `data` in place and returns the authentication tag.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        let tag = match self {
            Aead::Aes128Gcm(c) => c.encrypt_in_place_detached(nonce.into(), aad, data),
            Aead::Aes192Gcm(c) => c.encrypt_in_place_detached(nonce.into(), aad, data),
            Aead::Aes256Gcm(c) => c.encrypt_in_place_detached(nonce.into(), aad, data),
            Aead::ChaCha20Poly1305(c) => c.encrypt_in_place_detached(nonce.into(), aad, data),
            Aead::XChaCha20Poly1305(c) => c.encrypt_in_place_detached(nonce.into(), aad, data),
        }
        .expect("AEAD encryption cannot fail for in-memory buffers");
        tag.into()
    }

    /// Appends `plain` encrypted, followed by its tag, to `out`.
    pub fn seal_append(&self, nonce: &[u8], aad: &[u8], plain: &[u8], out: &mut bytes::BytesMut) {
        let start = out.len();
        out.extend_from_slice(plain);
        let tag = self.seal(nonce, aad, &mut out[start..]);
        out.extend_from_slice(&tag);
    }

    /// Decrypts `data` (ciphertext followed by tag) in place and returns
    /// the plaintext length.
    pub fn open(&self, nonce: &[u8], aad: &[u8], data: &mut [u8]) -> io::Result<usize> {
        if data.len() < TAG_LEN {
            return Err(auth_failed());
        }
        let (body, tag) = data.split_at_mut(data.len() - TAG_LEN);
        let tag = &*tag;
        match self {
            Aead::Aes128Gcm(c) => c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into()),
            Aead::Aes192Gcm(c) => c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into()),
            Aead::Aes256Gcm(c) => c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into()),
            Aead::ChaCha20Poly1305(c) => {
                c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into())
            }
            Aead::XChaCha20Poly1305(c) => {
                c.decrypt_in_place_detached(nonce.into(), aad, body, tag.into())
            }
        }
        .map_err(|_| auth_failed())?;
        Ok(body.len())
    }
}

/// Little-endian counter nonce (Shadowsocks AEAD chunk streams).
pub struct CounterNonce {
    buf: [u8; 24],
    len: usize,
}

impl CounterNonce {
    pub fn new(len: usize) -> Self {
        assert!(len <= 24);
        Self { buf: [0; 24], len }
    }

    /// Returns the current value and advances the counter.
    pub fn advance(&mut self) -> Nonce {
        let current = Nonce {
            buf: self.buf,
            len: self.len,
        };
        for b in self.buf[..self.len].iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        current
    }
}

/// A nonce value of 12 or 24 bytes.
pub struct Nonce {
    buf: [u8; 24],
    len: usize,
}

impl std::ops::Deref for Nonce {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut out);
    out
}

pub fn fill_random(buf: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_all_ciphers() {
        for kind in [
            AeadKind::Aes128Gcm,
            AeadKind::Aes192Gcm,
            AeadKind::Aes256Gcm,
            AeadKind::ChaCha20Poly1305,
            AeadKind::XChaCha20Poly1305,
        ] {
            let key = vec![7u8; kind.key_len()];
            let nonce = vec![1u8; kind.nonce_len()];
            let aead = Aead::new(kind, &key);
            let mut out = bytes::BytesMut::new();
            aead.seal_append(&nonce, b"aad", b"hello", &mut out);
            assert_eq!(out.len(), 5 + TAG_LEN);
            let mut tampered = out.clone();
            tampered[0] ^= 1;
            assert!(aead.open(&nonce, b"aad", &mut tampered).is_err());
            assert!(aead.open(&nonce, b"other", &mut out.clone()).is_err());
            let n = aead.open(&nonce, b"aad", &mut out).unwrap();
            assert_eq!(&out[..n], b"hello");
        }
    }

    #[test]
    fn counter_nonce_is_little_endian() {
        let mut n = CounterNonce::new(12);
        assert_eq!(&*n.advance(), &[0u8; 12][..]);
        assert_eq!(n.advance()[0], 1);
        for _ in 0..254 {
            n.advance();
        }
        let v = n.advance();
        assert_eq!((v[0], v[1]), (0, 1));
    }
}
