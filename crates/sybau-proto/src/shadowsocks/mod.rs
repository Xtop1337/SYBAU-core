//! Shadowsocks: classic AEAD ciphers (SIP004) and Shadowsocks 2022 (SIP022).

pub mod aead;
pub mod ss2022;

use std::io;

use base64::Engine as _;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use sybau_common::proto_err;

use crate::crypto::AeadKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// No encryption (`none` / `plain`).
    None,
    /// SIP004 AEAD cipher.
    Aead(AeadKind),
    /// SIP022 (`2022-blake3-*`).
    Ss2022(AeadKind),
}

pub fn parse_method(name: &str) -> Option<Method> {
    Some(match name.to_ascii_lowercase().as_str() {
        "none" | "plain" => Method::None,
        "aes-128-gcm" | "aead_aes_128_gcm" => Method::Aead(AeadKind::Aes128Gcm),
        "aes-192-gcm" => Method::Aead(AeadKind::Aes192Gcm),
        "aes-256-gcm" | "aead_aes_256_gcm" => Method::Aead(AeadKind::Aes256Gcm),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" | "aead_chacha20_poly1305" => {
            Method::Aead(AeadKind::ChaCha20Poly1305)
        }
        "xchacha20-ietf-poly1305" | "xchacha20-poly1305" | "aead_xchacha20_poly1305" => {
            Method::Aead(AeadKind::XChaCha20Poly1305)
        }
        "2022-blake3-aes-128-gcm" => Method::Ss2022(AeadKind::Aes128Gcm),
        "2022-blake3-aes-256-gcm" => Method::Ss2022(AeadKind::Aes256Gcm),
        "2022-blake3-chacha20-poly1305" => Method::Ss2022(AeadKind::ChaCha20Poly1305),
        _ => return None,
    })
}

/// OpenSSL `EVP_BytesToKey` with MD5: how classic Shadowsocks turns a
/// password into a key.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + 16);
    let mut last: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&last);
        h.update(password);
        last = h.finalize().to_vec();
        key.extend_from_slice(&last);
    }
    key.truncate(key_len);
    key
}

/// Per-session subkey of SIP004: HKDF-SHA1(key, salt, "ss-subkey").
pub fn session_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; key.len()];
    Hkdf::<Sha1>::new(Some(salt), key)
        .expand(b"ss-subkey", &mut out)
        .expect("HKDF output length is valid");
    out
}

/// Parses the keys of a Shadowsocks 2022 password: base64 PSKs separated
/// by `:`. All but the last are identity keys (multi-user servers).
pub fn parse_2022_keys(password: &str, kind: AeadKind) -> io::Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    for part in password.split(':') {
        let key = base64::engine::general_purpose::STANDARD
            .decode(part.trim())
            .map_err(|_| proto_err("Shadowsocks 2022 key is not valid base64"))?;
        if key.len() != kind.key_len() {
            return Err(proto_err(format!(
                "Shadowsocks 2022 key must be {} bytes, got {}",
                kind.key_len(),
                key.len()
            )));
        }
        keys.push(key);
    }
    if keys.len() > 1 && kind == AeadKind::ChaCha20Poly1305 {
        return Err(proto_err(
            "2022-blake3-chacha20-poly1305 does not support identity keys",
        ));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn evp_bytes_to_key_known_values() {
        // MD5("foobar") and MD5(MD5("foobar") || "foobar").
        assert_eq!(
            hex(&evp_bytes_to_key(b"foobar", 16)),
            "3858f62230ac3c915f300c664312c63f"
        );
        assert_eq!(
            hex(&evp_bytes_to_key(b"foobar", 32)),
            "3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf"
        );
    }

    #[test]
    fn methods_and_keys() {
        assert_eq!(
            parse_method("AES-256-GCM"),
            Some(Method::Aead(AeadKind::Aes256Gcm))
        );
        assert_eq!(
            parse_method("2022-blake3-aes-128-gcm"),
            Some(Method::Ss2022(AeadKind::Aes128Gcm))
        );
        assert!(parse_method("rc4-md5").is_none());
        let k16 = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert_eq!(
            parse_2022_keys(&format!("{k16}:{k16}"), AeadKind::Aes128Gcm)
                .unwrap()
                .len(),
            2
        );
        assert!(parse_2022_keys(&k16, AeadKind::Aes256Gcm).is_err());
        assert!(parse_2022_keys("!!", AeadKind::Aes128Gcm).is_err());
    }
}
