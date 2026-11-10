//! VMess AEAD key derivation: HMAC-SHA256 nested once per path element,
//! with "VMess AEAD KDF" as the innermost key.

use sha2::{Digest, Sha256};

pub const SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
pub const SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
pub const SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";
pub const SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub const SALT_HEADER_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
pub const SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
pub const SALT_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";

const BLOCK: usize = 64;

/// Hash function number `keys.len()` of the tower: level 0 is SHA-256,
/// level n is HMAC keyed with `keys[n-1]` over level n-1.
fn tower(keys: &[&[u8]], data: &[&[u8]]) -> [u8; 32] {
    let Some((key, below)) = keys.split_last() else {
        let mut h = Sha256::new();
        data.iter().for_each(|d| h.update(d));
        return h.finalize().into();
    };
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&tower(below, &[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let ipad = block.map(|b| b ^ 0x36);
    let opad = block.map(|b| b ^ 0x5c);
    let mut inner_input: Vec<&[u8]> = Vec::with_capacity(data.len() + 1);
    inner_input.push(&ipad);
    inner_input.extend_from_slice(data);
    let inner = tower(below, &inner_input);
    tower(below, &[&opad, &inner])
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF");
    keys.extend_from_slice(path);
    tower(&keys, &[key])
}

pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().expect("16 bytes")
}

pub fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    kdf(key, path)[..12].try_into().expect("12 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut block = [0u8; 64];
        block[..key.len()].copy_from_slice(key);
        let mut h = Sha256::new();
        h.update(block.map(|b| b ^ 0x36));
        h.update(msg);
        let inner = h.finalize();
        let mut h = Sha256::new();
        h.update(block.map(|b| b ^ 0x5c));
        h.update(inner);
        h.finalize().into()
    }

    #[test]
    fn empty_path_is_plain_hmac() {
        assert_eq!(
            kdf(b"key material", &[]),
            hmac_sha256(b"VMess AEAD KDF", b"key material")
        );
    }

    #[test]
    fn one_level_is_hmac_over_hmac() {
        // HMAC_outer(m) = H'(opad || H'(ipad || m)) where H' = HMAC("VMess AEAD KDF", ·)
        let base = |m: &[u8]| hmac_sha256(b"VMess AEAD KDF", m);
        let mut block = [0u8; 64];
        block[..4].copy_from_slice(b"path");
        let mut inner_in = block.map(|b| b ^ 0x36).to_vec();
        inner_in.extend_from_slice(b"msg");
        let inner = base(&inner_in);
        let mut outer_in = block.map(|b| b ^ 0x5c).to_vec();
        outer_in.extend_from_slice(&inner);
        assert_eq!(kdf(b"msg", &[b"path"]), base(&outer_in));
    }
}
