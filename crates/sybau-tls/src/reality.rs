//! REALITY client side (Xray's `transport/internet/reality`).
//!
//! The client proves knowledge of the server's public key inside the TLS
//! session id; a real REALITY server then answers with a temporary
//! Ed25519 certificate whose "signature" is `HMAC-SHA512(auth_key, pubkey)`.
//! Anyone else relays the handshake of the borrowed site untouched.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use sybau_common::proto_err;
use sybau_proto::crypto::{Aead, AeadKind};

use crate::fingerprint::ClientHello;

/// Version reported to the server (Xray-core release the protocol
/// behaviour was taken from); servers may enforce a minimum.
pub const CLIENT_VERSION: [u8; 3] = [26, 3, 27];

#[derive(Clone, Debug)]
pub struct RealityParams {
    /// Server's X25519 public key.
    pub public_key: [u8; 32],
    /// Up to 8 bytes, right-padded with zeros.
    pub short_id: [u8; 8],
}

impl RealityParams {
    /// Parses the base64url public key and hex short id as written in
    /// Xray and sing-box configs.
    pub fn parse(public_key: &str, short_id: &str) -> anyhow::Result<Self> {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key.trim().trim_end_matches('='))
            .map_err(|_| anyhow::anyhow!("REALITY public key is not valid base64url"))?;
        let public_key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("REALITY public key must be 32 bytes"))?;
        let hex = short_id.trim();
        if hex.len() > 16 || hex.len() & 1 == 1 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("REALITY short id must be up to 16 hex characters of even length");
        }
        let mut id = [0u8; 8];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            id[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16)
                .expect("hex digits");
        }
        Ok(Self {
            public_key,
            short_id: id,
        })
    }
}

/// Puts the authentication token into the session id of `hello` and
/// returns the 32-byte auth key shared with the server.
pub fn seal_hello(hello: &mut ClientHello, params: &RealityParams) -> io::Result<[u8; 32]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    seal_hello_at(hello, params, now as u32)
}

fn seal_hello_at(
    hello: &mut ClientHello,
    params: &RealityParams,
    unix_time: u32,
) -> io::Result<[u8; 32]> {
    if hello.session_id.len() != 32 {
        return Err(proto_err(
            "REALITY needs a fingerprint with a 32-byte session id",
        ));
    }
    if !hello.shared_groups.contains(&crate::keyshare::GROUP_X25519) {
        return Err(proto_err(
            "REALITY needs a fingerprint that offers an X25519 key share (TLS 1.3)",
        ));
    }
    let shared = hello
        .key_shares
        .x25519
        .diffie_hellman(&x25519_dalek::PublicKey::from(params.public_key));
    if !shared.was_contributory() {
        return Err(proto_err("REALITY public key is not a valid X25519 point"));
    }
    let mut auth_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello.random[..20]), shared.as_bytes())
        .expand(b"REALITY", &mut auth_key)
        .expect("32 bytes is a valid HKDF output length");

    let mut token = [0u8; 16];
    token[..3].copy_from_slice(&CLIENT_VERSION);
    token[4..8].copy_from_slice(&unix_time.to_be_bytes());
    token[8..].copy_from_slice(&params.short_id);

    // The hello with a zeroed session id is the additional data.
    hello.set_session_id(&[0u8; 32]);
    let aead = Aead::new(AeadKind::Aes256Gcm, &auth_key);
    let tag = aead.seal(&hello.random[20..], &hello.raw, &mut token);
    let mut session_id = [0u8; 32];
    session_id[..16].copy_from_slice(&token);
    session_id[16..].copy_from_slice(&tag);
    hello.set_session_id(&session_id);
    Ok(auth_key)
}

/// Checks that `cert` is the temporary certificate of a REALITY server
/// holding `auth_key`. Returns its Ed25519 public key.
pub fn verify_certificate(cert: &[u8], auth_key: &[u8; 32]) -> io::Result<[u8; 32]> {
    let not_reality = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY: the server presented a real certificate instead of a REALITY one \
             (wrong public key or short id, clock skew, or the connection is being intercepted)",
        )
    };
    let parsed = parse_ed25519_certificate(cert).ok_or_else(not_reality)?;
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(&parsed.public_key);
    mac.verify_slice(parsed.signature)
        .map_err(|_| not_reality())?;
    Ok(parsed.public_key)
}

/// Verifies the CertificateVerify signature of a REALITY handshake.
pub fn verify_handshake_signature(
    public_key: &[u8; 32],
    scheme: u16,
    message: &[u8],
    signature: &[u8],
) -> io::Result<()> {
    use ed25519_dalek::Verifier as _;
    if scheme != 0x0807 {
        return Err(proto_err("REALITY: handshake is not signed with Ed25519"));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| proto_err("REALITY: bad Ed25519 key"))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| proto_err("REALITY: bad signature length"))?;
    key.verify(message, &sig)
        .map_err(|_| proto_err("REALITY: server's handshake signature is invalid"))
}

struct Ed25519Certificate<'a> {
    public_key: [u8; 32],
    signature: &'a [u8],
}

/// Reads one DER element; returns `(tag, content, rest)`.
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_BIT_STRING: u8 = 0x03;
/// DER of OID 1.3.101.112 (id-Ed25519).
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// Extracts the public key and the signature value from an X.509
/// certificate whose subject key is Ed25519.
fn parse_ed25519_certificate(cert: &[u8]) -> Option<Ed25519Certificate<'_>> {
    let (tag, certificate, _) = der(cert)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (tag, tbs, rest) = der(certificate)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (_, _signature_algorithm, rest) = der(rest)?;
    let (tag, signature, _) = der(rest)?;
    if tag != TAG_BIT_STRING || signature.first() != Some(&0) {
        return None;
    }

    // TBSCertificate: [0] version?, serial, signature, issuer, validity,
    // subject, subjectPublicKeyInfo, ...
    let mut fields = tbs;
    let (tag, _, rest) = der(fields)?;
    if tag == 0xa0 {
        fields = rest;
    }
    for _ in 0..5 {
        fields = der(fields)?.2;
    }
    let (tag, spki, _) = der(fields)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (tag, algorithm, rest) = der(spki)?;
    if tag != TAG_SEQUENCE || algorithm != OID_ED25519 {
        return None;
    }
    let (tag, key, _) = der(rest)?;
    if tag != TAG_BIT_STRING || key.len() != 33 || key[0] != 0 {
        return None;
    }
    Some(Ed25519Certificate {
        public_key: key[1..].try_into().ok()?,
        signature: &signature[1..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{Fingerprint, HelloParams, SESSION_ID_OFFSET};

    fn hello() -> ClientHello {
        ClientHello::build(
            &Fingerprint::by_name("chrome").unwrap(),
            &HelloParams {
                server_name: "example.com".into(),
                alpn: None,
            },
        )
    }

    /// The server side of the token exchange, as xtls/reality does it.
    #[test]
    fn server_can_open_the_session_id() {
        let server_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let params = RealityParams {
            public_key: *x25519_dalek::PublicKey::from(&server_secret).as_bytes(),
            short_id: [0x12, 0x34, 0, 0, 0, 0, 0, 0],
        };
        let mut h = hello();
        let auth_key = seal_hello_at(&mut h, &params, 0x6655_4433).unwrap();

        let client_share = x25519_dalek::PublicKey::from(&h.key_shares.x25519);
        let shared = server_secret.diffie_hellman(&client_share);
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&h.random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut key)
            .unwrap();
        assert_eq!(key, auth_key);

        let mut session_id: [u8; 32] = h.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32]
            .try_into()
            .unwrap();
        let mut aad = h.raw.clone();
        aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].fill(0);
        let n = Aead::new(AeadKind::Aes256Gcm, &key)
            .open(&h.random[20..], &aad, &mut session_id)
            .unwrap();
        assert_eq!(n, 16);
        assert_eq!(&session_id[..4], &[26, 3, 27, 0]);
        assert_eq!(&session_id[4..8], &0x6655_4433u32.to_be_bytes());
        assert_eq!(&session_id[8..16], &params.short_id);
    }

    #[test]
    fn params_parsing() {
        let p =
            RealityParams::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "1a2b").unwrap();
        assert_eq!(p.public_key, [0u8; 32]);
        assert_eq!(p.short_id, [0x1a, 0x2b, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            RealityParams::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
                .unwrap()
                .short_id,
            [0u8; 8]
        );
        assert!(RealityParams::parse("short", "").is_err());
        assert!(
            RealityParams::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "abc").is_err()
        );
        assert!(RealityParams::parse(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "00112233445566778899"
        )
        .is_err());
    }

    /// Minimal Ed25519 certificate in the shape Go's x509 produces.
    fn fake_certificate(public_key: &[u8; 32], signature: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 0x80 {
                out.push(content.len() as u8);
            } else {
                out.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]);
            }
            out.extend_from_slice(content);
            out
        }
        let alg = tlv(TAG_SEQUENCE, OID_ED25519);
        let mut key_bits = vec![0u8];
        key_bits.extend_from_slice(public_key);
        let spki = tlv(
            TAG_SEQUENCE,
            &[alg.clone(), tlv(TAG_BIT_STRING, &key_bits)].concat(),
        );
        let tbs = tlv(
            TAG_SEQUENCE,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[0]),
                alg.clone(),
                tlv(TAG_SEQUENCE, &[]),
                tlv(TAG_SEQUENCE, &[]),
                tlv(TAG_SEQUENCE, &[]),
                spki,
            ]
            .concat(),
        );
        let mut sig_bits = vec![0u8];
        sig_bits.extend_from_slice(signature);
        tlv(
            TAG_SEQUENCE,
            &[tbs, alg, tlv(TAG_BIT_STRING, &sig_bits)].concat(),
        )
    }

    #[test]
    fn certificate_check_accepts_only_the_hmac_of_the_auth_key() {
        let auth_key = [9u8; 32];
        let public_key = [5u8; 32];
        let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).unwrap();
        mac.update(&public_key);
        let good = fake_certificate(&public_key, &mac.finalize().into_bytes());
        assert_eq!(verify_certificate(&good, &auth_key).unwrap(), public_key);
        assert!(verify_certificate(&good, &[8u8; 32]).is_err());
        assert!(verify_certificate(&fake_certificate(&public_key, &[0u8; 64]), &auth_key).is_err());
        assert!(verify_certificate(&good[..good.len() - 3], &auth_key).is_err());
        assert!(verify_certificate(b"not a certificate", &auth_key).is_err());
    }

    #[test]
    fn handshake_signature_is_checked_with_the_certificate_key() {
        use ed25519_dalek::Signer as _;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let sig = signing.sign(b"transcript").to_bytes();
        assert!(verify_handshake_signature(&public, 0x0807, b"transcript", &sig).is_ok());
        assert!(verify_handshake_signature(&public, 0x0807, b"other", &sig).is_err());
        assert!(verify_handshake_signature(&public, 0x0403, b"transcript", &sig).is_err());
    }
}
