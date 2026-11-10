//! TLS 1.3 key schedule (RFC 8446, section 7.1).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use sybau_proto::crypto::{Aead, AeadKind};

pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

/// Parameters of a TLS 1.3 cipher suite.
#[derive(Clone, Copy, Debug)]
pub struct Suite {
    pub id: u16,
    pub hash: HashAlg,
    pub aead: AeadKind,
}

impl Suite {
    pub fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            TLS_AES_128_GCM_SHA256 => Suite {
                id,
                hash: HashAlg::Sha256,
                aead: AeadKind::Aes128Gcm,
            },
            TLS_AES_256_GCM_SHA384 => Suite {
                id,
                hash: HashAlg::Sha384,
                aead: AeadKind::Aes256Gcm,
            },
            TLS_CHACHA20_POLY1305_SHA256 => Suite {
                id,
                hash: HashAlg::Sha256,
                aead: AeadKind::ChaCha20Poly1305,
            },
            _ => return None,
        })
    }
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            HashAlg::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        }
    }

    fn expand(self, secret: &[u8], info: &[u8], out: &mut [u8]) {
        match self {
            HashAlg::Sha256 => Hkdf::<Sha256>::from_prk(secret)
                .expect("PRK length")
                .expand(info, out),
            HashAlg::Sha384 => Hkdf::<Sha384>::from_prk(secret)
                .expect("PRK length")
                .expand(info, out),
        }
        .expect("HKDF output length is valid");
    }

    /// `HKDF-Expand-Label(secret, label, context, len)`.
    pub fn expand_label(self, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(6 + label.len() as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        let mut out = vec![0u8; len];
        self.expand(secret, &info, &mut out);
        out
    }

    /// `Derive-Secret(secret, label, messages)` given the transcript hash.
    pub fn derive_secret(self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.output_len())
    }

    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => {
                let mut m =
                    Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashAlg::Sha384 => {
                let mut m =
                    Hmac::<Sha384>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// Running hash of the handshake messages.
#[derive(Clone)]
pub enum Transcript {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Transcript {
    pub fn new(alg: HashAlg) -> Self {
        match alg {
            HashAlg::Sha256 => Transcript::Sha256(Sha256::new()),
            HashAlg::Sha384 => Transcript::Sha384(Sha384::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Transcript::Sha256(h) => h.update(data),
            Transcript::Sha384(h) => h.update(data),
        }
    }

    /// Hash of everything added so far; the transcript keeps going.
    pub fn current(&self) -> Vec<u8> {
        match self {
            Transcript::Sha256(h) => h.clone().finalize().to_vec(),
            Transcript::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }
}

/// Keys of one direction of the record layer.
pub struct RecordKeys {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
    /// Traffic secret the keys came from, kept for KeyUpdate.
    secret: Vec<u8>,
    suite: Suite,
}

impl RecordKeys {
    pub fn new(suite: Suite, secret: &[u8]) -> Self {
        let key = suite
            .hash
            .expand_label(secret, "key", &[], suite.aead.key_len());
        let iv = suite.hash.expand_label(secret, "iv", &[], 12);
        Self {
            aead: Aead::new(suite.aead, &key),
            iv: iv.try_into().expect("12 bytes"),
            seq: 0,
            secret: secret.to_vec(),
            suite,
        }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        for (n, s) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        self.seq += 1;
        nonce
    }

    /// Appends one protected record carrying `payload` of `content_type`.
    pub fn seal_record(&mut self, content_type: u8, payload: &[u8], out: &mut bytes::BytesMut) {
        let len = payload.len() + 1 + 16;
        let header = [23, 3, 3, (len >> 8) as u8, len as u8];
        out.extend_from_slice(&header);
        let start = out.len();
        out.extend_from_slice(payload);
        out.extend_from_slice(&[content_type]);
        let nonce = self.nonce();
        let tag = self.aead.seal(&nonce, &header, &mut out[start..]);
        out.extend_from_slice(&tag);
    }

    /// Decrypts a record body in place. Returns the inner content type and
    /// the length of the content at the start of `body`.
    pub fn open_record(
        &mut self,
        header: &[u8; 5],
        body: &mut [u8],
    ) -> std::io::Result<(u8, usize)> {
        let nonce = self.nonce();
        let n = self.aead.open(&nonce, header, body)?;
        // Strip zero padding; the last non-zero byte is the content type.
        let mut end = n;
        while end > 0 && body[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(sybau_common::proto_err("TLS record without content type"));
        }
        Ok((body[end - 1], end - 1))
    }

    /// Moves to the next generation of keys (KeyUpdate).
    pub fn update(&mut self) {
        let next = self.suite.hash.expand_label(
            &self.secret,
            "traffic upd",
            &[],
            self.suite.hash.output_len(),
        );
        *self = RecordKeys::new(self.suite, &next);
    }
}

/// Secrets derived while the handshake progresses.
pub struct KeySchedule {
    pub suite: Suite,
    handshake_secret: Vec<u8>,
}

impl KeySchedule {
    /// Called after ServerHello with the (EC)DHE shared secret.
    pub fn new(suite: Suite, shared_secret: &[u8]) -> Self {
        let h = suite.hash;
        let zeros = vec![0u8; h.output_len()];
        let early = h.extract(&zeros, &zeros);
        let derived = h.derive_secret(&early, "derived", &h.hash(&[]));
        Self {
            suite,
            handshake_secret: h.extract(&derived, shared_secret),
        }
    }

    /// `(client, server)` handshake traffic secrets; `hash` covers
    /// ClientHello..ServerHello.
    pub fn handshake_secrets(&self, hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let h = self.suite.hash;
        (
            h.derive_secret(&self.handshake_secret, "c hs traffic", hash),
            h.derive_secret(&self.handshake_secret, "s hs traffic", hash),
        )
    }

    /// `(client, server)` application traffic secrets; `hash` covers
    /// ClientHello..server Finished.
    pub fn application_secrets(&self, hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let h = self.suite.hash;
        let derived = h.derive_secret(&self.handshake_secret, "derived", &h.hash(&[]));
        let master = h.extract(&derived, &vec![0u8; h.output_len()]);
        (
            h.derive_secret(&master, "c ap traffic", hash),
            h.derive_secret(&master, "s ap traffic", hash),
        )
    }

    /// `verify_data` of a Finished message.
    pub fn finished(&self, traffic_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        let h = self.suite.hash;
        let key = h.expand_label(traffic_secret, "finished", &[], h.output_len());
        h.hmac(&key, transcript_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8448 section 3 ("Simple 1-RTT Handshake") intermediate values.
    #[test]
    fn rfc8448_key_schedule() {
        let suite = Suite::from_id(TLS_AES_128_GCM_SHA256).unwrap();
        let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let ks = KeySchedule::new(suite, &shared);
        assert_eq!(
            ks.handshake_secret,
            hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        );

        let ch_sh = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let (c_hs, s_hs) = ks.handshake_secrets(&ch_sh);
        assert_eq!(
            c_hs,
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            s_hs,
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );

        let server = RecordKeys::new(suite, &s_hs);
        assert_eq!(server.iv.to_vec(), hex("5d313eb2671276ee13000b30"));

        let ch_sfin = hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
        let (c_ap, s_ap) = ks.application_secrets(&ch_sfin);
        assert_eq!(
            c_ap,
            hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );
        assert_eq!(
            s_ap,
            hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        );

        // Server Finished: hash of ClientHello..CertificateVerify.
        let upto_cv = hex("edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed");
        assert_eq!(
            ks.finished(&s_hs, &upto_cv),
            hex("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718")
        );
    }

    #[test]
    fn record_roundtrip_and_key_update() {
        let suite = Suite::from_id(TLS_CHACHA20_POLY1305_SHA256).unwrap();
        let secret = vec![7u8; 32];
        let (mut tx, mut rx) = (
            RecordKeys::new(suite, &secret),
            RecordKeys::new(suite, &secret),
        );
        for round in 0..3 {
            let mut wire = bytes::BytesMut::new();
            tx.seal_record(23, b"payload", &mut wire);
            let header: [u8; 5] = wire[..5].try_into().unwrap();
            let mut body = wire[5..].to_vec();
            let (ty, n) = rx.open_record(&header, &mut body).unwrap();
            assert_eq!((ty, &body[..n]), (23, &b"payload"[..]), "round {round}");
            tx.update();
            rx.update();
        }
        let mut wire = bytes::BytesMut::new();
        tx.seal_record(23, b"x", &mut wire);
        let header: [u8; 5] = wire[..5].try_into().unwrap();
        let mut body = wire[5..].to_vec();
        body[0] ^= 1;
        assert!(rx.open_record(&header, &mut body).is_err());
    }
}
