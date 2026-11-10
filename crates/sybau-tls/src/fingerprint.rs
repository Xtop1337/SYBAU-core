//! ClientHello construction from uTLS-derived templates.
//!
//! `fingerprints.json` is produced by `tools/utls-dump` from the uTLS
//! revision that Xray uses. A template is one sampled ClientHello split
//! into cipher suites and extensions; building a hello replays it and
//! refreshes what must differ per connection: randoms, session id, key
//! shares, GREASE values, SNI, ECH GREASE payload and padding.

use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, Result};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use serde::Deserialize;

use crate::keyshare::KeyShares;

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_ALPN: u16 = 16;
pub const EXT_PADDING: u16 = 21;
pub const EXT_PRE_SHARED_KEY: u16 = 41;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_COOKIE: u16 = 44;
pub const EXT_KEY_SHARE: u16 = 51;
pub const EXT_ECH: u16 = 0xfe0d;

#[derive(Debug, Deserialize)]
struct TemplateExtension {
    id: u16,
    data: String,
}

#[derive(Debug, Deserialize)]
struct RawTemplate {
    name: String,
    utls: String,
    legacy_version: u16,
    session_id_len: usize,
    cipher_suites: Vec<u16>,
    compression: Vec<u8>,
    extensions: Vec<TemplateExtension>,
    shuffle: bool,
    supports_tls13: bool,
    sample: String,
}

/// One browser fingerprint.
#[derive(Debug)]
pub struct Template {
    pub name: String,
    /// uTLS identifier the template was sampled from, e.g. `Chrome-133`.
    pub utls: String,
    pub legacy_version: u16,
    pub session_id_len: usize,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<(u16, Vec<u8>)>,
    /// Extension order is randomised per connection (Chrome 106+).
    pub shuffle: bool,
    pub supports_tls13: bool,
    /// The sampled ClientHello, kept for tests.
    pub sample: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex in fingerprints.json")
        })
        .collect()
}

fn templates() -> &'static [Arc<Template>] {
    static ALL: OnceLock<Vec<Arc<Template>>> = OnceLock::new();
    ALL.get_or_init(|| {
        let raw: Vec<RawTemplate> = serde_json::from_str(include_str!("fingerprints.json"))
            .expect("fingerprints.json is valid");
        raw.into_iter()
            .map(|t| {
                Arc::new(Template {
                    name: t.name,
                    utls: t.utls,
                    legacy_version: t.legacy_version,
                    session_id_len: t.session_id_len,
                    cipher_suites: t.cipher_suites,
                    compression: t.compression,
                    extensions: t
                        .extensions
                        .iter()
                        .map(|e| (e.id, unhex(&e.data)))
                        .collect(),
                    shuffle: t.shuffle,
                    supports_tls13: t.supports_tls13,
                    sample: unhex(&t.sample),
                })
            })
            .collect()
    })
}

/// Names accepted by [`Fingerprint::by_name`], presets first.
pub fn names() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = templates().iter().map(|t| t.name.as_str()).collect();
    v.extend(["random", "randomized"]);
    v
}

pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn random_grease(rng: &mut impl Rng) -> u16 {
    let n = rng.gen_range(0..16u16);
    (n << 12) | 0x0a00 | (n << 4) | 0x0a
}

/// A fingerprint chosen from the config.
#[derive(Clone, Debug)]
pub struct Fingerprint {
    template: Arc<Template>,
    /// Extra per-connection randomisation (`randomized`).
    randomize: bool,
}

impl Fingerprint {
    /// Resolves a name as Xray does: browser presets (`chrome`, `firefox`,
    /// `safari`, `ios`, `android`, `edge`, `360`, `qq`), `random` (one
    /// modern browser picked once per process) and `randomized`.
    pub fn by_name(name: &str) -> Result<Self> {
        let key = name.to_ascii_lowercase();
        let all = templates();
        match key.as_str() {
            "random" => {
                static PICK: OnceLock<usize> = OnceLock::new();
                let modern: Vec<usize> = all
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| t.supports_tls13)
                    .map(|(i, _)| i)
                    .collect();
                let pick = *PICK.get_or_init(|| {
                    *modern
                        .choose(&mut rand::thread_rng())
                        .expect("templates exist")
                });
                Ok(Self {
                    template: all[pick].clone(),
                    randomize: false,
                })
            }
            "randomized" => {
                let base = all
                    .iter()
                    .find(|t| t.name == "chrome")
                    .expect("chrome template exists");
                Ok(Self {
                    template: base.clone(),
                    randomize: true,
                })
            }
            _ => all
                .iter()
                .find(|t| t.name == key)
                .map(|t| Self {
                    template: t.clone(),
                    randomize: false,
                })
                .ok_or_else(|| {
                    anyhow!(
                        "unknown TLS fingerprint `{name}` (known: {})",
                        names().join(", ")
                    )
                }),
        }
    }

    pub fn template(&self) -> &Template {
        &self.template
    }

    /// Fails for fingerprints that only offer TLS 1.2.
    pub fn require_tls13(&self) -> Result<()> {
        if !self.template.supports_tls13 {
            bail!(
                "TLS fingerprint `{}` ({}) offers only TLS 1.2, which this client does not implement yet",
                self.template.name,
                self.template.utls
            );
        }
        Ok(())
    }
}

/// What the caller wants in the hello besides the fingerprint.
#[derive(Clone, Debug, Default)]
pub struct HelloParams {
    /// SNI; omitted from the hello when empty (IP literal targets).
    pub server_name: String,
    /// Replaces the protocols of the template's ALPN extension.
    pub alpn: Option<Vec<String>>,
}

/// A built ClientHello together with the secrets behind it.
pub struct ClientHello {
    /// Handshake message: `type(1) | length(3) | body`.
    pub raw: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub key_shares: KeyShares,
    /// Cipher suites offered, without GREASE.
    pub cipher_suites: Vec<u16>,
    /// Groups a `key_share` was sent for, without GREASE.
    pub shared_groups: Vec<u16>,
    /// Groups listed in `supported_groups`, without GREASE.
    pub supported_groups: Vec<u16>,
    /// Certificate compression algorithms offered.
    pub cert_compression: Vec<u16>,
    order: Vec<usize>,
    grease: Grease,
    ech: Option<Vec<u8>>,
}

/// Offset of the session id inside [`ClientHello::raw`]:
/// handshake header (4) + version (2) + random (32) + length byte (1).
pub const SESSION_ID_OFFSET: usize = 39;

#[derive(Clone, Copy)]
struct Grease {
    cipher: u16,
    group: u16,
    extension1: u16,
    extension2: u16,
    version: u16,
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn sni_data(name: &str) -> Vec<u8> {
    let mut d = Vec::with_capacity(name.len() + 5);
    put_u16(&mut d, name.len() as u16 + 3);
    d.push(0);
    put_u16(&mut d, name.len() as u16);
    d.extend_from_slice(name.as_bytes());
    d
}

fn alpn_data(protocols: &[String]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        list.push(p.len() as u8);
        list.extend_from_slice(p.as_bytes());
    }
    let mut d = Vec::with_capacity(list.len() + 2);
    put_u16(&mut d, list.len() as u16);
    d.extend_from_slice(&list);
    d
}

/// BoringSSL's rule: hellos between 256 and 511 bytes are padded to 512.
fn boring_padding(unpadded_len: usize) -> Option<usize> {
    if unpadded_len > 0xff && unpadded_len < 0x200 {
        let padding = 0x200 - unpadded_len;
        Some(if padding >= 5 { padding - 4 } else { 1 })
    } else {
        None
    }
}

/// Fresh GREASE ECH payload with the layout of the sampled one:
/// `type(1) kdf(2) aead(2) config_id(1) enc<2> payload<2>`.
fn randomize_ech(sample: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut out = sample.to_vec();
    if out.len() < 8 {
        return out;
    }
    out[5] = rng.gen();
    let enc_len = u16::from_be_bytes([out[6], out[7]]) as usize;
    let enc_end = 8 + enc_len;
    if out.len() < enc_end + 2 {
        return out;
    }
    rng.fill_bytes(&mut out[8..enc_end]);
    rng.fill_bytes(&mut out[enc_end + 2..]);
    out
}

impl ClientHello {
    pub fn build(fp: &Fingerprint, params: &HelloParams) -> Self {
        let mut rng = rand::thread_rng();
        let t = &*fp.template;

        let extension1 = random_grease(&mut rng);
        let mut extension2 = random_grease(&mut rng);
        if extension2 == extension1 {
            extension2 ^= 0x1010;
        }
        let grease = Grease {
            cipher: random_grease(&mut rng),
            group: random_grease(&mut rng),
            extension1,
            extension2,
            version: random_grease(&mut rng),
        };

        // Extension order. GREASE, padding and pre_shared_key keep their
        // positions when a fingerprint shuffles (same rule as uTLS).
        let mut order: Vec<usize> = (0..t.extensions.len()).collect();
        if t.shuffle || fp.randomize {
            let fixed = |i: usize| {
                let id = t.extensions[i].0;
                is_grease(id) || id == EXT_PADDING || id == EXT_PRE_SHARED_KEY
            };
            let movable: Vec<usize> = order.iter().copied().filter(|i| !fixed(*i)).collect();
            let mut shuffled = movable.clone();
            shuffled.shuffle(&mut rng);
            let mut next = shuffled.into_iter();
            for slot in order.iter_mut() {
                if !fixed(*slot) {
                    *slot = next.next().expect("same number of movable extensions");
                }
            }
        }

        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        let mut session_id = vec![0u8; t.session_id_len];
        rng.fill_bytes(&mut session_id);
        let ech = t
            .extensions
            .iter()
            .find(|(id, _)| *id == EXT_ECH)
            .map(|(_, d)| randomize_ech(d, &mut rng));

        let mut hello = Self {
            raw: Vec::new(),
            random,
            session_id,
            key_shares: KeyShares::new(),
            cipher_suites: t
                .cipher_suites
                .iter()
                .copied()
                .filter(|c| !is_grease(*c))
                .collect(),
            shared_groups: Vec::new(),
            supported_groups: Vec::new(),
            cert_compression: Vec::new(),
            order,
            grease,
            ech,
        };
        hello.encode(t, params, None, None);
        hello
    }

    /// Rebuilds the hello after a HelloRetryRequest: the `key_share`
    /// holds only `group`, and the server's cookie is echoed.
    pub fn rebuild_for_retry(
        &mut self,
        fp: &Fingerprint,
        params: &HelloParams,
        group: u16,
        cookie: Option<&[u8]>,
    ) {
        self.encode(&fp.template, params, Some(group), cookie);
    }

    fn encode(
        &mut self,
        t: &Template,
        params: &HelloParams,
        only_group: Option<u16>,
        cookie: Option<&[u8]>,
    ) {
        let g = self.grease;
        let mut extensions: Vec<(u16, Vec<u8>)> = Vec::with_capacity(t.extensions.len() + 1);
        let mut grease_seen = 0;
        let mut padding_index = None;
        self.shared_groups.clear();
        self.supported_groups.clear();
        self.cert_compression.clear();

        for &index in &self.order {
            let (id, data) = &t.extensions[index];
            let (id, data) = (*id, data.as_slice());
            if is_grease(id) {
                grease_seen += 1;
                extensions.push((
                    if grease_seen == 1 {
                        g.extension1
                    } else {
                        g.extension2
                    },
                    data.to_vec(),
                ));
                continue;
            }
            match id {
                EXT_SERVER_NAME => {
                    if !params.server_name.is_empty() {
                        extensions.push((id, sni_data(&params.server_name)));
                    }
                }
                EXT_SUPPORTED_GROUPS => {
                    let mut d = data.to_vec();
                    for pair in d[2..].as_chunks_mut::<2>().0 {
                        let v = u16::from_be_bytes([pair[0], pair[1]]);
                        if is_grease(v) {
                            pair.copy_from_slice(&g.group.to_be_bytes());
                        } else {
                            self.supported_groups.push(v);
                        }
                    }
                    extensions.push((id, d));
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut d = data.to_vec();
                    for pair in d[1..].as_chunks_mut::<2>().0 {
                        if is_grease(u16::from_be_bytes([pair[0], pair[1]])) {
                            pair.copy_from_slice(&g.version.to_be_bytes());
                        }
                    }
                    extensions.push((id, d));
                }
                EXT_KEY_SHARE => {
                    let mut entries = Vec::new();
                    let mut rest = &data[2..];
                    while rest.len() >= 4 {
                        let group = u16::from_be_bytes([rest[0], rest[1]]);
                        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
                        let sample = &rest[4..4 + len];
                        rest = &rest[4 + len..];
                        if let Some(only) = only_group {
                            if group != only {
                                continue;
                            }
                        }
                        let key = if is_grease(group) {
                            put_u16(&mut entries, g.group);
                            sample.to_vec()
                        } else {
                            match self.key_shares.public(group) {
                                Some(key) => {
                                    put_u16(&mut entries, group);
                                    self.shared_groups.push(group);
                                    key
                                }
                                // A group we cannot compute is left out
                                // rather than sent with a bogus key.
                                None => continue,
                            }
                        };
                        put_u16(&mut entries, key.len() as u16);
                        entries.extend_from_slice(&key);
                    }
                    if let Some(only) = only_group {
                        if entries.is_empty() {
                            if let Some(key) = self.key_shares.public(only) {
                                put_u16(&mut entries, only);
                                put_u16(&mut entries, key.len() as u16);
                                entries.extend_from_slice(&key);
                                self.shared_groups.push(only);
                            }
                        }
                    }
                    let mut d = Vec::with_capacity(entries.len() + 2);
                    put_u16(&mut d, entries.len() as u16);
                    d.extend_from_slice(&entries);
                    extensions.push((id, d));
                    if let Some(cookie) = cookie {
                        let mut c = Vec::with_capacity(cookie.len() + 2);
                        put_u16(&mut c, cookie.len() as u16);
                        c.extend_from_slice(cookie);
                        extensions.push((EXT_COOKIE, c));
                    }
                }
                EXT_ALPN => match &params.alpn {
                    Some(protocols) => extensions.push((id, alpn_data(protocols))),
                    None => extensions.push((id, data.to_vec())),
                },
                EXT_ECH => extensions.push((id, self.ech.clone().unwrap_or_else(|| data.to_vec()))),
                EXT_PADDING => padding_index = Some(extensions.len()),
                EXT_PRE_SHARED_KEY => {}
                27 => {
                    for pair in data[1..].as_chunks::<2>().0 {
                        self.cert_compression
                            .push(u16::from_be_bytes([pair[0], pair[1]]));
                    }
                    extensions.push((id, data.to_vec()));
                }
                _ => extensions.push((id, data.to_vec())),
            }
        }

        let assemble = |extensions: &[(u16, Vec<u8>)], hello: &Self| -> Vec<u8> {
            let mut body = Vec::with_capacity(2048);
            put_u16(&mut body, t.legacy_version);
            body.extend_from_slice(&hello.random);
            body.push(hello.session_id.len() as u8);
            body.extend_from_slice(&hello.session_id);
            put_u16(&mut body, 2 * t.cipher_suites.len() as u16);
            for c in &t.cipher_suites {
                put_u16(&mut body, if is_grease(*c) { g.cipher } else { *c });
            }
            body.push(t.compression.len() as u8);
            body.extend_from_slice(&t.compression);
            let ext_len: usize = extensions.iter().map(|(_, d)| 4 + d.len()).sum();
            put_u16(&mut body, ext_len as u16);
            for (id, data) in extensions {
                put_u16(&mut body, *id);
                put_u16(&mut body, data.len() as u16);
                body.extend_from_slice(data);
            }
            let mut raw = Vec::with_capacity(body.len() + 4);
            raw.push(1);
            raw.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            raw.extend_from_slice(&body);
            raw
        };

        let mut raw = assemble(&extensions, self);
        if let Some(index) = padding_index {
            if let Some(len) = boring_padding(raw.len()) {
                extensions.insert(index, (EXT_PADDING, vec![0u8; len]));
                raw = assemble(&extensions, self);
            }
        }
        self.raw = raw;
    }

    /// Overwrites the session id (REALITY stores its token there).
    pub fn set_session_id(&mut self, id: &[u8]) {
        assert_eq!(
            id.len(),
            self.session_id.len(),
            "session id length is part of the fingerprint"
        );
        self.session_id.copy_from_slice(id);
        self.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + id.len()].copy_from_slice(id);
    }
}

/// Structure of a ClientHello, for comparing fingerprints.
#[derive(Debug, PartialEq, Eq)]
pub struct HelloShape {
    pub legacy_version: u16,
    pub session_id_len: usize,
    /// Cipher suites with GREASE values normalised to `0x0a0a`.
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    /// Extension ids (GREASE normalised) and their data lengths.
    pub extensions: Vec<(u16, usize)>,
    pub total_len: usize,
}

/// Parses a ClientHello handshake message into its shape.
pub fn shape(raw: &[u8]) -> Option<HelloShape> {
    let norm = |v: u16| if is_grease(v) { 0x0a0a } else { v };
    let body = raw.get(4..)?;
    let legacy_version = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    let mut pos = 34;
    let sid_len = *body.get(pos)? as usize;
    pos += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let cipher_suites = body
        .get(pos..pos + cs_len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| norm(u16::from_be_bytes([p[0], p[1]])))
        .collect();
    pos += cs_len;
    let comp_len = *body.get(pos)? as usize;
    let compression = body.get(pos + 1..pos + 1 + comp_len)?.to_vec();
    pos += 1 + comp_len;
    let ext_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let mut rest = body.get(pos..pos + ext_len)?;
    let mut extensions = Vec::new();
    while rest.len() >= 4 {
        let id = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        extensions.push((norm(id), len));
        rest = rest.get(4 + len..)?;
    }
    Some(HelloShape {
        legacy_version,
        session_id_len: sid_len,
        cipher_suites,
        compression,
        extensions,
        total_len: raw.len(),
    })
}

/// Returns the data of extension `id` in a ClientHello handshake message.
pub fn extension_data(raw: &[u8], id: u16) -> Option<&[u8]> {
    let body = raw.get(4..)?;
    let mut pos = 34;
    pos += 1 + *body.get(pos)? as usize;
    pos += 2 + u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 1 + *body.get(pos)? as usize;
    let ext_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    let mut rest = body.get(pos + 2..pos + 2 + ext_len)?;
    while rest.len() >= 4 {
        let ext = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if ext == id {
            return rest.get(4..4 + len);
        }
        rest = rest.get(4 + len..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SNI: &str = "example.com";

    fn params() -> HelloParams {
        HelloParams {
            server_name: SAMPLE_SNI.into(),
            alpn: None,
        }
    }

    /// Every template, rebuilt with the SNI it was sampled with, has
    /// exactly the structure uTLS produced: same suites, same extensions
    /// with the same lengths (in the same order unless the browser
    /// shuffles), same total size.
    #[test]
    fn rebuilt_hellos_match_utls_samples() {
        for t in templates() {
            let fp = Fingerprint {
                template: t.clone(),
                randomize: false,
            };
            let sample = shape(&t.sample).unwrap();
            for _ in 0..4 {
                let hello = ClientHello::build(&fp, &params());
                let mut built = shape(&hello.raw).unwrap();
                let mut expect = HelloShape {
                    extensions: sample.extensions.clone(),
                    ..shape(&t.sample).unwrap()
                };
                if t.shuffle {
                    built.extensions.sort();
                    expect.extensions.sort();
                }
                assert_eq!(built, expect, "fingerprint {}", t.name);
            }
        }
    }

    /// Extensions without per-connection content are byte-identical to
    /// the uTLS sample.
    #[test]
    fn static_extensions_are_copied_verbatim() {
        for t in templates() {
            let fp = Fingerprint {
                template: t.clone(),
                randomize: false,
            };
            let hello = ClientHello::build(&fp, &params());
            for (id, data) in &t.extensions {
                let dynamic = is_grease(*id)
                    || matches!(
                        *id,
                        EXT_SUPPORTED_GROUPS
                            | EXT_SUPPORTED_VERSIONS
                            | EXT_KEY_SHARE
                            | EXT_ECH
                            | EXT_PADDING
                    );
                if dynamic {
                    continue;
                }
                assert_eq!(
                    extension_data(&hello.raw, *id),
                    Some(data.as_slice()),
                    "{} extension {id}",
                    t.name
                );
            }
        }
    }

    #[test]
    fn per_connection_parts_are_fresh_and_consistent() {
        let fp = Fingerprint::by_name("chrome").unwrap();
        let a = ClientHello::build(&fp, &params());
        let b = ClientHello::build(&fp, &params());
        assert_ne!(a.random, b.random);
        assert_ne!(a.session_id, b.session_id);
        assert_ne!(
            extension_data(&a.raw, EXT_KEY_SHARE),
            extension_data(&b.raw, EXT_KEY_SHARE)
        );
        assert_ne!(
            extension_data(&a.raw, EXT_ECH),
            extension_data(&b.raw, EXT_ECH)
        );
        assert_eq!(&a.raw[6..38], &a.random);
        assert_eq!(
            &a.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
            &a.session_id[..]
        );
        assert_eq!(
            a.shared_groups,
            vec![
                crate::keyshare::GROUP_X25519_MLKEM768,
                crate::keyshare::GROUP_X25519
            ]
        );
        assert_eq!(a.cert_compression, vec![2]);

        // The GREASE group is the same in supported_groups and key_share.
        let groups = extension_data(&a.raw, EXT_SUPPORTED_GROUPS).unwrap();
        let shares = extension_data(&a.raw, EXT_KEY_SHARE).unwrap();
        assert!(is_grease(u16::from_be_bytes([groups[2], groups[3]])));
        assert_eq!(&groups[2..4], &shares[2..4]);

        // The X25519 share is the public key of the stored secret.
        let x = x25519_dalek::PublicKey::from(&a.key_shares.x25519);
        assert_eq!(&shares[shares.len() - 32..], x.as_bytes());
    }

    #[test]
    fn chrome_shuffles_but_firefox_does_not() {
        let order = |name: &str| {
            let fp = Fingerprint::by_name(name).unwrap();
            let h = ClientHello::build(&fp, &params());
            shape(&h.raw)
                .unwrap()
                .extensions
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        };
        assert!((0..20).any(|_| order("chrome") != order("chrome")));
        assert!((0..20).all(|_| order("firefox") == order("firefox")));
        let chrome = order("chrome");
        assert_eq!(
            (chrome[0], *chrome.last().unwrap()),
            (0x0a0a, 0x0a0a),
            "GREASE stays first and last"
        );
    }

    #[test]
    fn sni_alpn_padding_and_session_id() {
        let fp = Fingerprint::by_name("edge").unwrap();
        // Padding keeps 256..511-byte hellos at exactly 512 bytes.
        for name in ["a.io", "example.com", "a-rather-long-host-name.example.org"] {
            let h = ClientHello::build(
                &fp,
                &HelloParams {
                    server_name: name.into(),
                    alpn: None,
                },
            );
            assert_eq!(h.raw.len(), 512, "{name}");
            assert_eq!(
                extension_data(&h.raw, EXT_SERVER_NAME).unwrap()[5..],
                *name.as_bytes()
            );
        }
        // IP targets: no SNI extension at all.
        let h = ClientHello::build(&fp, &HelloParams::default());
        assert!(extension_data(&h.raw, EXT_SERVER_NAME).is_none());

        let mut h = ClientHello::build(
            &fp,
            &HelloParams {
                server_name: "x.y".into(),
                alpn: Some(vec!["http/1.1".into()]),
            },
        );
        assert_eq!(
            extension_data(&h.raw, EXT_ALPN).unwrap(),
            &[0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );
        h.set_session_id(&[0xee; 32]);
        assert_eq!(
            &h.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
            &[0xee; 32]
        );
    }

    #[test]
    fn retry_keeps_identity_and_narrows_key_share() {
        let fp = Fingerprint::by_name("firefox").unwrap();
        let mut h = ClientHello::build(&fp, &params());
        let (random, sid) = (h.random, h.session_id.clone());
        h.rebuild_for_retry(
            &fp,
            &params(),
            crate::keyshare::GROUP_SECP256R1,
            Some(b"cookie"),
        );
        assert_eq!((h.random, &h.session_id), (random, &sid));
        assert_eq!(h.shared_groups, vec![crate::keyshare::GROUP_SECP256R1]);
        let shares = extension_data(&h.raw, EXT_KEY_SHARE).unwrap();
        assert_eq!(shares.len(), 2 + 4 + 65);
        assert_eq!(
            extension_data(&h.raw, EXT_COOKIE).unwrap(),
            b"\x00\x06cookie"
        );
    }

    #[test]
    fn names_resolve_like_xray() {
        for name in [
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
            "Chrome",
        ] {
            assert!(Fingerprint::by_name(name).is_ok(), "{name}");
        }
        assert!(Fingerprint::by_name("netscape").is_err());
        assert!(Fingerprint::by_name("360")
            .unwrap()
            .require_tls13()
            .is_err());
        assert!(Fingerprint::by_name("random")
            .unwrap()
            .require_tls13()
            .is_ok());
        assert_eq!(
            Fingerprint::by_name("chrome").unwrap().template().utls,
            "Chrome-133"
        );
    }
}
