//! Xray `geosite.dat` and `geoip.dat` files.
//!
//! Both are protobuf lists of `{country_code, entries}` (see Xray's
//! `app/router/config.proto`). Only the requested codes are decoded.

use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use parking_lot::Mutex;

use crate::domain::DomainSetBuilder;
use crate::ipset::IpSetBuilder;
use crate::protobuf::{Reader, Value};

const TYPE_PLAIN: u64 = 0;
const TYPE_REGEX: u64 = 1;
const TYPE_DOMAIN: u64 = 2;
const TYPE_FULL: u64 = 3;

/// A loaded `.dat` file with an index of its entries.
pub struct GeoFile {
    path: PathBuf,
    data: Vec<u8>,
    /// Upper-case country code → byte range of the entry message.
    index: HashMap<String, Range<usize>>,
}

impl GeoFile {
    pub fn load(path: &Path) -> Result<Self> {
        let data =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        Self::from_bytes(path.to_path_buf(), data)
    }

    pub fn from_bytes(path: PathBuf, data: Vec<u8>) -> Result<Self> {
        let mut index = HashMap::new();
        let mut list = Reader::new(&data);
        while let Some((field, value)) = list
            .next_field()
            .with_context(|| format!("{} is corrupt", path.display()))?
        {
            let (1, Value::Bytes(entry)) = (field, value) else {
                continue;
            };
            // `entry` borrows from `data`; its offset locates the message.
            let entry_start = entry.as_ptr() as usize - data.as_ptr() as usize;
            let mut fields = Reader::new(entry);
            while let Some((field, value)) = fields.next_field()? {
                if let (1, Value::Bytes(code)) = (field, value) {
                    let code = String::from_utf8_lossy(code).to_ascii_uppercase();
                    index
                        .entry(code)
                        .or_insert(entry_start..entry_start + entry.len());
                    break;
                }
            }
        }
        if index.is_empty() && !data.is_empty() {
            bail!("{} contains no entries", path.display());
        }
        Ok(Self { path, data, index })
    }

    fn entry(&self, code: &str) -> Result<&[u8]> {
        let range = self
            .index
            .get(&code.to_ascii_uppercase())
            .ok_or_else(|| anyhow!("`{code}` not found in {}", self.path.display()))?;
        Ok(&self.data[range.clone()])
    }

    pub fn codes(&self) -> impl Iterator<Item = &str> {
        self.index.keys().map(String::as_str)
    }

    /// Domains of `site`, keeping only those carrying every attribute in
    /// `attrs` (`geosite:google@ads`).
    pub fn site(&self, site: &str, attrs: &[String], out: &mut DomainSetBuilder) -> Result<usize> {
        let mut fields = Reader::new(self.entry(site)?);
        let mut count = 0;
        while let Some((field, value)) = fields.next_field()? {
            let (2, Value::Bytes(domain)) = (field, value) else {
                continue;
            };
            let (mut kind, mut text, mut keys) = (TYPE_PLAIN, "", Vec::new());
            let mut d = Reader::new(domain);
            while let Some((field, value)) = d.next_field()? {
                match (field, value) {
                    (1, Value::Varint(v)) => kind = v,
                    (2, Value::Bytes(v)) => {
                        text = std::str::from_utf8(v).context("domain is not UTF-8")?
                    }
                    (3, Value::Bytes(attr)) => {
                        let mut a = Reader::new(attr);
                        while let Some((field, value)) = a.next_field()? {
                            if let (1, Value::Bytes(k)) = (field, value) {
                                keys.push(String::from_utf8_lossy(k).into_owned());
                            }
                        }
                    }
                    _ => {}
                }
            }
            if !attrs.iter().all(|want| keys.iter().any(|k| k == want)) {
                continue;
            }
            match kind {
                TYPE_PLAIN => out.keyword(text),
                TYPE_REGEX => out.regex(text),
                TYPE_DOMAIN => out.suffix(text),
                TYPE_FULL => out.full(text),
                other => bail!("unknown domain type {other} in {}", self.path.display()),
            }
            count += 1;
        }
        Ok(count)
    }

    /// CIDRs of `code`.
    pub fn ip(&self, code: &str, out: &mut IpSetBuilder) -> Result<usize> {
        let mut fields = Reader::new(self.entry(code)?);
        let mut count = 0;
        while let Some((field, value)) = fields.next_field()? {
            let (2, Value::Bytes(cidr)) = (field, value) else {
                continue;
            };
            let (mut ip, mut prefix) = (&[][..], 0u64);
            let mut c = Reader::new(cidr);
            while let Some((field, value)) = c.next_field()? {
                match (field, value) {
                    (1, Value::Bytes(v)) => ip = v,
                    (2, Value::Varint(v)) => prefix = v,
                    _ => {}
                }
            }
            out.add_bytes(ip, prefix.min(128) as u8)
                .with_context(|| format!("bad CIDR in {}", self.path.display()))?;
            count += 1;
        }
        Ok(count)
    }
}

/// Process-wide cache so that several rules share one parsed file.
#[derive(Default)]
pub struct GeoCache {
    files: Mutex<HashMap<PathBuf, Arc<GeoFile>>>,
}

impl GeoCache {
    pub fn get(&self, path: &Path) -> Result<Arc<GeoFile>> {
        if let Some(f) = self.files.lock().get(path) {
            return Ok(f.clone());
        }
        let file = Arc::new(GeoFile::load(path)?);
        self.files.lock().insert(path.to_path_buf(), file.clone());
        Ok(file)
    }
}

/// Splits `google@ads@cn` into the site and its attribute filters.
pub fn split_site(spec: &str) -> (String, Vec<String>) {
    let mut parts = spec.split('@');
    let site = parts.next().unwrap_or("").trim().to_string();
    (
        site,
        parts
            .map(|a| a.trim().to_ascii_lowercase())
            .filter(|a| !a.is_empty())
            .collect(),
    )
}
