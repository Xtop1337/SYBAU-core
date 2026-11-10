//! Domain matching: exact names, suffixes, keywords and regular expressions.

use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use regex::RegexSet;

/// Normalises a domain for matching: lower case, no trailing dot.
pub fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

impl DomainSetBuilder {
    /// Number of patterns collected so far.
    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keyword.len() + self.regex.len()
    }
}

/// Collects patterns; [`build`](Self::build) turns them into a matcher.
#[derive(Default, Debug, Clone)]
pub struct DomainSetBuilder {
    full: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Vec<String>,
}

impl DomainSetBuilder {
    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
    }

    /// Exact match.
    pub fn full(&mut self, domain: &str) {
        self.full.push(normalize(domain));
    }

    /// `example.com` matches the domain and its subdomains;
    /// `.example.com` matches subdomains only.
    pub fn suffix(&mut self, suffix: &str) {
        self.suffix.push(normalize(suffix));
    }

    /// Substring match.
    pub fn keyword(&mut self, keyword: &str) {
        self.keyword.push(keyword.to_ascii_lowercase());
    }

    pub fn regex(&mut self, pattern: &str) {
        self.regex.push(pattern.to_string());
    }

    /// Exact match against the value as stored, without lower-casing.
    /// sing-box rule-sets compare case-sensitively; queries are always
    /// lower case, so an upper-case entry never matches, as in sing-box.
    pub fn full_raw(&mut self, domain: &str) {
        self.full.push(domain.to_string());
    }

    /// Suffix counterpart of [`full_raw`](Self::full_raw).
    pub fn suffix_raw(&mut self, suffix: &str) {
        self.suffix.push(suffix.to_string());
    }

    pub fn extend(&mut self, other: &DomainSetBuilder) {
        self.full.extend_from_slice(&other.full);
        self.suffix.extend_from_slice(&other.suffix);
        self.keyword.extend_from_slice(&other.keyword);
        self.regex.extend_from_slice(&other.regex);
    }

    pub fn build(self) -> Result<DomainSet> {
        let mut full: HashSet<String> = self.full.into_iter().collect();
        let mut suffix = HashSet::new();
        let mut any = false;
        for s in self.suffix {
            match s.strip_prefix('.') {
                // Subdomains only.
                Some(rest) if !rest.is_empty() => {
                    suffix.insert(rest.to_string());
                }
                // "." or "": every domain.
                Some(_) => any = true,
                None if s.is_empty() => any = true,
                None => {
                    full.insert(s.clone());
                    suffix.insert(s);
                }
            }
        }
        let keyword = if self.keyword.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&self.keyword).context("invalid domain keyword")?)
        };
        let regex = if self.regex.is_empty() {
            None
        } else {
            // Case-sensitive like Xray and sing-box; domains are matched
            // in lower case.
            let set = regex::RegexSetBuilder::new(&self.regex)
                .size_limit(32 << 20)
                .build()
                .context("invalid domain regex")?;
            Some(set)
        };
        Ok(DomainSet {
            full,
            suffix,
            any,
            keyword,
            regex,
        })
    }
}

/// Compiled set of domain patterns.
#[derive(Debug)]
pub struct DomainSet {
    full: HashSet<String>,
    /// A domain matches when one of its proper parents is in here.
    suffix: HashSet<String>,
    any: bool,
    keyword: Option<AhoCorasick>,
    regex: Option<RegexSet>,
}

impl DomainSet {
    /// `domain` must be normalised (see [`normalize`]).
    pub fn matches(&self, domain: &str) -> bool {
        if self.any || self.full.contains(domain) {
            return true;
        }
        if !self.suffix.is_empty() {
            let mut rest = domain;
            while let Some(dot) = rest.find('.') {
                rest = &rest[dot + 1..];
                if self.suffix.contains(rest) {
                    return true;
                }
            }
        }
        if self.keyword.as_ref().is_some_and(|k| k.is_match(domain)) {
            return true;
        }
        self.regex.as_ref().is_some_and(|r| r.is_match(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_suffix_keyword_regex() {
        let mut b = DomainSetBuilder::default();
        b.full("Exact.Example.com.");
        b.suffix("example.org");
        b.suffix(".sub-only.net");
        b.keyword("TRACKER");
        b.regex(r"^ad[0-9]+\.");
        let set = b.build().unwrap();

        assert!(set.matches("exact.example.com"));
        assert!(!set.matches("www.exact.example.com"));

        assert!(set.matches("example.org"));
        assert!(set.matches("a.b.example.org"));
        assert!(
            !set.matches("badexample.org"),
            "suffix matches on label boundaries only"
        );

        assert!(set.matches("x.sub-only.net"));
        assert!(!set.matches("sub-only.net"));

        assert!(set.matches("my-tracker.io"));
        assert!(set.matches("ad42.site.com"));
        assert!(set.matches(&normalize("AD7.Site.com")));
        assert!(!set.matches("bad42.site.com"));
        assert!(!set.matches("other.com"));
    }

    #[test]
    fn empty_and_catch_all() {
        assert!(!DomainSetBuilder::default()
            .build()
            .unwrap()
            .matches("a.com"));
        let mut b = DomainSetBuilder::default();
        b.suffix(".");
        assert!(b.build().unwrap().matches("anything.at.all"));
        let mut b = DomainSetBuilder::default();
        b.regex("(unclosed");
        assert!(b.build().is_err());
    }
}
