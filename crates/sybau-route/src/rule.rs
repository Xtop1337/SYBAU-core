//! Routing rules: an uncompiled description ([`RuleSpec`]) and the
//! compiled matcher ([`Rule`]).
//!
//! A default rule matches when every condition group that is present
//! matches, as in sing-box:
//!
//! ```text
//! (domain items || destination IP items || rule_set) &&
//! (port || port_range) && (source IP items) && (source port items) &&
//! network && protocol && inbound && user && process && ...
//! ```

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use parking_lot::RwLock;
use regex::RegexSet;

use crate::domain::{DomainSet, DomainSetBuilder};
use crate::ipset::{private_ranges, IpSet, IpSetBuilder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// Everything a rule can look at.
#[derive(Clone, Debug, Default)]
pub struct MatchContext<'a> {
    pub network: Option<Network>,
    /// Destination domain, lower case (target or sniffed).
    pub domain: Option<&'a str>,
    /// Destination addresses: the literal target or the resolved domain.
    pub dest_ips: &'a [IpAddr],
    pub dest_port: u16,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub inbound: &'a str,
    /// Sniffed protocol.
    pub protocol: Option<&'a str>,
    pub user: Option<&'a str>,
    /// Executable name and full path of the local process.
    pub process_name: Option<&'a str>,
    pub process_path: Option<&'a str>,
    /// Android package name.
    pub package_name: Option<&'a str>,
    /// DNS query type, for DNS rules.
    pub query_type: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalMode {
    And,
    Or,
}

/// IP condition item: a set, optionally negated (`geoip:!cn`).
#[derive(Clone, Debug, Default)]
pub struct IpItem {
    pub set: IpSetBuilder,
    pub negate: bool,
}

/// Uncompiled rule. Rule-sets are referenced by tag and resolved at
/// compile time.
#[derive(Clone, Debug, Default)]
pub struct RuleSpec {
    /// Some domain item was configured (even if it expanded to nothing).
    pub has_domain: bool,
    pub domain: DomainSetBuilder,
    pub dest_ip: Vec<IpItem>,
    pub source_ip: Vec<IpItem>,
    pub dest_port: Vec<(u16, u16)>,
    pub source_port: Vec<(u16, u16)>,
    pub network: Vec<Network>,
    pub protocol: Vec<String>,
    pub inbound: Vec<String>,
    pub user: Vec<String>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub process_path_regex: Vec<String>,
    pub package_name: Vec<String>,
    pub query_type: Vec<u16>,
    pub rule_set: Vec<String>,
    /// Conditions this implementation cannot evaluate (Wi-Fi SSID, …):
    /// the rule never matches, as on platforms without that information.
    pub unsupported: bool,
    pub invert: bool,
    pub logical: Option<(LogicalMode, Vec<RuleSpec>)>,
}

impl RuleSpec {
    pub fn private_ip() -> IpItem {
        IpItem {
            set: private_ranges(),
            negate: false,
        }
    }

    /// Whether evaluating the rule needs process information.
    pub fn needs_process(&self) -> bool {
        !self.process_name.is_empty()
            || !self.process_path.is_empty()
            || !self.process_path_regex.is_empty()
            || !self.package_name.is_empty()
            || self
                .logical
                .as_ref()
                .is_some_and(|(_, rules)| rules.iter().any(RuleSpec::needs_process))
    }
}

/// Parses `"1000:2000"`, `":100"`, `"100:"` (sing-box) or `"1000-2000"` (Xray).
pub fn parse_port_range(text: &str) -> Result<(u16, u16)> {
    let t = text.trim();
    let (a, b) = t
        .split_once(':')
        .or_else(|| t.split_once('-'))
        .unwrap_or((t, t));
    let parse = |s: &str, default: u16| -> Result<u16> {
        if s.trim().is_empty() {
            return Ok(default);
        }
        s.trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("bad port range `{text}`"))
    };
    let (from, to) = (parse(a, 0)?, parse(b, u16::MAX)?);
    if from > to {
        bail!("port range `{text}` is reversed");
    }
    Ok((from, to))
}

/// A named, replaceable list of rules (sing-box rule-set).
pub struct RuleSet {
    pub tag: String,
    rules: RwLock<Arc<Vec<Rule>>>,
}

impl RuleSet {
    pub fn new(tag: &str, rules: Vec<Rule>) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.to_string(),
            rules: RwLock::new(Arc::new(rules)),
        })
    }

    /// Swaps in a new version (remote rule-set update).
    pub fn replace(&self, rules: Vec<Rule>) {
        *self.rules.write() = Arc::new(rules);
    }

    pub fn len(&self) -> usize {
        self.rules.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn matches(&self, ctx: &MatchContext<'_>) -> bool {
        let rules = self.rules.read().clone();
        rules.iter().any(|r| r.matches(ctx))
    }
}

struct IpCond {
    set: IpSet,
    negate: bool,
}

impl IpCond {
    fn compile(items: Vec<IpItem>) -> Vec<IpCond> {
        // All positive plain items share one set.
        let mut positive = IpSetBuilder::default();
        let mut out = Vec::new();
        let mut any_positive = false;
        for item in items {
            if item.negate {
                out.push(IpCond {
                    set: item.set.build(),
                    negate: true,
                });
            } else {
                any_positive = true;
                positive.extend(&item.set);
            }
        }
        if any_positive {
            out.insert(
                0,
                IpCond {
                    set: positive.build(),
                    negate: false,
                },
            );
        }
        out
    }

    fn matches(&self, ip: IpAddr) -> bool {
        self.set.contains(ip) != self.negate
    }
}

fn port_in(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges.iter().any(|(a, b)| *a <= port && port <= *b)
}

fn eq_process_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

struct DefaultBody {
    has_domain: bool,
    domain: DomainSet,
    dest_ip: Vec<IpCond>,
    source_ip: Vec<IpCond>,
    dest_port: Vec<(u16, u16)>,
    source_port: Vec<(u16, u16)>,
    network: Vec<Network>,
    protocol: Vec<String>,
    inbound: Vec<String>,
    user: Vec<String>,
    process_name: Vec<String>,
    process_path: Vec<String>,
    process_path_regex: Option<RegexSet>,
    package_name: Vec<String>,
    query_type: Vec<u16>,
    rule_set: Vec<Arc<RuleSet>>,
    unsupported: bool,
}

enum Body {
    /// Boxed: a default rule is much larger than a logical one.
    Default(Box<DefaultBody>),
    Logical(LogicalMode, Vec<Rule>),
}

/// A compiled rule.
pub struct Rule {
    body: Body,
    invert: bool,
}

impl Rule {
    /// `lookup` resolves rule-set tags.
    pub fn compile(spec: RuleSpec, lookup: &dyn Fn(&str) -> Option<Arc<RuleSet>>) -> Result<Self> {
        let invert = spec.invert;
        if let Some((mode, rules)) = spec.logical {
            if rules.is_empty() {
                bail!("logical rule without rules");
            }
            let rules = rules
                .into_iter()
                .map(|r| Rule::compile(r, lookup))
                .collect::<Result<_>>()?;
            return Ok(Self {
                body: Body::Logical(mode, rules),
                invert,
            });
        }
        let rule_set = spec
            .rule_set
            .iter()
            .map(|tag| {
                lookup(tag).ok_or_else(|| anyhow::anyhow!("rule-set `{tag}` is not defined"))
            })
            .collect::<Result<_>>()?;
        let process_path_regex = if spec.process_path_regex.is_empty() {
            None
        } else {
            Some(RegexSet::new(&spec.process_path_regex)?)
        };
        Ok(Self {
            body: Body::Default(Box::new(DefaultBody {
                has_domain: spec.has_domain || !spec.domain.is_empty(),
                domain: spec.domain.build()?,
                dest_ip: IpCond::compile(spec.dest_ip),
                source_ip: IpCond::compile(spec.source_ip),
                dest_port: spec.dest_port,
                source_port: spec.source_port,
                network: spec.network,
                protocol: spec.protocol,
                inbound: spec.inbound,
                user: spec.user,
                process_name: spec.process_name,
                process_path: spec.process_path,
                process_path_regex,
                package_name: spec.package_name,
                query_type: spec.query_type,
                rule_set,
                unsupported: spec.unsupported,
            })),
            invert,
        })
    }

    pub fn matches(&self, ctx: &MatchContext<'_>) -> bool {
        self.matches_inner(ctx) != self.invert
    }

    fn matches_inner(&self, ctx: &MatchContext<'_>) -> bool {
        let Body::Default(body) = &self.body else {
            let Body::Logical(mode, rules) = &self.body else {
                unreachable!()
            };
            return match mode {
                LogicalMode::And => rules.iter().all(|r| r.matches(ctx)),
                LogicalMode::Or => rules.iter().any(|r| r.matches(ctx)),
            };
        };
        let DefaultBody {
            has_domain,
            domain,
            dest_ip,
            source_ip,
            dest_port,
            source_port,
            network,
            protocol,
            inbound,
            user,
            process_name,
            process_path,
            process_path_regex,
            package_name,
            query_type,
            rule_set,
            unsupported,
        } = &**body;
        if *unsupported {
            return false;
        }

        // Destination address group.
        if *has_domain || !dest_ip.is_empty() || !rule_set.is_empty() {
            let by_domain = *has_domain && ctx.domain.is_some_and(|d| domain.matches(d));
            let by_ip = !dest_ip.is_empty()
                && ctx
                    .dest_ips
                    .iter()
                    .any(|ip| dest_ip.iter().any(|c| c.matches(*ip)));
            let by_set = !rule_set.is_empty() && rule_set.iter().any(|s| s.matches(ctx));
            if !(by_domain || by_ip || by_set) {
                return false;
            }
        }
        if !dest_port.is_empty() && !port_in(dest_port, ctx.dest_port) {
            return false;
        }
        if !source_ip.is_empty()
            && !ctx
                .source_ip
                .is_some_and(|ip| source_ip.iter().any(|c| c.matches(ip)))
        {
            return false;
        }
        if !source_port.is_empty() && !ctx.source_port.is_some_and(|p| port_in(source_port, p)) {
            return false;
        }
        if !network.is_empty() && !ctx.network.is_some_and(|n| network.contains(&n)) {
            return false;
        }
        if !protocol.is_empty()
            && !ctx
                .protocol
                .is_some_and(|p| protocol.iter().any(|x| x == p))
        {
            return false;
        }
        if !inbound.is_empty() && !inbound.iter().any(|t| t == ctx.inbound) {
            return false;
        }
        if !user.is_empty() && !ctx.user.is_some_and(|u| user.iter().any(|x| x == u)) {
            return false;
        }
        if !process_name.is_empty() || !process_path.is_empty() || process_path_regex.is_some() {
            let by_name = ctx
                .process_name
                .is_some_and(|n| process_name.iter().any(|x| eq_process_name(x, n)));
            let by_path = ctx.process_path.is_some_and(|p| {
                process_path.iter().any(|x| eq_process_name(x, p))
                    || process_path_regex.as_ref().is_some_and(|r| r.is_match(p))
            });
            if !(by_name || by_path) {
                return false;
            }
        }
        if !package_name.is_empty()
            && !ctx
                .package_name
                .is_some_and(|p| package_name.iter().any(|x| x == p))
        {
            return false;
        }
        if !query_type.is_empty() && !ctx.query_type.is_some_and(|q| query_type.contains(&q)) {
            return false;
        }
        true
    }
}

#[cfg(test)]
// Specs are built field by field to keep each test readable.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<Arc<RuleSet>> {
        None
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(list: &[&str], negate: bool) -> IpItem {
        let mut set = IpSetBuilder::default();
        for c in list {
            set.add_cidr(c).unwrap();
        }
        IpItem { set, negate }
    }

    #[test]
    fn groups_are_or_inside_and_between() {
        let mut spec = RuleSpec::default();
        spec.domain.suffix("example.com");
        spec.dest_ip.push(cidr(&["10.0.0.0/8"], false));
        spec.dest_port = vec![(443, 443), (8000, 8999)];
        spec.network = vec![Network::Tcp];
        let rule = Rule::compile(spec, &none).unwrap();

        let base = MatchContext {
            network: Some(Network::Tcp),
            dest_port: 443,
            ..Default::default()
        };
        let ips = [ip("10.1.1.1")];
        assert!(rule.matches(&MatchContext {
            domain: Some("a.example.com"),
            ..base.clone()
        }));
        assert!(
            rule.matches(&MatchContext {
                dest_ips: &ips,
                ..base.clone()
            }),
            "IP alternative"
        );
        assert!(!rule.matches(&MatchContext {
            domain: Some("other.org"),
            ..base.clone()
        }));
        assert!(!rule.matches(&MatchContext {
            domain: Some("example.com"),
            dest_port: 80,
            ..base.clone()
        }));
        assert!(rule.matches(&MatchContext {
            domain: Some("example.com"),
            dest_port: 8080,
            ..base.clone()
        }));
        assert!(!rule.matches(&MatchContext {
            domain: Some("example.com"),
            network: Some(Network::Udp),
            ..base.clone()
        }));
    }

    #[test]
    fn negated_geoip_private_invert_and_logical() {
        let mut spec = RuleSpec::default();
        spec.dest_ip.push(cidr(&["5.0.0.0/8"], true));
        let not_ru = Rule::compile(spec, &none).unwrap();
        assert!(not_ru.matches(&MatchContext {
            dest_ips: &[ip("8.8.8.8")],
            ..Default::default()
        }));
        assert!(!not_ru.matches(&MatchContext {
            dest_ips: &[ip("5.1.1.1")],
            ..Default::default()
        }));
        assert!(!not_ru.matches(&MatchContext::default()), "no IP, no match");

        let mut spec = RuleSpec::default();
        spec.dest_ip.push(RuleSpec::private_ip());
        spec.invert = true;
        let public = Rule::compile(spec, &none).unwrap();
        assert!(public.matches(&MatchContext {
            dest_ips: &[ip("1.1.1.1")],
            ..Default::default()
        }));
        assert!(!public.matches(&MatchContext {
            dest_ips: &[ip("192.168.1.1")],
            ..Default::default()
        }));

        let mut a = RuleSpec::default();
        a.inbound = vec!["tun".into()];
        let mut b = RuleSpec::default();
        b.protocol = vec!["bittorrent".into()];
        let and = Rule::compile(
            RuleSpec {
                logical: Some((LogicalMode::And, vec![a.clone(), b.clone()])),
                ..Default::default()
            },
            &none,
        )
        .unwrap();
        let or = Rule::compile(
            RuleSpec {
                logical: Some((LogicalMode::Or, vec![a, b])),
                ..Default::default()
            },
            &none,
        )
        .unwrap();
        let ctx = MatchContext {
            inbound: "tun",
            protocol: Some("tls"),
            ..Default::default()
        };
        assert!(!and.matches(&ctx) && or.matches(&ctx));
    }

    #[test]
    fn process_source_user_and_rule_sets() {
        let mut spec = RuleSpec::default();
        spec.process_name = vec!["Discord.exe".into()];
        spec.process_path_regex = vec![r"(?i)\\steam\\".into()];
        let rule = Rule::compile(spec, &none).unwrap();
        assert!(rule.matches(&MatchContext {
            process_name: Some("Discord.exe"),
            ..Default::default()
        }));
        assert!(rule.matches(&MatchContext {
            process_path: Some(r"C:\Games\Steam\steam.exe"),
            ..Default::default()
        }));
        assert!(!rule.matches(&MatchContext {
            process_name: Some("chrome.exe"),
            ..Default::default()
        }));
        assert!(!rule.matches(&MatchContext::default()));

        let mut spec = RuleSpec::default();
        spec.source_ip.push(cidr(&["192.168.0.0/16"], false));
        spec.source_port = vec![parse_port_range("1000:").unwrap()];
        spec.user = vec!["alice".into()];
        let rule = Rule::compile(spec, &none).unwrap();
        let ok = MatchContext {
            source_ip: Some(ip("192.168.1.2")),
            source_port: Some(5000),
            user: Some("alice"),
            ..Default::default()
        };
        assert!(rule.matches(&ok));
        assert!(!rule.matches(&MatchContext {
            user: Some("bob"),
            ..ok.clone()
        }));
        assert!(!rule.matches(&MatchContext {
            source_port: Some(999),
            ..ok.clone()
        }));

        let mut inner = RuleSpec::default();
        inner.domain.keyword("ads");
        let set = RuleSet::new("ads", vec![Rule::compile(inner, &none).unwrap()]);
        let lookup = |tag: &str| (tag == "ads").then(|| set.clone());
        let rule = Rule::compile(
            RuleSpec {
                rule_set: vec!["ads".into()],
                ..Default::default()
            },
            &lookup,
        )
        .unwrap();
        assert!(rule.matches(&MatchContext {
            domain: Some("myads.net"),
            ..Default::default()
        }));
        set.replace(vec![]);
        assert!(
            !rule.matches(&MatchContext {
                domain: Some("myads.net"),
                ..Default::default()
            }),
            "updates are visible"
        );
        assert!(Rule::compile(
            RuleSpec {
                rule_set: vec!["missing".into()],
                ..Default::default()
            },
            &none
        )
        .is_err());
    }

    #[test]
    fn port_ranges() {
        assert_eq!(parse_port_range("1000:2000").unwrap(), (1000, 2000));
        assert_eq!(parse_port_range(":100").unwrap(), (0, 100));
        assert_eq!(parse_port_range("100:").unwrap(), (100, 65535));
        assert_eq!(parse_port_range("53").unwrap(), (53, 53));
        assert_eq!(parse_port_range("8000-9000").unwrap(), (8000, 9000));
        assert!(parse_port_range("9:1").is_err());
        assert!(parse_port_range("a:b").is_err());
    }
}
