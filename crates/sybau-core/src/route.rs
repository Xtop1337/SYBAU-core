//! Turns the `route` section into a [`Router`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use sybau_config::route::{HeadlessRule, RuleSetConfig, RuleSetSource};
use sybau_config::RouteConfig;
use sybau_route::domain::DomainSetBuilder;
use sybau_route::geodata::{split_site, GeoCache, GeoFile};
use sybau_route::ipset::IpSetBuilder;
use sybau_route::rule::{
    parse_port_range, IpItem, LogicalMode, MatchContext, Network, Rule, RuleSet, RuleSpec,
};

/// What to do with traffic that matched a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Route(Arc<str>),
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainStrategy {
    /// IP rules only see IP targets.
    AsIs,
    /// Resolve domain targets when no rule matched them by domain.
    IpIfNonMatch,
    /// Resolve domain targets before matching.
    IpOnDemand,
}

/// Where geo files and relative rule-set paths are looked up.
#[derive(Clone, Debug, Default)]
pub struct Assets {
    pub dirs: Vec<PathBuf>,
}

impl Assets {
    /// Config directory, executable directory, `SYBAU_ASSET_DIR`,
    /// `XRAY_LOCATION_ASSET` and the working directory, in this order.
    pub fn standard(config_path: Option<&Path>) -> Self {
        let mut dirs = Vec::new();
        if let Some(dir) = config_path.and_then(Path::parent) {
            dirs.push(if dir.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                dir.to_path_buf()
            });
        }
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
        {
            dirs.push(dir);
        }
        for var in ["SYBAU_ASSET_DIR", "XRAY_LOCATION_ASSET"] {
            if let Some(dir) = std::env::var_os(var) {
                dirs.push(PathBuf::from(dir));
            }
        }
        dirs.push(PathBuf::from("."));
        Self { dirs }
    }

    pub fn find(&self, name: &str) -> Result<PathBuf> {
        let p = Path::new(name);
        if p.is_absolute() {
            return Ok(p.to_path_buf());
        }
        self.dirs
            .iter()
            .map(|d| d.join(name))
            .find(|c| c.is_file())
            .ok_or_else(|| {
                anyhow!(
                    "`{name}` not found in {}",
                    self.dirs
                        .iter()
                        .map(|d| d.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}

/// Converts config rules to rule specifications.
struct SpecBuilder<'a> {
    assets: &'a Assets,
    geo: &'a GeoCache,
    geosite: Option<String>,
    geoip: Option<String>,
}

impl SpecBuilder<'_> {
    fn geo_file(&self, configured: &Option<String>, default: &str) -> Result<Arc<GeoFile>> {
        let name = configured.as_deref().unwrap_or(default);
        self.geo.get(&self.assets.find(name)?)
    }

    /// `cn`, `google@ads` or `ext:file.dat:tag`.
    fn geosite(&self, spec: &str, out: &mut DomainSetBuilder) -> Result<()> {
        let (file, site) = match spec
            .strip_prefix("ext:")
            .or_else(|| spec.strip_prefix("ext-domain:"))
        {
            Some(rest) => {
                let (file, site) = rest
                    .split_once(':')
                    .ok_or_else(|| anyhow!("bad geosite `{spec}`"))?;
                (self.geo.get(&self.assets.find(file)?)?, site)
            }
            None => (self.geo_file(&self.geosite, "geosite.dat")?, spec),
        };
        let (site, attrs) = split_site(site);
        file.site(&site, &attrs, out)
            .with_context(|| format!("geosite `{spec}`"))?;
        Ok(())
    }

    /// `ru`, `!cn`, `private` or `ext:file.dat:tag`.
    fn geoip(&self, spec: &str) -> Result<IpItem> {
        let (file, code) = match spec
            .strip_prefix("ext:")
            .or_else(|| spec.strip_prefix("ext-ip:"))
        {
            Some(rest) => {
                let (file, code) = rest
                    .split_once(':')
                    .ok_or_else(|| anyhow!("bad geoip `{spec}`"))?;
                (Some(file), code)
            }
            None => (None, spec),
        };
        let (negate, code) = match code.strip_prefix('!') {
            Some(c) => (true, c),
            None => (false, code),
        };
        let file = match file {
            Some(f) => Some(self.geo.get(&self.assets.find(f)?)?),
            None => match self.geo_file(&self.geoip, "geoip.dat") {
                Ok(f) => Some(f),
                // Without geoip.dat, `private` still works from built-in ranges.
                Err(_) if code.eq_ignore_ascii_case("private") => None,
                Err(e) => return Err(e),
            },
        };
        let mut set = IpSetBuilder::default();
        match file {
            Some(f) if f.codes().any(|c| c.eq_ignore_ascii_case(code)) => {
                f.ip(code, &mut set)?;
            }
            _ if code.eq_ignore_ascii_case("private") => set = sybau_route::ipset::private_ranges(),
            Some(f) => {
                f.ip(code, &mut set)
                    .with_context(|| format!("geoip `{spec}`"))?;
            }
            None => unreachable!("handled above"),
        }
        Ok(IpItem { set, negate })
    }

    fn cidrs(&self, list: &[String]) -> Result<Option<IpItem>> {
        if list.is_empty() {
            return Ok(None);
        }
        let mut set = IpSetBuilder::default();
        for c in list {
            set.add_cidr(c)?;
        }
        Ok(Some(IpItem { set, negate: false }))
    }

    fn spec(&self, r: &HeadlessRule) -> Result<RuleSpec> {
        let mut s = RuleSpec {
            invert: r.invert,
            ..Default::default()
        };
        match r.kind.as_deref() {
            None | Some("default") => {}
            Some("logical") => {
                let mode = match r.mode.as_deref() {
                    Some("and") => LogicalMode::And,
                    Some("or") => LogicalMode::Or,
                    other => bail!("logical rule needs `mode` and or or, got {other:?}"),
                };
                let mut plain = r.clone();
                plain.kind = None;
                plain.mode = None;
                plain.rules = Vec::new();
                plain.invert = false;
                if serde_json::to_value(&plain)?
                    .as_object()
                    .is_some_and(|o| !o.is_empty())
                {
                    bail!("a logical rule may only contain `mode`, `rules` and `invert`");
                }
                let rules = r
                    .rules
                    .iter()
                    .map(|x| self.spec(x))
                    .collect::<Result<Vec<_>>>()?;
                s.logical = Some((mode, rules));
                return Ok(s);
            }
            Some(other) => bail!("unknown rule type `{other}`"),
        }
        if !r.rules.is_empty() || r.mode.is_some() {
            bail!("`rules` and `mode` need `\"type\": \"logical\"`");
        }
        s.has_domain = !(r.domain.is_empty()
            && r.domain_suffix.is_empty()
            && r.domain_keyword.is_empty()
            && r.domain_regex.is_empty()
            && r.geosite.is_empty());
        r.domain.iter().for_each(|d| s.domain.full(d));
        r.domain_suffix.iter().for_each(|d| s.domain.suffix(d));
        r.domain_keyword.iter().for_each(|d| s.domain.keyword(d));
        r.domain_regex.iter().for_each(|d| s.domain.regex(d));
        for g in &r.geosite {
            self.geosite(g, &mut s.domain)?;
        }
        s.dest_ip.extend(self.cidrs(&r.ip_cidr)?);
        for g in &r.geoip {
            s.dest_ip.push(self.geoip(g)?);
        }
        if r.ip_is_private {
            s.dest_ip.push(RuleSpec::private_ip());
        }
        s.source_ip.extend(self.cidrs(&r.source_ip_cidr)?);
        for g in &r.source_geoip {
            s.source_ip.push(self.geoip(g)?);
        }
        if r.source_ip_is_private {
            s.source_ip.push(RuleSpec::private_ip());
        }
        s.dest_port = r.port.iter().map(|p| (*p, *p)).collect();
        for p in &r.port_range {
            s.dest_port.push(parse_port_range(p)?);
        }
        s.source_port = r.source_port.iter().map(|p| (*p, *p)).collect();
        for p in &r.source_port_range {
            s.source_port.push(parse_port_range(p)?);
        }
        for n in &r.network {
            s.network.push(match n.to_ascii_lowercase().as_str() {
                "tcp" => Network::Tcp,
                "udp" => Network::Udp,
                other => bail!("unknown network `{other}`"),
            });
        }
        s.protocol = r.protocol.iter().map(|p| p.to_ascii_lowercase()).collect();
        s.inbound = r.inbound.clone();
        s.user = r.auth_user.clone();
        s.process_name = r.process_name.clone();
        s.process_path = r.process_path.clone();
        s.process_path_regex = r.process_path_regex.clone();
        s.package_name = r.package_name.clone();
        s.rule_set = r.rule_set.clone();
        Ok(s)
    }
}

fn spec_needs_ip(s: &RuleSpec) -> bool {
    !s.dest_ip.is_empty()
        || s.logical
            .as_ref()
            .is_some_and(|(_, r)| r.iter().any(spec_needs_ip))
}

/// Compiled routing table.
pub struct Router {
    rules: Vec<(Rule, Action)>,
    pub final_tag: Arc<str>,
    pub needs_process: bool,
    pub needs_ip: bool,
    pub domain_strategy: DomainStrategy,
    pub rule_sets: HashMap<String, Arc<RuleSet>>,
}

/// Result of a routing decision.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision<'a> {
    pub action: &'a Action,
    /// Index of the rule that matched; `None` for the final outbound.
    pub rule: Option<usize>,
}

impl Router {
    pub fn build(
        cfg: &RouteConfig,
        final_tag: Arc<str>,
        assets: &Assets,
        geo: &GeoCache,
    ) -> Result<Self> {
        let builder = SpecBuilder {
            assets,
            geo,
            geosite: cfg.geosite.clone(),
            geoip: cfg.geoip.clone(),
        };
        let domain_strategy = match cfg
            .domain_strategy
            .as_deref()
            .unwrap_or("as_is")
            .to_ascii_lowercase()
            .as_str()
        {
            "as_is" | "asis" => DomainStrategy::AsIs,
            "ip_if_non_match" | "ipifnonmatch" => DomainStrategy::IpIfNonMatch,
            "ip_on_demand" | "ipondemand" => DomainStrategy::IpOnDemand,
            other => bail!("unknown route.domain_strategy `{other}`"),
        };

        let mut needs_process = false;
        let mut needs_ip = false;
        let mut rule_sets: HashMap<String, Arc<RuleSet>> = HashMap::new();
        for rs in &cfg.rule_set {
            let specs =
                load_rule_set(rs, &builder).with_context(|| format!("rule-set `{}`", rs.tag))?;
            needs_process |= specs.iter().any(RuleSpec::needs_process);
            needs_ip |= specs.iter().any(spec_needs_ip);
            // Rule-sets may not reference other rule-sets.
            let rules = specs
                .into_iter()
                .map(|s| Rule::compile(s, &|_| None))
                .collect::<Result<Vec<_>>>()?;
            rule_sets.insert(rs.tag.clone(), RuleSet::new(&rs.tag, rules));
        }
        let lookup = |tag: &str| rule_sets.get(tag).cloned();

        let mut rules = Vec::with_capacity(cfg.rules.len());
        for (i, r) in cfg.rules.iter().enumerate() {
            let spec = builder
                .spec(&r.conditions)
                .with_context(|| format!("route.rules[{i}]"))?;
            needs_process |= spec.needs_process();
            needs_ip |= spec_needs_ip(&spec);
            let action = match r.action.as_deref().unwrap_or("route") {
                "reject" => Action::Reject,
                _ => Action::Route(Arc::from(
                    r.outbound
                        .as_deref()
                        .ok_or_else(|| anyhow!("route.rules[{i}]: `outbound` is required"))?,
                )),
            };
            rules.push((
                Rule::compile(spec, &lookup).with_context(|| format!("route.rules[{i}]"))?,
                action,
            ));
        }
        Ok(Self {
            rules,
            final_tag,
            needs_process,
            needs_ip,
            domain_strategy,
            rule_sets,
        })
    }

    pub fn decide(&self, ctx: &MatchContext<'_>) -> Option<Decision<'_>> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, (rule, _))| rule.matches(ctx))
            .map(|(i, (_, action))| Decision {
                action,
                rule: Some(i),
            })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn load_rule_set(rs: &RuleSetConfig, builder: &SpecBuilder<'_>) -> Result<Vec<RuleSpec>> {
    let from_source = |text: &str| -> Result<Vec<RuleSpec>> {
        let source: RuleSetSource =
            serde_json::from_str(text).context("invalid rule-set source")?;
        source.rules.iter().map(|r| builder.spec(r)).collect()
    };
    let read_file = |path: &str| -> Result<Vec<RuleSpec>> {
        let path = builder.assets.find(path)?;
        let data =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let binary = match rs.format.as_deref() {
            Some("binary") => true,
            Some("source") => false,
            Some(other) => bail!("unknown rule-set format `{other}`"),
            None => path.extension().is_some_and(|e| e == "srs") || data.starts_with(b"SRS"),
        };
        if binary {
            sybau_route::srs::read(&data)
        } else {
            from_source(std::str::from_utf8(&data).context("rule-set source is not UTF-8")?)
        }
    };
    match rs.kind.as_str() {
        "inline" => rs.rules.iter().map(|r| builder.spec(r)).collect(),
        "local" => read_file(rs.path.as_deref().ok_or_else(|| anyhow!("`path` is required"))?),
        "remote" => match rs.path.as_deref() {
            // A previously downloaded copy can be used.
            Some(path) if builder.assets.find(path).is_ok() => read_file(path),
            _ => bail!(
                "downloading remote rule-sets is not implemented yet; download {} yourself and use `\"type\": \"local\"`",
                rs.url.as_deref().unwrap_or("the file")
            ),
        },
        other => bail!("unknown rule-set type `{other}` (local, inline or remote)"),
    }
}

/// Compiles extra rules (DNS rules) with the same geo files and the
/// rule-sets of the router.
pub fn compile_rule(
    cfg: &RouteConfig,
    assets: &Assets,
    geo: &GeoCache,
    rule_sets: &HashMap<String, Arc<RuleSet>>,
    rule: &HeadlessRule,
    query_types: Vec<u16>,
) -> Result<Rule> {
    let builder = SpecBuilder {
        assets,
        geo,
        geosite: cfg.geosite.clone(),
        geoip: cfg.geoip.clone(),
    };
    let mut spec = builder.spec(rule)?;
    spec.query_type = query_types;
    Rule::compile(spec, &|tag| rule_sets.get(tag).cloned())
}
