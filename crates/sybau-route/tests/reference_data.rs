//! Geo data files and rule-sets produced by the reference implementations
//! (see tools/geo-fixtures) must match exactly what Xray and sing-box
//! decide for the same queries.

use std::net::IpAddr;
use std::path::PathBuf;

use serde_json::Value;
use sybau_route::domain::DomainSetBuilder;
use sybau_route::geodata::{split_site, GeoFile};
use sybau_route::ipset::IpSetBuilder;
use sybau_route::rule::{IpItem, MatchContext, Rule, RuleSet, RuleSpec};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn expectations(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture(name)).unwrap()).unwrap()
}

#[test]
fn geosite_matches_xray() {
    let file = GeoFile::load(&fixture("geosite.dat")).unwrap();
    let exp = expectations("xray-expectations.json");
    let mut checked = 0;
    for case in exp["geosite"].as_array().unwrap() {
        let (site, attrs) = split_site(case["site"].as_str().unwrap());
        let mut b = DomainSetBuilder::default();
        file.site(&site, &attrs, &mut b).unwrap();
        let set = b.build().unwrap();
        let domain = case["domain"].as_str().unwrap();
        assert_eq!(
            set.matches(domain),
            case["match"].as_bool().unwrap(),
            "geosite:{} {domain}",
            case["site"]
        );
        checked += 1;
    }
    assert!(checked > 50);
    assert!(file
        .site("missing", &[], &mut DomainSetBuilder::default())
        .is_err());
}

#[test]
fn geoip_matches_xray() {
    let file = GeoFile::load(&fixture("geoip.dat")).unwrap();
    for case in expectations("xray-expectations.json")["geoip"]
        .as_array()
        .unwrap()
    {
        let mut set = IpSetBuilder::default();
        file.ip(case["code"].as_str().unwrap(), &mut set).unwrap();
        let spec = RuleSpec {
            dest_ip: vec![IpItem {
                set,
                negate: case["reverse"].as_bool().unwrap(),
            }],
            ..Default::default()
        };
        let rule = Rule::compile(spec, &|_| None).unwrap();
        let ip: IpAddr = case["ip"].as_str().unwrap().parse().unwrap();
        let ctx = MatchContext {
            dest_ips: &[ip],
            ..Default::default()
        };
        assert_eq!(
            rule.matches(&ctx),
            case["match"].as_bool().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn rule_sets_match_sing_box() {
    let mut checked = 0;
    for case in expectations("singbox-expectations.json")
        .as_array()
        .unwrap()
    {
        let file = case["file"].as_str().unwrap();
        let specs = sybau_route::srs::read(&std::fs::read(fixture(file)).unwrap())
            .unwrap_or_else(|e| panic!("{file}: {e:#}"));
        let rules = specs
            .into_iter()
            .map(|s| Rule::compile(s, &|_| None).unwrap())
            .collect();
        let set = RuleSet::new("t", rules);
        let query = case["query"].as_str().unwrap();
        // `sing-box rule-set match` fills in either the domain or the IP.
        let ips: Vec<IpAddr> = query.parse().into_iter().collect();
        let ctx = MatchContext {
            domain: if ips.is_empty() { Some(query) } else { None },
            dest_ips: &ips,
            ..Default::default()
        };
        assert_eq!(
            set.matches(&ctx),
            case["match"].as_bool().unwrap(),
            "{file} {query}"
        );
        checked += 1;
    }
    assert!(checked > 300);
}
