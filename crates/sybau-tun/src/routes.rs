//! System routes that send traffic into the TUN interface, and the kill
//! switch.
//!
//! Linux uses policy routing: the core's own sockets carry a firewall
//! mark and keep using the main table. Windows gets `0.0.0.0/1` and
//! `128.0.0.0/1` (and the IPv6 halves) on the TUN, narrower than the
//! default route; the core's own sockets are pinned to the uplink
//! interface instead.

use anyhow::Result;

#[derive(Clone, Debug, Default)]
pub struct RouteOptions {
    pub interface: String,
    /// Interface index of the TUN (Windows).
    pub interface_index: u32,
    /// Addresses on the interface (`172.19.0.1/30`).
    pub addresses: Vec<String>,
    /// Only these destinations go to the TUN; empty means everything.
    pub route_address: Vec<String>,
    /// Destinations that never go to the TUN.
    pub route_exclude_address: Vec<String>,
    /// Without strict routing, more specific routes of the main table
    /// (the LAN) still win over the TUN.
    pub strict_route: bool,
    /// Linux: users whose traffic is routed / not routed.
    pub include_uid: Vec<u32>,
    pub exclude_uid: Vec<u32>,
    /// Mark on the core's own sockets (Linux).
    pub fwmark: u32,
    /// Routing table used for the TUN routes (Linux).
    pub table: u32,
    /// Block traffic that would bypass the TUN, even after a crash.
    pub kill_switch: bool,
}

/// Installed routes. They are removed by [`Routes::shutdown`] or when
/// dropped; the kill switch is removed only by a clean shutdown, so that
/// a crash or a panic keeps traffic blocked.
pub struct Routes {
    opts: RouteOptions,
    #[cfg(windows)]
    added: Vec<crate::windows::Route>,
    /// DNS block of `strict_route` without a kill switch (Windows).
    #[cfg(windows)]
    filters: Option<crate::wfp::Session>,
    active: bool,
}

impl Routes {
    pub fn install(opts: &RouteOptions) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::install(opts)?;
            Ok(Self {
                opts: opts.clone(),
                active: true,
            })
        }
        #[cfg(windows)]
        {
            let (added, filters) = win::install(opts)?;
            Ok(Self {
                opts: opts.clone(),
                added,
                filters,
                active: true,
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = opts;
            anyhow::bail!("auto_route is not implemented on this platform");
        }
    }

    /// Removes the routes. `keep_kill_switch` is set during a reload: the
    /// next configuration replaces the kill switch atomically (or removes
    /// it), so no traffic slips out in between.
    pub fn shutdown(mut self, keep_kill_switch: bool) {
        self.remove(!keep_kill_switch);
    }

    fn remove(&mut self, kill_switch: bool) {
        if !std::mem::take(&mut self.active) {
            return;
        }
        #[cfg(target_os = "linux")]
        linux::cleanup(self.opts.table, kill_switch);
        #[cfg(windows)]
        {
            for route in self.added.drain(..) {
                crate::windows::delete_route(&route);
            }
            self.filters = None;
            if kill_switch && self.opts.kill_switch {
                crate::wfp::remove();
            }
        }
        let _ = kill_switch;
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        if self.active {
            self.remove(false);
            if self.opts.kill_switch {
                tracing::warn!(target: "sybau::tun", "routes removed; the kill switch stays until a clean exit or `sybau tun-cleanup`");
            }
        }
    }
}

/// Removes routes, rules and the kill switch left by a crashed run.
pub fn cleanup(table: u32) {
    #[cfg(target_os = "linux")]
    linux::cleanup(table, true);
    #[cfg(windows)]
    crate::wfp::remove();
    let _ = table;
}

/// Destinations a kill switch lets through outside the TUN when routing
/// is not strict: the LAN, link-local and multicast.
pub fn local_networks() -> Vec<(std::net::IpAddr, u8)> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "fe80::/10",
        "fc00::/7",
        "ff00::/8",
    ]
    .iter()
    .map(|c| parse_cidr(c).expect("valid built-in network"))
    .collect()
}

/// Splits `a.b.c.d/n` into the address and prefix length.
pub fn parse_cidr(text: &str) -> Result<(std::net::IpAddr, u8)> {
    let (a, p) = text
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("`{text}` is not in address/prefix form"))?;
    let ip: std::net::IpAddr = a
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad address in `{text}`"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = p
        .trim()
        .parse()
        .ok()
        .filter(|p| *p <= max)
        .ok_or_else(|| anyhow::anyhow!("bad prefix in `{text}`"))?;
    Ok((ip, prefix))
}

#[cfg(windows)]
mod win {
    use std::net::IpAddr;

    use anyhow::{Context, Result};
    use tracing::{info, warn};

    use super::{parse_cidr, RouteOptions};
    use crate::windows::{add_route, default_route, Route};

    pub fn install(o: &RouteOptions) -> Result<(Vec<Route>, Option<crate::wfp::Session>)> {
        if !o.include_uid.is_empty() || !o.exclude_uid.is_empty() {
            warn!(target: "sybau::tun", "include_uid / exclude_uid only work on Linux; use include_process / exclude_process");
        }
        let has_v6 = o.addresses.iter().any(|a| a.contains(':'));
        let mut wanted: Vec<String> = if o.route_address.is_empty() {
            let mut v = vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()];
            if has_v6 {
                v.extend(["::/1".to_string(), "8000::/1".to_string()]);
            }
            v
        } else {
            o.route_address.clone()
        };
        wanted.retain(|c| has_v6 || !c.contains(':'));
        let mut added = Vec::new();
        let result = (|| -> Result<()> {
            for cidr in &wanted {
                let (ip, len) = parse_cidr(cidr)?;
                if let Some(r) = add_route(ip, len, o.interface_index, None, 0)
                    .with_context(|| format!("route {cidr} via the TUN"))?
                {
                    added.push(r);
                }
            }
            for cidr in &o.route_exclude_address {
                let (ip, len) = parse_cidr(cidr)?;
                let Some(uplink) = default_route(ip.is_ipv6(), o.interface_index) else {
                    warn!(target: "sybau::tun", "route_exclude_address {cidr}: no default route outside the TUN");
                    continue;
                };
                let hop = (!uplink.next_hop.is_unspecified()).then_some(uplink.next_hop);
                if let Some(r) = add_route(ip, len, uplink.index, hop, 0)
                    .with_context(|| format!("route {cidr} outside the TUN"))?
                {
                    added.push(r);
                }
            }
            Ok(())
        })();
        let filters = result.and_then(|()| {
            let mut allow = if o.strict_route {
                Vec::new()
            } else {
                super::local_networks()
            };
            for cidr in &o.route_exclude_address {
                allow.push(parse_cidr(cidr)?);
            }
            crate::wfp::install(&crate::wfp::FilterOptions {
                kill_switch: o.kill_switch,
                block_dns: o.strict_route,
                tun_index: o.interface_index,
                allow: &allow,
            })
            .context("filters (kill switch / strict_route)")
        });
        let filters = match filters {
            Ok(f) => f,
            Err(e) => {
                for r in &added {
                    crate::windows::delete_route(r);
                }
                return Err(e);
            }
        };
        let uplink: Option<IpAddr> = default_route(false, o.interface_index).map(|r| r.next_hop);
        info!(target: "sybau::tun", "routes through `{}` installed ({}; uplink gateway {}{}{})", o.interface, wanted.join(", "), uplink.map_or("none".into(), |g| g.to_string()), if o.strict_route { ", DNS outside the TUN blocked" } else { "" }, if o.kill_switch { ", kill switch on" } else { "" });
        Ok((added, filters))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;

    use anyhow::{bail, Context, Result};
    use tracing::{debug, info};

    use super::RouteOptions;

    /// Rule priorities used by the core.
    const PREF_MARK: u32 = 8999;
    const PREF_EXCLUDE_UID: u32 = 9000;
    const PREF_SUPPRESS: u32 = 9001;
    const PREF_TUN: u32 = 9002;
    const NFT_TABLE: &str = "sybau_killswitch";

    fn run(program: &str, args: &[&str]) -> Result<()> {
        let out = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("cannot run `{program}` (is it installed?)"))?;
        if !out.status.success() {
            bail!(
                "`{program} {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        debug!(target: "sybau::tun", "{program} {}", args.join(" "));
        Ok(())
    }

    fn ip(family: &str, args: &[&str]) -> Result<()> {
        let mut all = vec![family];
        all.extend_from_slice(args);
        run("ip", &all)
    }

    fn family_of(cidr: &str) -> &'static str {
        if cidr.contains(':') {
            "-6"
        } else {
            "-4"
        }
    }

    /// Deletes every rule at `pref` (errors are expected: there may be none).
    fn delete_rules(family: &str, pref: u32) {
        let pref = pref.to_string();
        for _ in 0..256 {
            let ok = Command::new("ip")
                .args([family, "rule", "del", "pref", &pref])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                break;
            }
        }
    }

    pub fn cleanup(table: u32, kill_switch: bool) {
        for family in ["-4", "-6"] {
            for pref in [PREF_MARK, PREF_EXCLUDE_UID, PREF_SUPPRESS, PREF_TUN] {
                delete_rules(family, pref);
            }
            let _ = Command::new("ip")
                .args([family, "route", "flush", "table", &table.to_string()])
                .output();
        }
        if kill_switch {
            remove_kill_switch();
        }
    }

    fn remove_kill_switch() {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .output();
    }

    pub fn install(o: &RouteOptions) -> Result<()> {
        // Leftovers of a run that did not clean up; a kill switch left
        // in place is replaced (or removed) below.
        cleanup(o.table, false);
        let result = install_routes(o).and_then(|()| {
            if o.kill_switch {
                install_kill_switch(o)
            } else {
                remove_kill_switch();
                Ok(())
            }
        });
        if let Err(e) = result {
            cleanup(o.table, false);
            return Err(e);
        }
        info!(target: "sybau::tun", "routes through `{}` installed (table {}, mark {:#x}{})", o.interface, o.table, o.fwmark, if o.kill_switch { ", kill switch on" } else { "" });
        Ok(())
    }

    fn install_routes(o: &RouteOptions) -> Result<()> {
        let table = o.table.to_string();
        let mark = format!("{:#x}", o.fwmark);
        let has_v6 = o.addresses.iter().any(|a| a.contains(':'));
        let families: Vec<&str> = if has_v6 { vec!["-4", "-6"] } else { vec!["-4"] };
        if o.route_address.is_empty() {
            for family in &families {
                ip(
                    family,
                    &[
                        "route",
                        "replace",
                        "default",
                        "dev",
                        &o.interface,
                        "table",
                        &table,
                    ],
                )?;
            }
        }
        for cidr in &o.route_address {
            if families.contains(&family_of(cidr)) {
                ip(
                    family_of(cidr),
                    &[
                        "route",
                        "replace",
                        cidr,
                        "dev",
                        &o.interface,
                        "table",
                        &table,
                    ],
                )?;
            }
        }
        for cidr in &o.route_exclude_address {
            // `throw` ends the lookup in this table; the next rule (main) decides.
            ip(
                family_of(cidr),
                &["route", "replace", "throw", cidr, "table", &table],
            )?;
        }
        for family in &families {
            // The core's own sockets carry the mark and keep the main table.
            ip(
                family,
                &[
                    "rule",
                    "add",
                    "pref",
                    &PREF_MARK.to_string(),
                    "fwmark",
                    &mark,
                    "lookup",
                    "main",
                ],
            )?;
            for uid in &o.exclude_uid {
                let range = format!("{uid}-{uid}");
                ip(
                    family,
                    &[
                        "rule",
                        "add",
                        "pref",
                        &PREF_EXCLUDE_UID.to_string(),
                        "uidrange",
                        &range,
                        "lookup",
                        "main",
                    ],
                )?;
            }
            if !o.strict_route {
                // Routes more specific than the default one (LAN, VPNs)
                // still win; only the default route is replaced.
                ip(
                    family,
                    &[
                        "rule",
                        "add",
                        "pref",
                        &PREF_SUPPRESS.to_string(),
                        "lookup",
                        "main",
                        "suppress_prefixlength",
                        "0",
                    ],
                )?;
            }
            if o.include_uid.is_empty() {
                ip(
                    family,
                    &[
                        "rule",
                        "add",
                        "pref",
                        &PREF_TUN.to_string(),
                        "lookup",
                        &table,
                    ],
                )?;
            } else {
                for uid in &o.include_uid {
                    let range = format!("{uid}-{uid}");
                    ip(
                        family,
                        &[
                            "rule",
                            "add",
                            "pref",
                            &PREF_TUN.to_string(),
                            "uidrange",
                            &range,
                            "lookup",
                            &table,
                        ],
                    )?;
                }
            }
        }
        Ok(())
    }

    fn uid_set(uids: &[u32]) -> String {
        let list: Vec<String> = uids.iter().map(u32::to_string).collect();
        format!("{{ {} }}", list.join(", "))
    }

    /// nftables script for the kill switch: locally generated traffic may
    /// only leave through the TUN, loopback or the LAN (unless strict),
    /// apart from the core's own marked sockets.
    pub(super) fn kill_switch_script(o: &RouteOptions) -> String {
        let mut allow = vec![
            "oifname \"lo\" accept".to_string(),
            format!("oifname \"{}\" accept", o.interface),
            format!("meta mark {:#x} accept", o.fwmark),
        ];
        if !o.exclude_uid.is_empty() {
            allow.push(format!("meta skuid {} accept", uid_set(&o.exclude_uid)));
        }
        if !o.include_uid.is_empty() {
            allow.push(format!("meta skuid != {} accept", uid_set(&o.include_uid)));
        }
        let mut v4: Vec<String> = Vec::new();
        let mut v6: Vec<String> = Vec::new();
        for cidr in o.route_exclude_address.iter().chain(o.addresses.iter()) {
            if cidr.contains(':') {
                v6.push(cidr.clone())
            } else {
                v4.push(cidr.clone())
            }
        }
        if !o.strict_route {
            v4.extend(
                [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.0.0/16",
                ]
                .map(String::from),
            );
            v6.extend(["fe80::/10", "fc00::/7"].map(String::from));
        }
        if !v4.is_empty() {
            allow.push(format!("ip daddr {{ {} }} accept", v4.join(", ")));
        }
        if !v6.is_empty() {
            allow.push(format!("ip6 daddr {{ {} }} accept", v6.join(", ")));
        }
        // Declaring, flushing and filling the table in one transaction
        // replaces an existing kill switch without a gap.
        format!(
            "table inet {NFT_TABLE} {{}}\nflush table inet {NFT_TABLE}\ntable inet {NFT_TABLE} {{\n  chain output {{\n    type filter hook output priority 0; policy accept;\n    {}\n    counter reject\n  }}\n}}\n",
            allow.join("\n    ")
        )
    }

    fn install_kill_switch(o: &RouteOptions) -> Result<()> {
        use std::io::Write;
        let script = kill_switch_script(o);
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("cannot run `nft` for the kill switch (is nftables installed?)")?;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "kill switch: nft failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_rules() {
        let o = RouteOptions {
            interface: "sybau0".into(),
            addresses: vec!["172.19.0.1/30".into(), "fdfe:dcba:9876::1/126".into()],
            route_exclude_address: vec!["203.0.113.0/24".into()],
            exclude_uid: vec![1001],
            fwmark: 0x2023,
            table: 2022,
            kill_switch: true,
            ..Default::default()
        };
        let s = linux::kill_switch_script(&o);
        assert!(s.contains("oifname \"sybau0\" accept"));
        assert!(s.contains("meta mark 0x2023 accept"));
        assert!(s.contains("meta skuid { 1001 } accept"));
        assert!(s.contains("ip daddr { 203.0.113.0/24, 172.19.0.1/30, 10.0.0.0/8"));
        assert!(s.contains("ip6 daddr { fdfe:dcba:9876::1/126, fe80::/10"));
        assert!(s.trim_end().ends_with("counter reject\n  }\n}"));
        let strict = linux::kill_switch_script(&RouteOptions {
            strict_route: true,
            ..o
        });
        assert!(!strict.contains("192.168.0.0/16"));
    }
}
