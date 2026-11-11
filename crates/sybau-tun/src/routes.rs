//! System routes that send traffic into the TUN interface, and the kill
//! switch. Linux uses policy routing: the core's own sockets carry a
//! firewall mark and keep using the main table.

use anyhow::Result;

#[derive(Clone, Debug, Default)]
pub struct RouteOptions {
    pub interface: String,
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
    opts: Option<RouteOptions>,
}

impl Routes {
    pub fn install(opts: &RouteOptions) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = opts;
            anyhow::bail!("auto_route is not implemented on this platform yet");
        }
        #[cfg(target_os = "linux")]
        {
            linux::install(opts)?;
            Ok(Self {
                opts: Some(opts.clone()),
            })
        }
    }

    /// Removes the routes. `keep_kill_switch` is set during a reload: the
    /// next configuration replaces the kill switch atomically (or removes
    /// it), so no traffic slips out in between.
    pub fn shutdown(mut self, keep_kill_switch: bool) {
        if let Some(opts) = self.opts.take() {
            remove(&opts, !keep_kill_switch);
        }
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        if let Some(opts) = self.opts.take() {
            remove(&opts, false);
            if opts.kill_switch {
                tracing::warn!(target: "sybau::tun", "routes removed; the kill switch stays until a clean exit or `sybau tun-cleanup`");
            }
        }
    }
}

fn remove(opts: &RouteOptions, kill_switch: bool) {
    #[cfg(target_os = "linux")]
    linux::cleanup(opts.table, kill_switch);
    let _ = (opts, kill_switch);
}

/// Removes routes, rules and the kill switch left by a crashed run.
pub fn cleanup(table: u32) {
    #[cfg(target_os = "linux")]
    linux::cleanup(table, true);
    let _ = table;
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
