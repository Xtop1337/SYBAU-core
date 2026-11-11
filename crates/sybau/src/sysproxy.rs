//! Windows system proxy (WinINet settings of the current user).
//!
//! The previous settings are saved to a state file before they are
//! changed. They are restored on exit, by a guard process if the core
//! dies, and on the next start if both were killed.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sybau_config::{Config, InboundKind, SystemProxyConfig};

/// Settings before the core changed them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub auto_config_url: Option<String>,
}

pub const DEFAULT_BYPASS: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

pub fn state_file(profile: &str) -> PathBuf {
    sybau_core::control::runtime_dir().join(format!("sybau-core-{profile}.sysproxy.json"))
}

/// The `host:port` to announce for this config.
pub fn proxy_server(cfg: &Config, sp: &SystemProxyConfig) -> Option<String> {
    if let Some(s) = &sp.server {
        return Some(s.clone());
    }
    cfg.inbounds.iter().find_map(|ib| match &ib.kind {
        InboundKind::Mixed(c) | InboundKind::Http(c) => {
            let host = match c.listen.as_str() {
                "0.0.0.0" | "::" | "" => "127.0.0.1",
                other => other,
            };
            Some(if host.contains(':') {
                format!("[{host}]:{}", c.port)
            } else {
                format!("{host}:{}", c.port)
            })
        }
        InboundKind::Socks(_) | InboundKind::Tun(_) => None,
    })
}

/// Contents of the state file: the settings to restore and the core
/// that changed them.
#[derive(Debug, Serialize, Deserialize)]
struct State {
    pid: u32,
    saved: Saved,
}

fn write_state(path: &Path, saved: &Saved) -> Result<()> {
    let state = State {
        pid: std::process::id(),
        saved: saved.clone(),
    };
    std::fs::write(path, serde_json::to_vec(&state)?)?;
    Ok(())
}

fn read_state(path: &Path) -> Option<State> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Restores settings left behind by a run that did not clean up. With
/// `owner`, only if that core wrote them: a guard must not undo the
/// settings of a core started after its own one exited.
pub fn recover_from(profile: &str, owner: Option<u32>) {
    let path = state_file(profile);
    if let Some(state) = read_state(&path) {
        if owner.is_some_and(|pid| pid != state.pid) {
            return;
        }
        match imp::apply(&state.saved) {
            Ok(()) => {
                eprintln!("restored the system proxy settings left by a previous run");
                let _ = std::fs::remove_file(&path);
            }
            Err(e) => eprintln!("warning: cannot restore the system proxy: {e:#}"),
        }
    }
}

/// Restores settings left by any earlier run (called at start, when no
/// other core of the profile can be running).
pub fn recover(profile: &str) {
    recover_from(profile, None);
}

/// Active system proxy; restores the previous settings when dropped.
pub struct SystemProxy {
    state: PathBuf,
    saved: Saved,
}

impl SystemProxy {
    pub fn enable(profile: &str, server: &str, bypass: &[String]) -> Result<Self> {
        let state = state_file(profile);
        let saved = imp::read()?;
        // Saved before touching anything, so a crash in between is recoverable.
        write_state(&state, &saved)?;
        let bypass = if bypass.is_empty() {
            DEFAULT_BYPASS.to_string()
        } else {
            bypass.join(";")
        };
        let ours = Saved {
            enable: Some(1),
            server: Some(server.to_string()),
            bypass: Some(bypass),
            auto_config_url: None,
        };
        if let Err(e) = imp::apply(&ours) {
            let _ = imp::apply(&saved);
            let _ = std::fs::remove_file(&state);
            return Err(e);
        }
        imp::spawn_guard(profile)?;
        Ok(Self { state, saved })
    }
}

impl Drop for SystemProxy {
    fn drop(&mut self) {
        match imp::apply(&self.saved) {
            Ok(()) => {
                let _ = std::fs::remove_file(&self.state);
            }
            Err(e) => eprintln!("warning: cannot restore the system proxy: {e:#}"),
        }
    }
}

/// Body of `sybau sysproxy-guard`: waits for the core to exit and
/// restores the settings if it did not.
pub fn guard(pid: u32, profile: &str) -> Result<()> {
    imp::wait_for_exit(pid)?;
    // A clean exit removed the state file; give it a moment to do so.
    std::thread::sleep(std::time::Duration::from_millis(500));
    recover_from(profile, Some(pid));
    Ok(())
}

#[cfg(windows)]
mod imp {
    use std::os::windows::process::CommandExt;

    use anyhow::{bail, Context, Result};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
    };

    use super::Saved;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from RegOpenKeyExW and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(access: u32) -> Result<Key> {
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated name and out pointer.
        let rc =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(KEY).as_ptr(), 0, access, &mut key) };
        if rc != ERROR_SUCCESS {
            bail!("cannot open the Internet Settings registry key (error {rc})");
        }
        Ok(Key(key))
    }

    fn query(key: &Key, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
        let name = wide(name);
        let mut kind = 0u32;
        let mut len = 0u32;
        // SAFETY: size query with null data pointer.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc != ERROR_SUCCESS {
            bail!("cannot read registry value (error {rc})");
        }
        let mut data = vec![0u8; len as usize];
        // SAFETY: the buffer has the size the first call reported.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("cannot read registry value (error {rc})");
        }
        data.truncate(len as usize);
        Ok(Some((kind, data)))
    }

    fn query_string(key: &Key, name: &str) -> Result<Option<String>> {
        Ok(query(key, name)?
            .filter(|(k, _)| *k == REG_SZ)
            .map(|(_, d)| {
                let units: Vec<u16> = d
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_string()
            }))
    }

    fn set(key: &Key, name: &str, kind: u32, data: &[u8]) -> Result<()> {
        // SAFETY: valid name and data buffer.
        let rc = unsafe {
            RegSetValueExW(
                key.0,
                wide(name).as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("cannot write registry value {name} (error {rc})");
        }
        Ok(())
    }

    fn set_string(key: &Key, name: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => set(
                key,
                name,
                REG_SZ,
                &wide(v)
                    .iter()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<u8>>(),
            ),
            None => {
                // SAFETY: valid name.
                let rc = unsafe { RegDeleteValueW(key.0, wide(name).as_ptr()) };
                if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
                    bail!("cannot delete registry value {name} (error {rc})");
                }
                Ok(())
            }
        }
    }

    pub fn read() -> Result<Saved> {
        let key = open(KEY_READ)?;
        let enable = query(&key, "ProxyEnable")?
            .filter(|(k, d)| *k == REG_DWORD && d.len() >= 4)
            .map(|(_, d)| u32::from_le_bytes([d[0], d[1], d[2], d[3]]));
        Ok(Saved {
            enable,
            server: query_string(&key, "ProxyServer")?,
            bypass: query_string(&key, "ProxyOverride")?,
            auto_config_url: query_string(&key, "AutoConfigURL")?,
        })
    }

    pub fn apply(s: &Saved) -> Result<()> {
        let key = open(KEY_READ | KEY_WRITE)?;
        set(
            &key,
            "ProxyEnable",
            REG_DWORD,
            &s.enable.unwrap_or(0).to_le_bytes(),
        )?;
        set_string(&key, "ProxyServer", s.server.as_deref())?;
        set_string(&key, "ProxyOverride", s.bypass.as_deref())?;
        set_string(&key, "AutoConfigURL", s.auto_config_url.as_deref())?;
        // SAFETY: documented way to make running programs reread the settings.
        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
        Ok(())
    }

    pub fn spawn_guard(profile: &str) -> Result<()> {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        let exe = std::env::current_exe().context("cannot locate sybau.exe")?;
        std::process::Command::new(exe)
            .args([
                "sysproxy-guard",
                "--pid",
                &std::process::id().to_string(),
                "--profile",
                profile,
            ])
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn()
            .context("cannot start the system proxy guard")?;
        Ok(())
    }

    pub fn wait_for_exit(pid: u32) -> Result<()> {
        // SAFETY: plain Win32 calls; the handle is closed below.
        unsafe {
            let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
            if handle.is_null() {
                // Already gone.
                return Ok(());
            }
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{bail, Result};

    use super::Saved;

    pub fn read() -> Result<Saved> {
        bail!("the system proxy is only managed on Windows")
    }

    pub fn apply(_s: &Saved) -> Result<()> {
        bail!("the system proxy is only managed on Windows")
    }

    pub fn spawn_guard(_profile: &str) -> Result<()> {
        Ok(())
    }

    pub fn wait_for_exit(pid: u32) -> Result<()> {
        // SAFETY: kill with signal 0 only checks that the process exists.
        while unsafe { libc::kill(pid as i32, 0) } == 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_defaults_to_the_first_http_capable_inbound() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "inbounds": [
                {"type": "socks", "port": 1080},
                {"type": "mixed", "listen": "0.0.0.0", "port": 2080},
            ],
        }))
        .unwrap();
        let sp = SystemProxyConfig {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(proxy_server(&cfg, &sp).as_deref(), Some("127.0.0.1:2080"));
        let sp = SystemProxyConfig {
            enabled: true,
            server: Some("10.0.0.1:3128".into()),
            bypass: vec![],
        };
        assert_eq!(proxy_server(&cfg, &sp).as_deref(), Some("10.0.0.1:3128"));
        let only_socks: Config =
            serde_json::from_value(serde_json::json!({"inbounds": [{"type": "socks", "port": 1}]}))
                .unwrap();
        assert_eq!(
            proxy_server(&only_socks, &SystemProxyConfig::default()),
            None
        );
    }

    #[test]
    fn state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sybau-sysproxy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let saved = Saved {
            enable: Some(0),
            server: Some("old:1".into()),
            bypass: None,
            auto_config_url: Some("http://pac".into()),
        };
        write_state(&path, &saved).unwrap();
        let state = read_state(&path).unwrap();
        // The owner lets a guard tell its own core's state from a newer one.
        assert_eq!(state.pid, std::process::id());
        assert_eq!(state.saved, saved);
        let _ = std::fs::remove_dir_all(dir);
    }
}
