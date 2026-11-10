//! Finds the local process that owns a connection made to an inbound.

use std::net::SocketAddr;

use sybau_common::Network;

/// Executable of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Full path of the executable.
    pub path: String,
    /// File name of the executable.
    pub name: String,
    /// Owner user id (Linux, Android).
    pub uid: Option<u32>,
}

impl ProcessInfo {
    fn from_path(pid: u32, path: String, uid: Option<u32>) -> Self {
        let name = path.rsplit(['/', '\\']).next().unwrap_or(&path).to_string();
        Self {
            pid,
            path,
            name,
            uid,
        }
    }
}

/// Looks up the process whose socket has the local address `source`
/// (the client side of a connection to one of our inbounds).
/// `peer` is the address the client connected to, if known.
pub fn find(network: Network, source: SocketAddr, peer: Option<SocketAddr>) -> Option<ProcessInfo> {
    imp::find(network, source, peer)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{Network, ProcessInfo};

    /// Parses `0100007F:1F90` (little-endian words, as in /proc/net).
    fn parse_addr(text: &str) -> Option<SocketAddr> {
        let (ip, port) = text.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let ip: IpAddr = match ip.len() {
            8 => Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.swap_bytes()).into(),
            32 => {
                let mut bytes = [0u8; 16];
                for i in 0..4 {
                    let word = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16)
                        .ok()?
                        .swap_bytes();
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
                }
                Ipv6Addr::from(bytes).into()
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    fn same(a: SocketAddr, b: SocketAddr) -> bool {
        a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
    }

    /// `(inode, uid)` of the socket bound to `source`.
    fn socket_inode(
        network: Network,
        source: SocketAddr,
        peer: Option<SocketAddr>,
    ) -> Option<(u64, u32)> {
        let tables: &[&str] = match network {
            Network::Tcp => &["/proc/net/tcp", "/proc/net/tcp6"],
            Network::Udp => &["/proc/net/udp", "/proc/net/udp6"],
        };
        for table in tables {
            let Ok(text) = std::fs::read_to_string(table) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 10 {
                    continue;
                }
                let (Some(local), Some(remote)) = (parse_addr(cols[1]), parse_addr(cols[2])) else {
                    continue;
                };
                if !same(local, source) {
                    continue;
                }
                if let (Network::Tcp, Some(peer)) = (network, peer) {
                    if !same(remote, peer) {
                        continue;
                    }
                }
                let (Ok(uid), Ok(inode)) = (cols[7].parse::<u32>(), cols[9].parse::<u64>()) else {
                    continue;
                };
                if inode != 0 {
                    return Some((inode, uid));
                }
            }
        }
        None
    }

    pub fn find(
        network: Network,
        source: SocketAddr,
        peer: Option<SocketAddr>,
    ) -> Option<ProcessInfo> {
        let (inode, uid) = socket_inode(network, source, peer)?;
        let wanted = format!("socket:[{inode}]");
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            let owns = fds.flatten().any(|fd| {
                std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == wanted.as_str())
            });
            if owns {
                let path = std::fs::read_link(entry.path().join("exe"))
                    .ok()?
                    .to_string_lossy()
                    .into_owned();
                return Some(ProcessInfo::from_path(pid, path, Some(uid)));
            }
        }
        // The socket exists but its process is not visible (another user
        // without permission, or Android): the uid is still useful.
        Some(ProcessInfo {
            pid: 0,
            path: String::new(),
            name: String::new(),
            uid: Some(uid),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn proc_net_addresses() {
            assert_eq!(
                parse_addr("0100007F:1F90"),
                Some("127.0.0.1:8080".parse().unwrap())
            );
            assert_eq!(
                parse_addr("00000000000000000000000001000000:0035"),
                Some("[::1]:53".parse().unwrap())
            );
            assert_eq!(
                parse_addr("0000000000000000FFFF00000100007F:0050"),
                Some("[::ffff:127.0.0.1]:80".parse().unwrap())
            );
            assert_eq!(parse_addr("zz:1"), None);
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{Network, ProcessInfo};

    /// Calls a table function with a growing buffer.
    fn table(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u8>> {
        let mut size = 64 * 1024u32;
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize];
            match call(buf.as_mut_ptr().cast(), &mut size) {
                NO_ERROR => return Some(buf),
                ERROR_INSUFFICIENT_BUFFER => size = size.saturating_mul(2).max(size + 1024),
                _ => return None,
            }
        }
        None
    }

    /// Rows of a MIB table: `u32 count` followed by the rows.
    fn rows<T: Copy>(buf: &[u8]) -> impl Iterator<Item = T> + '_ {
        let count = u32::from_ne_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
        let align = std::mem::align_of::<T>().max(4);
        let start = 4usize.next_multiple_of(align);
        let size = std::mem::size_of::<T>();
        (0..count).filter_map(move |i| {
            let off = start + i * size;
            // SAFETY: the bounds are checked; read_unaligned copes with any alignment.
            (off + size <= buf.len())
                .then(|| unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast::<T>()) })
        })
    }

    fn port(raw: u32) -> u16 {
        u16::from_be(raw as u16)
    }

    fn pid_of(network: Network, source: SocketAddr) -> Option<u32> {
        let ip = source.ip().to_canonical();
        match (network, ip) {
            (Network::Tcp, IpAddr::V4(v4)) => {
                // SAFETY: the buffer and size pointers are valid for the call.
                let buf = table(|p, s| unsafe {
                    GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
                })?;
                let pid = rows::<MIB_TCPROW_OWNER_PID>(&buf)
                    .find(|r| {
                        Ipv4Addr::from(u32::from_be(r.dwLocalAddr)) == v4
                            && port(r.dwLocalPort) == source.port()
                    })
                    .map(|r| r.dwOwningPid);
                pid
            }
            (Network::Tcp, IpAddr::V6(v6)) => {
                // SAFETY: as above.
                let buf = table(|p, s| unsafe {
                    GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
                })?;
                let pid = rows::<MIB_TCP6ROW_OWNER_PID>(&buf)
                    .find(|r| {
                        Ipv6Addr::from(r.ucLocalAddr) == v6 && port(r.dwLocalPort) == source.port()
                    })
                    .map(|r| r.dwOwningPid);
                pid
            }
            (Network::Udp, IpAddr::V4(v4)) => {
                // SAFETY: as above.
                let buf = table(|p, s| unsafe {
                    GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
                })?;
                let pid = rows::<MIB_UDPROW_OWNER_PID>(&buf)
                    .find(|r| {
                        let local = Ipv4Addr::from(u32::from_be(r.dwLocalAddr));
                        (local == v4 || local.is_unspecified())
                            && port(r.dwLocalPort) == source.port()
                    })
                    .map(|r| r.dwOwningPid);
                pid
            }
            (Network::Udp, IpAddr::V6(v6)) => {
                // SAFETY: as above.
                let buf = table(|p, s| unsafe {
                    GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
                })?;
                let pid = rows::<MIB_UDP6ROW_OWNER_PID>(&buf)
                    .find(|r| {
                        let local = Ipv6Addr::from(r.ucLocalAddr);
                        (local == v6 || local.is_unspecified())
                            && port(r.dwLocalPort) == source.port()
                    })
                    .map(|r| r.dwOwningPid);
                pid
            }
        }
    }

    fn image_path(pid: u32) -> Option<String> {
        // SAFETY: plain Win32 calls; the handle is closed before returning.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 32768];
            let mut len = buf.len() as u32;
            let ok =
                QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(handle);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    pub fn find(
        network: Network,
        source: SocketAddr,
        _peer: Option<SocketAddr>,
    ) -> Option<ProcessInfo> {
        let pid = pid_of(network, source)?;
        let path = image_path(pid).unwrap_or_default();
        Some(ProcessInfo::from_path(pid, path, None))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
mod imp {
    use std::net::SocketAddr;

    use super::{Network, ProcessInfo};

    pub fn find(
        _network: Network,
        _source: SocketAddr,
        _peer: Option<SocketAddr>,
    ) -> Option<ProcessInfo> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_exe_name() -> String {
        std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn finds_this_process_for_tcp_and_udp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let info = find(
            Network::Tcp,
            client.local_addr().unwrap(),
            Some(listener.local_addr().unwrap()),
        )
        .expect("tcp lookup");
        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.name, current_exe_name());

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let info = find(Network::Udp, udp.local_addr().unwrap(), None).expect("udp lookup");
        assert_eq!(info.pid, std::process::id());

        let unused = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(find(Network::Tcp, unused, None).is_none() || cfg!(windows));
    }
}
