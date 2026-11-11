//! Windows routing through the IP Helper API.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

/// `MIB_IPPROTO_NETMGMT`: a route added by management (like `route add`).
const PROTO_NETMGMT: i32 = 3;

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: an all-zero SOCKADDR_INET is valid (family AF_UNSPEC).
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}

fn ip_of(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family field is shared by every member of the union and
    // selects which member is valid.
    unsafe {
        match sa.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// Metric of an interface and whether it is connected.
fn interface_state(family: u16, index: u32) -> Option<(u32, bool)> {
    // SAFETY: the row is initialised by the API before use.
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = family;
        row.InterfaceIndex = index;
        if GetIpInterfaceEntry(&mut row) != NO_ERROR {
            return None;
        }
        Some((row.Metric, row.Connected != 0))
    }
}

/// The system's preferred default route of a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub index: u32,
    pub next_hop: IpAddr,
}

/// Best default route (prefix length 0) on a connected interface other
/// than `skip_index`. The TUN only adds narrower routes (`0.0.0.0/1` and
/// `128.0.0.0/1`), so this keeps finding the physical uplink.
pub fn default_route(v6: bool, skip_index: u32) -> Option<DefaultRoute> {
    let family = if v6 { AF_INET6 } else { AF_INET };
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: on success the API allocates the table, freed below.
    if unsafe { GetIpForwardTable2(family, &mut table) } != NO_ERROR || table.is_null() {
        return None;
    }
    // SAFETY: the table holds `NumEntries` rows.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut best: Option<(u32, DefaultRoute)> = None;
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0
            || row.InterfaceIndex == skip_index
            || row.Loopback != 0
        {
            continue;
        }
        let Some((if_metric, connected)) = interface_state(family, row.InterfaceIndex) else {
            continue;
        };
        if !connected {
            continue;
        }
        let Some(next_hop) = ip_of(&row.NextHop) else {
            continue;
        };
        let metric = row.Metric.saturating_add(if_metric);
        if best.as_ref().is_none_or(|(m, _)| metric < *m) {
            best = Some((
                metric,
                DefaultRoute {
                    index: row.InterfaceIndex,
                    next_hop,
                },
            ));
        }
    }
    // SAFETY: allocated by GetIpForwardTable2.
    unsafe { FreeMibTable(table.cast()) };
    best.map(|(_, r)| r)
}

/// Interface indexes of the IPv4 and IPv6 uplinks (0 when there is none).
pub fn uplinks(skip_index: u32) -> (u32, u32) {
    (
        default_route(false, skip_index).map_or(0, |r| r.index),
        default_route(true, skip_index).map_or(0, |r| r.index),
    )
}

/// A route this process added; deleted with [`delete_route`].
pub struct Route(MIB_IPFORWARD_ROW2);

// SAFETY: the row is plain data (addresses, indexes, numbers).
unsafe impl Send for Route {}
unsafe impl Sync for Route {}

/// Adds `prefix/len` via `index` (on-link when `next_hop` is `None`).
/// Returns `None` if an identical route already exists: it is not ours
/// to delete later.
pub fn add_route(
    prefix: IpAddr,
    len: u8,
    index: u32,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> io::Result<Option<Route>> {
    let unspecified = if prefix.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    // SAFETY: the row is initialised by the API, then filled in.
    let row = unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = index;
        row.DestinationPrefix.Prefix = sockaddr(prefix);
        row.DestinationPrefix.PrefixLength = len;
        row.NextHop = sockaddr(next_hop.unwrap_or(unspecified));
        row.Metric = metric;
        row.Protocol = PROTO_NETMGMT;
        row
    };
    // SAFETY: `row` is a fully initialised route.
    match unsafe { CreateIpForwardEntry2(&row) } {
        NO_ERROR => Ok(Some(Route(row))),
        ERROR_OBJECT_ALREADY_EXISTS => Ok(None),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

pub fn delete_route(route: &Route) {
    // SAFETY: the row describes a route created by `add_route`.
    let code = unsafe { DeleteIpForwardEntry2(&route.0) };
    if code != NO_ERROR {
        tracing::debug!(target: "sybau::tun", "delete route: error {code}");
    }
}
