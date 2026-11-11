//! Windows Filtering Platform filters: the kill switch and the DNS leak
//! protection of `strict_route`.
//!
//! Kill switch filters belong to a non-dynamic session, so they stay when
//! the core dies, and are not persistent, so a reboot lifts them. The DNS
//! block alone lives in a dynamic session held by the core: it goes away
//! with the core. Every object has a fixed key: installing replaces the
//! previous set in one transaction (no gap during a reload) and removing
//! needs no lookup.

use std::io;
use std::net::IpAddr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT16,
    FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const PROVIDER: GUID = GUID::from_u128(0x5b7d1a20_5359_4241_5543_4f5245000001);
const SUBLAYER: GUID = GUID::from_u128(0x5b7d1a20_5359_4241_5543_4f5245000002);
/// Filter keys are `FILTER_BASE + n`.
const FILTER_BASE: u128 = 0x5b7d1a20_5359_4241_5543_4f5246000000;
const MAX_FILTERS: u32 = 256;

const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const PROTO_UDP: u8 = 17;

/// What the filters let through.
pub struct FilterOptions<'a> {
    /// Block everything that does not leave through the TUN.
    pub kill_switch: bool,
    /// Block DNS (port 53) outside the TUN (`strict_route`).
    pub block_dns: bool,
    /// The TUN interface.
    pub tun_index: u32,
    /// Allowed outside the TUN anyway (LAN ranges, excluded routes).
    pub allow: &'a [(IpAddr, u8)],
}

enum Cond {
    AppId(*mut FWP_BYTE_BLOB),
    Interface(u64),
    Loopback,
    RemoteV4(u32, u32),
    RemoteV6([u8; 16], u8),
    RemotePort(u16),
    Protocol(u8),
}

struct Spec {
    v6: bool,
    permit: bool,
    weight: u8,
    conds: Vec<Cond>,
}

fn wide(s: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn check(code: u32, what: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what}: error {code:#010x}")))
    }
}

struct Engine(HANDLE);

// SAFETY: an engine handle may be used and closed from any thread.
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

/// A dynamic session; its filters disappear when it is dropped or the
/// process ends.
pub struct Session(#[allow(dead_code)] Engine);

impl Engine {
    fn open(dynamic: bool) -> io::Result<Self> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: an all-zero session record is valid.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = if dynamic {
            FWPM_SESSION_FLAG_DYNAMIC
        } else {
            0
        };
        // SAFETY: plain call with valid pointers.
        let code = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut handle,
            )
        };
        check(
            code,
            "cannot open the filtering engine (administrator rights are needed)",
        )?;
        Ok(Self(handle))
    }

    /// Runs `f` in a transaction: all of it applies, or none.
    fn transaction(&self, f: impl FnOnce(&Engine) -> io::Result<()>) -> io::Result<()> {
        // SAFETY: valid engine handle.
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "begin transaction",
        )?;
        match f(self) {
            Ok(()) => check(unsafe { FwpmTransactionCommit0(self.0) }, "commit"),
            Err(e) => {
                // SAFETY: a transaction is open.
                unsafe { FwpmTransactionAbort0(self.0) };
                Err(e)
            }
        }
    }

    fn delete_all(&self) {
        for n in 0..MAX_FILTERS {
            let key = GUID::from_u128(FILTER_BASE + u128::from(n));
            // SAFETY: valid handle and key; a missing filter is fine.
            unsafe { FwpmFilterDeleteByKey0(self.0, &key) };
        }
        // SAFETY: as above.
        unsafe {
            FwpmSubLayerDeleteByKey0(self.0, &SUBLAYER);
            FwpmProviderDeleteByKey0(self.0, &PROVIDER);
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

fn specs(o: &FilterOptions<'_>, app: *mut FWP_BYTE_BLOB, luid: u64) -> Vec<Spec> {
    let mut out = Vec::new();
    for v6 in [false, true] {
        let permit = |weight: u8, conds: Vec<Cond>| Spec {
            v6,
            permit: true,
            weight,
            conds,
        };
        // The core itself (its sockets are pinned to the uplink).
        out.push(permit(15, vec![Cond::AppId(app)]));
        out.push(permit(14, vec![Cond::Interface(luid)]));
        out.push(permit(13, vec![Cond::Loopback]));
        if o.kill_switch {
            // DHCP keeps the uplink's address.
            let dhcp_port = if v6 { 547 } else { 67 };
            out.push(permit(
                12,
                vec![Cond::Protocol(PROTO_UDP), Cond::RemotePort(dhcp_port)],
            ));
            for (ip, len) in o.allow.iter().filter(|(ip, _)| ip.is_ipv6() == v6) {
                let cond = match ip {
                    IpAddr::V4(v4) => {
                        let mask = u32::MAX.checked_shl(32 - u32::from(*len)).unwrap_or(0);
                        Cond::RemoteV4(u32::from(*v4) & mask, mask)
                    }
                    IpAddr::V6(v6) => Cond::RemoteV6(v6.octets(), *len),
                };
                out.push(permit(11, vec![cond]));
            }
            out.push(Spec {
                v6,
                permit: false,
                weight: 0,
                conds: Vec::new(),
            });
        } else if o.block_dns {
            out.push(Spec {
                v6,
                permit: false,
                weight: 1,
                conds: vec![Cond::RemotePort(53)],
            });
        }
    }
    out
}

fn add_filter(engine: &Engine, n: u32, spec: &Spec) -> io::Result<()> {
    // Values the conditions point to must outlive FwpmFilterAdd0.
    let mut u64s: Vec<Box<u64>> = Vec::new();
    let mut v4s: Vec<Box<FWP_V4_ADDR_AND_MASK>> = Vec::new();
    let mut v6s: Vec<Box<FWP_V6_ADDR_AND_MASK>> = Vec::new();
    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
    for c in &spec.conds {
        // SAFETY: an all-zero condition is a valid starting point.
        let mut fc: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        fc.matchType = FWP_MATCH_EQUAL;
        match c {
            Cond::AppId(blob) => {
                fc.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                fc.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                fc.conditionValue.Anonymous.byteBlob = *blob;
            }
            Cond::Interface(luid) => {
                u64s.push(Box::new(*luid));
                fc.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                fc.conditionValue.r#type = FWP_UINT64;
                fc.conditionValue.Anonymous.uint64 = &mut **u64s.last_mut().expect("pushed");
            }
            Cond::Loopback => {
                fc.fieldKey = FWPM_CONDITION_FLAGS;
                fc.matchType = FWP_MATCH_FLAGS_ALL_SET;
                fc.conditionValue.r#type = FWP_UINT32;
                fc.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            }
            Cond::RemoteV4(addr, mask) => {
                v4s.push(Box::new(FWP_V4_ADDR_AND_MASK {
                    addr: *addr,
                    mask: *mask,
                }));
                fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                fc.conditionValue.r#type = FWP_V4_ADDR_MASK;
                fc.conditionValue.Anonymous.v4AddrMask = &mut **v4s.last_mut().expect("pushed");
            }
            Cond::RemoteV6(addr, len) => {
                v6s.push(Box::new(FWP_V6_ADDR_AND_MASK {
                    addr: *addr,
                    prefixLength: *len,
                }));
                fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                fc.conditionValue.r#type = FWP_V6_ADDR_MASK;
                fc.conditionValue.Anonymous.v6AddrMask = &mut **v6s.last_mut().expect("pushed");
            }
            Cond::RemotePort(port) => {
                fc.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                fc.conditionValue.r#type = FWP_UINT16;
                fc.conditionValue.Anonymous.uint16 = *port;
            }
            Cond::Protocol(proto) => {
                fc.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                fc.conditionValue.r#type = FWP_UINT8;
                fc.conditionValue.Anonymous.uint8 = *proto;
            }
        }
        conds.push(fc);
    }
    let mut name = wide(std::path::Path::new("SYBAU-CORE TUN"));
    let mut provider = PROVIDER;
    // SAFETY: an all-zero filter is a valid starting point; every pointer
    // set below stays alive until the call returns.
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.filterKey = GUID::from_u128(FILTER_BASE + u128::from(n));
    filter.displayData.name = name.as_mut_ptr();
    filter.providerKey = &mut provider;
    filter.layerKey = if spec.v6 {
        FWPM_LAYER_ALE_AUTH_CONNECT_V6
    } else {
        FWPM_LAYER_ALE_AUTH_CONNECT_V4
    };
    filter.subLayerKey = SUBLAYER;
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = spec.weight;
    filter.numFilterConditions = conds.len() as u32;
    filter.filterCondition = if conds.is_empty() {
        std::ptr::null_mut()
    } else {
        conds.as_mut_ptr()
    };
    filter.action.r#type = if spec.permit {
        FWP_ACTION_PERMIT
    } else {
        FWP_ACTION_BLOCK
    };
    let mut id = 0u64;
    // SAFETY: see above.
    let code = unsafe { FwpmFilterAdd0(engine.0, &filter, std::ptr::null_mut(), &mut id) };
    check(code, "add filter")
}

/// Installs the filters. A kill switch atomically replaces an earlier
/// one and outlives the core; a DNS block alone is returned as a
/// [`Session`] that removes it when dropped. With neither, leftovers of
/// an earlier kill switch are removed.
pub fn install(o: &FilterOptions<'_>) -> io::Result<Option<Session>> {
    if !o.kill_switch {
        remove();
        if !o.block_dns {
            return Ok(None);
        }
    }
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: plain call with valid out pointer.
    check(
        unsafe { ConvertInterfaceIndexToLuid(o.tun_index, &mut luid) },
        "TUN interface",
    )?;
    // SAFETY: `Value` is the whole union.
    let luid = unsafe { luid.Value };
    let exe = std::env::current_exe()?;
    let exe_w = wide(&exe);
    let mut app: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated path and out pointer.
    check(
        unsafe { FwpmGetAppIdFromFileName0(exe_w.as_ptr(), &mut app) },
        "application id",
    )?;
    let engine = Engine::open(!o.kill_switch);
    let result = engine.and_then(|engine| {
        engine.transaction(|e| {
            e.delete_all();
            let mut name = wide(std::path::Path::new("SYBAU-CORE"));
            // SAFETY: zeroed provider/sublayer records, filled below.
            let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
            provider.providerKey = PROVIDER;
            provider.displayData.name = name.as_mut_ptr();
            let code = unsafe { FwpmProviderAdd0(e.0, &provider, std::ptr::null_mut()) };
            if code != FWP_E_ALREADY_EXISTS {
                check(code, "add provider")?;
            }
            let mut provider_key = PROVIDER;
            let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sublayer.subLayerKey = SUBLAYER;
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.providerKey = &mut provider_key;
            sublayer.weight = 0xffff;
            let code = unsafe { FwpmSubLayerAdd0(e.0, &sublayer, std::ptr::null_mut()) };
            if code != FWP_E_ALREADY_EXISTS {
                check(code, "add sublayer")?;
            }
            let specs = specs(o, app, luid);
            if specs.len() > MAX_FILTERS as usize {
                return Err(io::Error::other(
                    "too many route_exclude_address entries for the kill switch",
                ));
            }
            for (n, spec) in specs.iter().enumerate() {
                add_filter(e, n as u32, spec)?;
            }
            Ok(())
        })?;
        Ok(engine)
    });
    // SAFETY: allocated by FwpmGetAppIdFromFileName0.
    unsafe { FwpmFreeMemory0((&mut app as *mut *mut FWP_BYTE_BLOB).cast()) };
    let engine = result?;
    Ok((!o.kill_switch).then(|| Session(engine)))
}

/// Removes every filter of the core.
pub fn remove() {
    match Engine::open(false) {
        Ok(engine) => {
            if let Err(e) = engine.transaction(|e| {
                e.delete_all();
                Ok(())
            }) {
                tracing::warn!(target: "sybau::tun", "cannot remove the filters: {e}");
            }
        }
        Err(e) => tracing::warn!(target: "sybau::tun", "cannot remove the filters: {e}"),
    }
}
