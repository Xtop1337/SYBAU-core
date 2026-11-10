//! C API of SYBAU-CORE (see `include/sybau.h`).
//!
//! The library hosts one core per process. All functions are thread-safe
//! and must not be called from inside a callback.

use std::ffi::{c_char, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{json, Value};
use sybau_core::{logging, Engine, EngineOptions, RpcError};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

pub const SYBAU_OK: i32 = 0;
pub const SYBAU_ERR_INVALID_ARGUMENT: i32 = 1;
pub const SYBAU_ERR_ALREADY_RUNNING: i32 = 2;
pub const SYBAU_ERR_START_FAILED: i32 = 3;
pub const SYBAU_ERR_NOT_RUNNING: i32 = 4;
pub const SYBAU_ERR_PANIC: i32 = 5;

/// Receives events (`{"method":"log"|"stats","params":{...}}`) as JSON.
/// The string is only valid during the call.
pub type SybauEventCallback = extern "C" fn(user: *mut c_void, json: *const c_char);
/// Must exclude the socket `fd` from the VPN and return non-zero on success.
pub type SybauProtectCallback = extern "C" fn(user: *mut c_void, fd: i64) -> i32;

#[derive(Clone, Copy)]
struct Callback<F> {
    func: F,
    user: usize,
}

struct Core {
    engine: Engine,
    feeds: Vec<JoinHandle<()>>,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static CORE: Mutex<Option<Core>> = Mutex::new(None);
static EVENT_CB: Mutex<Option<Callback<SybauEventCallback>>> = Mutex::new(None);
static PROTECT_CB: Mutex<Option<Callback<SybauProtectCallback>>> = Mutex::new(None);

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("sybau-worker")
            .build()
            .expect("cannot create the SYBAU-CORE runtime")
    })
}

fn to_c(s: String) -> *mut c_char {
    CString::new(s.replace('\0', " "))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `ptr` must be null or point to a NUL-terminated string.
unsafe fn from_c<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by the caller.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn emit(event: &Value) {
    let cb = *EVENT_CB.lock();
    if let Some(cb) = cb {
        if let Ok(text) = CString::new(event.to_string()) {
            (cb.func)(cb.user as *mut c_void, text.as_ptr());
        }
    }
}

async fn log_feed() {
    let mut rx = logging::subscribe();
    loop {
        match rx.recv().await {
            Ok(line) => emit(&json!({ "method": "log", "params": line })),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return,
        }
    }
}

async fn stats_feed(engine: Engine) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let (mut last_up, mut last_down) = engine.stats().total.snapshot();
    loop {
        ticker.tick().await;
        if EVENT_CB.lock().is_none() {
            continue;
        }
        let (up, down) = engine.stats().total.snapshot();
        emit(&json!({ "method": "stats", "params": {
            "up": up, "down": down, "up_rate": up - last_up, "down_rate": down - last_down,
            "connections": engine.stats().connection_count(),
        }}));
        (last_up, last_down) = (up, down);
    }
}

fn set_error(out: *mut *mut c_char, msg: String) {
    if !out.is_null() {
        // SAFETY: the caller passed a valid location for the error string.
        unsafe { *out = to_c(msg) };
    }
}

/// Version string, e.g. `"0.1.0"`. Static; do not free.
#[no_mangle]
pub extern "C" fn sybau_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Starts the core with a JSON config.
///
/// On failure a message is stored in `*error_out` (if not null); release it
/// with `sybau_free_string`.
///
/// # Safety
/// `config_json` must be null or a NUL-terminated UTF-8 string; `error_out`
/// must be null or a valid pointer to a `char*`.
#[no_mangle]
pub unsafe extern "C" fn sybau_start(
    config_json: *const c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    // SAFETY: forwarded caller guarantee.
    let Some(text) = (unsafe { from_c(config_json) }) else {
        set_error(error_out, "config_json is null or not UTF-8".into());
        return SYBAU_ERR_INVALID_ARGUMENT;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut core = CORE.lock();
        if core.is_some() {
            return Err((
                SYBAU_ERR_ALREADY_RUNNING,
                "core is already running".to_string(),
            ));
        }
        logging::init(false);
        let config = sybau_config::parse_native(text)
            .map_err(|e| (SYBAU_ERR_START_FAILED, format!("{e:#}")))?;
        let protect: Option<sybau_common::net::ProtectFn> = Some(Arc::new(|fd: i64| {
            let cb = *PROTECT_CB.lock();
            match cb {
                Some(cb) => (cb.func)(cb.user as *mut c_void, fd) != 0,
                None => true,
            }
        }));
        let engine = Engine::new(EngineOptions {
            profile: "embedded".into(),
            config_path: None,
            loader: None,
            protect,
        });
        let rt = runtime();
        rt.block_on(engine.start(config))
            .map_err(|e| (SYBAU_ERR_START_FAILED, format!("{e:#}")))?;
        let feeds = vec![rt.spawn(log_feed()), rt.spawn(stats_feed(engine.clone()))];
        *core = Some(Core { engine, feeds });
        Ok(())
    }));
    match result {
        Ok(Ok(())) => SYBAU_OK,
        Ok(Err((code, msg))) => {
            set_error(error_out, msg);
            code
        }
        Err(_) => {
            set_error(error_out, "internal error (panic)".into());
            SYBAU_ERR_PANIC
        }
    }
}

/// Stops the core and closes every connection.
#[no_mangle]
pub extern "C" fn sybau_stop() -> i32 {
    catch_unwind(|| {
        let core = CORE.lock().take();
        match core {
            Some(core) => {
                runtime().block_on(core.engine.stop());
                core.feeds.iter().for_each(JoinHandle::abort);
                SYBAU_OK
            }
            None => SYBAU_ERR_NOT_RUNNING,
        }
    })
    .unwrap_or(SYBAU_ERR_PANIC)
}

fn rpc_response(id: &Value, result: Result<Value, RpcError>) -> String {
    match result {
        Ok(v) => json!({ "id": id, "result": v }).to_string(),
        Err(e) => {
            json!({ "id": id, "error": { "code": e.code, "message": e.message } }).to_string()
        }
    }
}

/// Executes one control request (`{"id":1,"method":"stats.get","params":{}}`)
/// and returns the JSON response. Release it with `sybau_free_string`.
/// The methods are the same as on the control channel of `sybau.exe`,
/// except `*.subscribe`: events arrive through the event callback instead.
///
/// # Safety
/// `request_json` must be null or a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn sybau_call(request_json: *const c_char) -> *mut c_char {
    // SAFETY: forwarded caller guarantee.
    let Some(text) = (unsafe { from_c(request_json) }) else {
        return to_c(rpc_response(
            &Value::Null,
            Err(RpcError::parse("request is null or not UTF-8")),
        ));
    };
    let out = catch_unwind(AssertUnwindSafe(|| {
        let req: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => return rpc_response(&Value::Null, Err(RpcError::parse(e))),
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return rpc_response(&id, Err(RpcError::parse("`method` is required")));
        };
        let engine = CORE.lock().as_ref().map(|c| c.engine.clone());
        let Some(engine) = engine else {
            return rpc_response(&id, Err(RpcError::failed("core is not running")));
        };
        rpc_response(&id, runtime().block_on(engine.call(method, &params)))
    }));
    to_c(out.unwrap_or_else(|_| {
        rpc_response(
            &Value::Null,
            Err(RpcError::failed("internal error (panic)")),
        )
    }))
}

/// Sets (or clears, with a null `callback`) the event callback. It is
/// invoked from core threads.
#[no_mangle]
pub extern "C" fn sybau_set_event_callback(
    callback: Option<SybauEventCallback>,
    user: *mut c_void,
) {
    *EVENT_CB.lock() = callback.map(|func| Callback {
        func,
        user: user as usize,
    });
}

/// Sets (or clears) the socket protect callback. Call before `sybau_start`.
#[no_mangle]
pub extern "C" fn sybau_set_protect_callback(
    callback: Option<SybauProtectCallback>,
    user: *mut c_void,
) {
    *PROTECT_CB.lock() = callback.map(|func| Callback {
        func,
        user: user as usize,
    });
}

/// Releases a string returned by this library.
///
/// # Safety
/// `s` must be null or a pointer returned by this library that was not
/// freed before.
#[no_mangle]
pub unsafe extern "C" fn sybau_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: guaranteed by the caller.
        drop(unsafe { CString::from_raw(s) });
    }
}
