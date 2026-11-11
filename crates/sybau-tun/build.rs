//! Embeds `wintun.dll` into Windows builds when `SYBAU_WINTUN_DLL` points
//! to it (release CI downloads the official build and checks its SHA-256).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(sybau_wintun_embedded)");
    println!("cargo::rerun-if-env-changed=SYBAU_WINTUN_DLL");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let Ok(path) = std::env::var("SYBAU_WINTUN_DLL") else {
        return;
    };
    println!("cargo::rerun-if-changed={path}");
    let dll = std::fs::read(&path).unwrap_or_else(|e| panic!("SYBAU_WINTUN_DLL={path}: {e}"));
    assert!(
        dll.starts_with(b"MZ"),
        "SYBAU_WINTUN_DLL={path} is not a DLL"
    );
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("wintun.dll");
    std::fs::write(out, dll).unwrap();
    println!("cargo::rustc-cfg=sybau_wintun_embedded");
}
