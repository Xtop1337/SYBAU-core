//! Embeds the icon, version info and application manifest into `sybau.exe`
//! so that Explorer and Task Manager show "SYBAU-CORE".

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../assets/sybau.ico");
    println!("cargo:rerun-if-changed=../../assets/sybau.exe.manifest");
    println!("cargo:rerun-if-env-changed=SYBAU_SKIP_WINRES");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var_os("SYBAU_SKIP_WINRES").is_some() {
        println!("cargo:warning=SYBAU_SKIP_WINRES is set: sybau.exe is built without icon and version info");
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/sybau.ico");
    res.set_manifest_file("../../assets/sybau.exe.manifest");
    res.set("ProductName", "SYBAU-CORE");
    res.set("FileDescription", "SYBAU-CORE");
    res.set("CompanyName", "SYBAU");
    res.set("InternalName", "sybau");
    res.set("OriginalFilename", "sybau.exe");
    res.set("LegalCopyright", "GPL-3.0-or-later");
    if let Err(e) = res.compile() {
        panic!("cannot embed Windows resources into sybau.exe: {e} (set SYBAU_SKIP_WINRES=1 to build without them)");
    }
}
