//! Fetches the official WinDivert 2.2.2-A release, extracts the x64 DLL / driver / import
//! library into `vendor/windivert/`, and links `WinDivert.lib`.
//!
//! * MSVC: WinDivert.dll is delay-loaded (/DELAYLOAD + delayimp.lib), so the exe can extract
//!   its embedded copy of the DLL and driver before the first WinDivert call (single binary).
//! * GNU (mingw-w64): same idea, via a delay-import library generated with `dlltool -y`;
//!   if dlltool is missing it falls back to a regular import of WinDivert.lib.
//! * Both toolchains: the DLL and driver are also copied next to the produced exe.
//!
//! Offline builds: drop the three files into `vendor/windivert/`, or point `WINDIVERT_ZIP` at a
//! local copy of WinDivert-2.2.2-A.zip.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION: &str = "2.2.2";
const ZIP_NAME: &str = "WinDivert-2.2.2-A.zip";
const URLS: &[&str] = &[
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip",
    "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip",
];
const ZIP_SHA256: &str = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";
const FILES: &[&str] = &["WinDivert.dll", "WinDivert64.sys", "WinDivert.lib"];
/// Functions declared in src/windivert_engine/ffi.rs (for the GNU delay-import library).
const EXPORTS: &[&str] = &[
    "WinDivertOpen",
    "WinDivertRecv",
    "WinDivertSend",
    "WinDivertShutdown",
    "WinDivertClose",
    "WinDivertHelperCalcChecksums",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/windivert");
    println!("cargo:rerun-if-env-changed=WINDIVERT_ZIP");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest.join("vendor").join("windivert");
    println!("cargo:rustc-env=WINDIVERT_VENDOR_DIR={}", vendor.display());

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        // Pure-Rust modules (crypto, parsers, NAT table) still build and test on other hosts.
        return;
    }
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        panic!("dpi-bypass only supports x86_64 Windows (WinDivert64.sys)");
    }

    if let Err(e) = ensure_vendor(&vendor) {
        panic!(
            "failed to obtain WinDivert {VERSION}: {e}\n\
             Download {} manually and either set WINDIVERT_ZIP=<path to zip> or copy \
             x64/WinDivert.dll, x64/WinDivert64.sys and x64/WinDivert.lib into {}",
            URLS[0],
            vendor.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", vendor.display());
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-lib=dylib=WinDivert");
        println!("cargo:rustc-link-lib=delayimp");
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:WinDivert.dll");
    } else {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        match gnu_delay_lib(&out) {
            Ok(()) => {
                println!("cargo:rustc-link-search=native={}", out.display());
                println!("cargo:rustc-link-lib=dylib=WinDivert_delay");
            }
            Err(e) => {
                println!("cargo:warning=no delay-load import for WinDivert.dll ({e}); the exe needs WinDivert.dll beside it");
                println!("cargo:rustc-link-lib=dylib=WinDivert");
            }
        }
    }

    if let Some(exe_dir) = exe_dir() {
        for f in ["WinDivert.dll", "WinDivert64.sys"] {
            let dst = exe_dir.join(f);
            if !same_file_contents(&vendor.join(f), &dst) {
                let _ = fs::copy(vendor.join(f), dst);
            }
        }
    }
}

/// mingw-w64: builds libWinDivert_delay.a (resolved at first call by __delayLoadHelper2 from
/// libmingwex, which Rust's GNU targets always link).
fn gnu_delay_lib(out: &Path) -> Result<(), String> {
    let def = out.join("WinDivert.def");
    let mut text = String::from("LIBRARY WinDivert.dll\nEXPORTS\n");
    for e in EXPORTS {
        text.push_str(e);
        text.push('\n');
    }
    fs::write(&def, text).map_err(|e| format!("write .def: {e}"))?;
    let lib = out.join("libWinDivert_delay.a");
    let mut errors = Vec::new();
    for tool in ["x86_64-w64-mingw32-dlltool", "dlltool"] {
        match Command::new(tool).arg("--input-def").arg(&def).arg("--output-delaylib").arg(&lib).status() {
            Ok(s) if s.success() && lib.is_file() => return Ok(()),
            Ok(s) => errors.push(format!("{tool}: {s}")),
            Err(e) => errors.push(format!("{tool}: {e}")),
        }
    }
    Err(errors.join("; "))
}

/// target/<triple>/<profile>/build/<pkg>-<hash>/out -> target/<triple>/<profile>
fn exe_dir() -> Option<PathBuf> {
    PathBuf::from(env::var("OUT_DIR").ok()?).ancestors().nth(3).map(Path::to_path_buf)
}

fn same_file_contents(a: &Path, b: &Path) -> bool {
    match (fs::read(a), fs::read(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn ensure_vendor(vendor: &Path) -> Result<(), String> {
    if FILES.iter().all(|f| vendor.join(f).is_file()) {
        return Ok(());
    }
    fs::create_dir_all(vendor).map_err(|e| format!("create {}: {e}", vendor.display()))?;

    let zip_path = match env::var_os("WINDIVERT_ZIP") {
        Some(p) => PathBuf::from(p),
        None => {
            let p = PathBuf::from(env::var("OUT_DIR").unwrap()).join(ZIP_NAME);
            if !p.is_file() || sha256_file(&p).as_deref() != Ok(ZIP_SHA256) {
                download(&p)?;
            }
            p
        }
    };

    let digest = sha256_file(&zip_path)?;
    if digest != ZIP_SHA256 {
        return Err(format!("{} has SHA-256 {digest}, expected {ZIP_SHA256}", zip_path.display()));
    }
    extract(&zip_path, vendor)
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let data = fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    Ok(hex(&Sha256::digest(&data)))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn download(dst: &Path) -> Result<(), String> {
    let mut errors = Vec::new();
    for url in URLS {
        let _ = fs::remove_file(dst);
        // curl ships with Windows 10 1803+ and every Linux/macOS host.
        match Command::new("curl")
            .args(["-fsSL", "--retry", "3", "--connect-timeout", "20", "-o"])
            .arg(dst)
            .arg(url)
            .status()
        {
            Ok(s) if s.success() && dst.is_file() => return Ok(()),
            Ok(s) => errors.push(format!("curl {url}: {s}")),
            Err(e) => errors.push(format!("curl: {e}")),
        }
        if cfg!(windows) {
            let script = format!(
                "$ProgressPreference='SilentlyContinue';\
                 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;\
                 Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile '{}'",
                dst.display()
            );
            match Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
                .status()
            {
                Ok(s) if s.success() && dst.is_file() => return Ok(()),
                Ok(s) => errors.push(format!("powershell {url}: {s}")),
                Err(e) => errors.push(format!("powershell: {e}")),
            }
        }
    }
    Err(errors.join("; "))
}

fn extract(zip_path: &Path, vendor: &Path) -> Result<(), String> {
    let f = fs::File::open(zip_path).map_err(|e| format!("open {}: {e}", zip_path.display()))?;
    let mut z = zip::ZipArchive::new(f).map_err(|e| format!("bad zip: {e}"))?;
    for name in FILES {
        let inner = format!("WinDivert-{VERSION}-A/x64/{name}");
        let mut entry = z.by_name(&inner).map_err(|e| format!("{inner}: {e}"))?;
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data).map_err(|e| format!("{inner}: {e}"))?;
        let tmp = vendor.join(format!("{name}.part"));
        fs::write(&tmp, &data).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, vendor.join(name)).map_err(|e| format!("rename {name}: {e}"))?;
    }
    Ok(())
}
