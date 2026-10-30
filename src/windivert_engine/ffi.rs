//! Binding to WinDivert 2.2 (network layer), linked against WinDivert.lib.
//!
//! On MSVC the DLL is delay-loaded (see build.rs): `prepare()` writes the embedded
//! WinDivert.dll + WinDivert64.sys next to the exe (or into %LOCALAPPDATA% when that is not
//! writable) and points the loader there before the first call. WinDivert.dll installs the
//! driver from its own directory, so both files must sit side by side.

use anyhow::{bail, Context, Result};
use std::ffi::{c_char, c_void, CString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};

static DLL: &[u8] = include_bytes!(concat!(env!("WINDIVERT_VENDOR_DIR"), "/WinDivert.dll"));
static SYS: &[u8] = include_bytes!(concat!(env!("WINDIVERT_VENDOR_DIR"), "/WinDivert64.sys"));

const LAYER_NETWORK: i32 = 0;
const SHUTDOWN_BOTH: i32 = 3;
const INVALID_HANDLE: isize = -1;

/// WINDIVERT_ADDRESS (WinDivert 2.2): 80 bytes.
/// flags bit layout: Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1
///                   IPChecksum:1 TCPChecksum:1 UDPChecksum:1 Reserved1:8
/// data (network layer): IfIdx:u32 SubIfIdx:u32 — kept as-is when reflecting a packet, so
/// the "inbound" copy is delivered on the interface the original left from.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

const OUTBOUND_BIT: u32 = 1 << 17;

impl Address {
    pub fn zeroed() -> Self {
        Address { timestamp: 0, flags: 0, reserved2: 0, data: [0; 64] }
    }
    pub fn set_outbound(&mut self, v: bool) {
        if v {
            self.flags |= OUTBOUND_BIT;
        } else {
            self.flags &= !OUTBOUND_BIT;
        }
    }
}

// Linked by build.rs (WinDivert.lib, delay-loaded).
extern "C" {
    fn WinDivertOpen(filter: *const c_char, layer: i32, priority: i16, flags: u64) -> *mut c_void;
    fn WinDivertRecv(h: *mut c_void, pkt: *mut c_void, len: u32, recv_len: *mut u32, addr: *mut Address) -> i32;
    fn WinDivertSend(h: *mut c_void, pkt: *const c_void, len: u32, send_len: *mut u32, addr: *const Address) -> i32;
    fn WinDivertShutdown(h: *mut c_void, how: i32) -> i32;
    fn WinDivertClose(h: *mut c_void) -> i32;
    fn WinDivertHelperCalcChecksums(pkt: *mut c_void, len: u32, addr: *mut Address, flags: u64) -> i32;
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn write_if_different(p: &Path, bytes: &[u8]) -> io::Result<()> {
    if std::fs::read(p).map(|cur| cur == bytes).unwrap_or(false) {
        return Ok(());
    }
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, p).or_else(|e| {
        let _ = std::fs::remove_file(&tmp);
        // the driver file is locked while the service runs; identical content is fine then
        if std::fs::metadata(p).map(|m| m.len() == bytes.len() as u64).unwrap_or(false) {
            Ok(())
        } else {
            Err(e)
        }
    })
}

fn install_to(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_if_different(&dir.join("WinDivert.dll"), DLL)?;
    write_if_different(&dir.join("WinDivert64.sys"), SYS)?;
    Ok(())
}

/// Extracts the embedded DLL + driver and makes the delay-load helper find them.
fn prepare() -> Result<PathBuf> {
    static DIR: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    DIR.get_or_init(|| {
        let mut candidates = Vec::new();
        if let Some(d) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
            candidates.push(d);
        }
        if let Some(d) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(PathBuf::from(d).join("dpi-bypass").join(env!("CARGO_PKG_VERSION")));
        }
        let mut errs = Vec::new();
        for dir in candidates {
            match install_to(&dir) {
                Ok(()) => {
                    let w = wide(&dir);
                    let dll = wide(&dir.join("WinDivert.dll"));
                    unsafe {
                        SetDllDirectoryW(w.as_ptr());
                        if LoadLibraryW(dll.as_ptr()).is_null() {
                            errs.push(format!("LoadLibrary {}: {}", dir.display(), io::Error::last_os_error()));
                            continue;
                        }
                    }
                    return Ok(dir);
                }
                Err(e) => errs.push(format!("{}: {e}", dir.display())),
            }
        }
        Err(errs.join("; "))
    })
    .clone()
    .map_err(|e| anyhow::anyhow!("cannot install WinDivert.dll: {e}"))
}

pub struct Divert {
    h: *mut c_void,
    closed: AtomicBool,
}
// WinDivert handles are safe to use from multiple threads (overlapped I/O inside the DLL).
unsafe impl Send for Divert {}
unsafe impl Sync for Divert {}

impl Divert {
    pub fn open(filter: &str, priority: i16) -> Result<Self> {
        let dir = prepare()?;
        tracing::debug!("WinDivert loaded from {}", dir.display());
        let cf = CString::new(filter).context("filter contains NUL")?;
        let h = unsafe { WinDivertOpen(cf.as_ptr(), LAYER_NETWORK, priority, 0) };
        if h as isize == INVALID_HANDLE || h.is_null() {
            let e = io::Error::last_os_error();
            let hint = match e.raw_os_error() {
                Some(2) => "WinDivert64.sys not found next to WinDivert.dll",
                Some(5) => "run as Administrator",
                Some(87) => "invalid filter",
                Some(577) | Some(1275) => "driver blocked (signature / HVCI / anti-virus)",
                Some(654) => "an incompatible WinDivert driver version is already loaded",
                _ => "see WinDivert documentation",
            };
            bail!("WinDivertOpen failed: {e} ({hint})");
        }
        Ok(Divert { h, closed: AtomicBool::new(false) })
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut a = Address::zeroed();
        let mut n = 0u32;
        let ok = unsafe { WinDivertRecv(self.h, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, &mut a) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((n as usize, a))
        }
    }

    pub fn send(&self, pkt: &[u8], addr: &Address) -> io::Result<()> {
        let mut n = 0u32;
        let ok = unsafe { WinDivertSend(self.h, pkt.as_ptr().cast(), pkt.len() as u32, &mut n, addr) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Recompute IPv4/IPv6 + TCP/UDP checksums in place (also marks them valid in `addr`).
    pub fn calc_checksums(&self, pkt: &mut [u8], addr: &mut Address) {
        unsafe { WinDivertHelperCalcChecksums(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0) };
    }

    /// Unblocks threads sitting in `recv` (they then fail and observe `is_closed`). The
    /// handle itself is released on drop, once no thread can touch it any more.
    pub fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            unsafe { WinDivertShutdown(self.h, SHUTDOWN_BOTH) };
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        self.shutdown();
        unsafe { WinDivertClose(self.h) };
    }
}
