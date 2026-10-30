//! Thin runtime binding to WinDivert 2.2 (network layer).
//! The DLL and driver are embedded in the exe, extracted to %TEMP% and loaded with
//! LoadLibrary, so the product stays a single binary. WinDivert64.sys must sit next to the DLL.

use anyhow::Result;
use libloading::Library;
use std::ffi::{c_char, c_void, CString};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static DLL: &[u8] = include_bytes!("../vendor/WinDivert.dll");
static SYS: &[u8] = include_bytes!("../vendor/WinDivert64.sys");

/// WINDIVERT_ADDRESS (WinDivert 2.2): 80 bytes.
/// flags bit layout: Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1
///                   IPChecksum:1 TCPChecksum:1 UDPChecksum:1
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}
impl Address {
    pub fn zeroed() -> Self {
        Address { timestamp: 0, flags: 0, reserved2: 0, data: [0; 64] }
    }
    pub fn outbound(&self) -> bool {
        self.flags & (1 << 17) != 0
    }
}

type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> *mut c_void;
type RecvFn = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(*mut c_void, *const c_void, u32, *mut u32, *const Address) -> i32;
type CalcFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;
type CloseFn = unsafe extern "C" fn(*mut c_void) -> i32;

pub struct Divert {
    _lib: Library,
    h: *mut c_void,
    recv: RecvFn,
    send: SendFn,
    calc: CalcFn,
    close: CloseFn,
    closed: AtomicBool,
}
unsafe impl Send for Divert {}
unsafe impl Sync for Divert {}

fn extract() -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("dpib-{}", env!("CARGO_PKG_VERSION")));
    std::fs::create_dir_all(&dir)?;
    for (name, bytes) in [("WinDivert.dll", DLL), ("WinDivert64.sys", SYS)] {
        let p = dir.join(name);
        let same = std::fs::metadata(&p).map(|m| m.len() == bytes.len() as u64).unwrap_or(false);
        if !same {
            std::fs::write(&p, bytes)?;
        }
    }
    Ok(dir.join("WinDivert.dll"))
}

impl Divert {
    pub fn open(filter: &str, priority: i16) -> Result<Self> {
        let path = extract()?;
        unsafe {
            let lib = Library::new(&path)?;
            let open: OpenFn = *lib.get::<OpenFn>(b"WinDivertOpen\0")?;
            let recv: RecvFn = *lib.get::<RecvFn>(b"WinDivertRecv\0")?;
            let send: SendFn = *lib.get::<SendFn>(b"WinDivertSend\0")?;
            let calc: CalcFn = *lib.get::<CalcFn>(b"WinDivertHelperCalcChecksums\0")?;
            let close: CloseFn = *lib.get::<CloseFn>(b"WinDivertClose\0")?;
            let cf = CString::new(filter)?;
            let h = open(cf.as_ptr(), 0 /* WINDIVERT_LAYER_NETWORK */, priority, 0);
            if h as isize == -1 {
                let e = io::Error::last_os_error();
                // 5 = needs Administrator, 87 = bad filter, 577 = driver signature, 1275 = blocked by AV/HVCI
                anyhow::bail!("WinDivertOpen failed: {e} (run elevated; code 87 = bad filter, 577/1275 = driver blocked)");
            }
            Ok(Divert { _lib: lib, h, recv, send, calc, close, closed: AtomicBool::new(false) })
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut a = Address::zeroed();
        let mut n = 0u32;
        let ok = unsafe { (self.recv)(self.h, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, &mut a) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok((n as usize, a)) }
    }

    pub fn send(&self, pkt: &[u8], addr: &Address) -> io::Result<()> {
        let mut n = 0u32;
        let ok = unsafe { (self.send)(self.h, pkt.as_ptr().cast(), pkt.len() as u32, &mut n, addr) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Recompute IPv4 + TCP/UDP checksums in place.
    pub fn calc_checksums(&self, pkt: &mut [u8], addr: &mut Address) {
        unsafe { (self.calc)(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0) };
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            unsafe { (self.close)(self.h) };
        }
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}
impl Drop for Divert {
    fn drop(&mut self) {
        self.close();
    }
}
