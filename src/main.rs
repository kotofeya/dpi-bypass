//! Serverless DPI mitigation client for YouTube and Discord (Windows).
//!
//!  Engine A (windivert_engine) — packet-level desync (TLS/HTTP split + fakes, QUIC, voice UDP)
//!  Engine C (prober)           — strategy search and health checks

#![cfg_attr(not(windows), allow(dead_code))]

mod prober;
mod windivert_engine;

#[cfg(not(windows))]
fn main() {
    eprintln!("dpi-bypass needs Windows (WinDivert); build with --target x86_64-pc-windows-msvc");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let arg_value = |args: &[String], name: &str| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };

    // Log filter: --log <filter>, -v / --verbose (= debug), else RUST_LOG, else info.
    // The UAC relaunch does not inherit environment variables, so RUST_LOG is forwarded as --log.
    let filter = arg_value(&args, "--log")
        .or_else(|| args.iter().any(|a| a == "-v" || a == "--verbose").then(|| "debug".to_string()))
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".to_string());
    let ansi = win::enable_ansi();
    tracing_subscriber::fmt()
        .with_ansi(ansi)
        .with_env_filter(tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|_| "info".into()))
        .init();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "dpi-bypass [-v | --log <filter>]\n\n\
             Needs Administrator rights (relaunches itself via UAC) to load the WinDivert driver.\n\
             -v shows packet-level debug logs."
        );
        return Ok(());
    }

    if !win::is_elevated() {
        if arg_value(&args, "--log").is_none() {
            args.push("--log".into());
            args.push(filter.clone());
        }
        match win::relaunch_elevated(&args) {
            Ok(()) => {
                tracing::info!("relaunched elevated, exiting this instance");
                return Ok(());
            }
            Err(e) => anyhow::bail!("Administrator rights are required to load the WinDivert driver ({e})"),
        }
    }

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
}

#[cfg(windows)]
async fn run() -> anyhow::Result<()> {
    use std::sync::Arc;
    use tracing::{info, warn};

    match win::primary_ipv4() {
        Some(ip) => info!("primary interface address: {ip}"),
        None => warn!("no IPv4 default route found; only IPv4 traffic is handled"),
    }

    let shared = prober::profile::shared_default();
    let engine = Arc::new(windivert_engine::Engine::open(shared.clone())?);
    let a_thread = {
        let e = engine.clone();
        std::thread::Builder::new().name("engine-a".into()).spawn(move || {
            if let Err(err) = e.run() {
                tracing::error!("engine A stopped: {err:#}");
            }
        })?
    };

    tokio::spawn(prober::run(shared.clone()));

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    engine.shutdown();
    let _ = a_thread.join();
    Ok(())
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// Turns on VT escape processing so log colours render in old consoles (Windows
    /// PowerShell 5 / conhost). Returns false when colours should be disabled instead.
    pub fn enable_ansi() -> bool {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
        };
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode = 0u32;
            if h.is_null() || GetConsoleMode(h, &mut mode) == 0 {
                return false; // redirected to a file/pipe: plain text
            }
            mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
                || SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        }
    }

    /// Is this process running with an elevated (Administrator) token?
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut el = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut el as *mut TOKEN_ELEVATION as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && el.TokenIsElevated != 0
        }
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    fn quote(a: &str) -> String {
        if !a.is_empty() && !a.contains([' ', '\t', '"']) {
            return a.to_string();
        }
        format!("\"{}\"", a.replace('"', "\\\""))
    }

    /// Starts a second, elevated copy of ourselves through the UAC prompt.
    pub fn relaunch_elevated(args: &[String]) -> std::io::Result<()> {
        let exe = std::env::current_exe()?;
        let params = args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
        let verb = wide("runas".as_ref());
        let file = wide(exe.as_os_str());
        let params = wide(params.as_ref());
        let r = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecute returns a value > 32 on success
        if r as isize > 32 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Address of the interface holding the IPv4 default route (no packet is sent).
    pub fn primary_ipv4() -> Option<Ipv4Addr> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        s.connect("1.1.1.1:53").ok()?;
        match s.local_addr().ok()?.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
            _ => None,
        }
    }
}
