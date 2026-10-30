//! Serverless DPI mitigation client for YouTube, Discord and Telegram Desktop (Windows).
//!
//!  Engine A (windivert_engine) — packet-level desync + transparent Telegram redirect
//!  Engine B (tg_bridge)        — Telegram MTProto over wss://kws*.web.telegram.org
//!  Engine C (prober)           — strategy search and gateway / Cloudflare health checks

#![cfg_attr(not(windows), allow(dead_code))]

mod nat_table;
mod obfs2;
mod prober;
mod tg_bridge;
mod windivert_engine;

#[cfg(not(windows))]
fn main() {
    eprintln!("dpi-bypass needs Windows (WinDivert); build with --target x86_64-pc-windows-msvc");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "dpi-bypass [--no-elevate] [--bridge-port N]\n\n\
             Runs elevated (relaunches itself via UAC). RUST_LOG=debug for packet-level logs.\n\
             Without Administrator rights only the SOCKS5 ({}) and MTProxy ({}) fallbacks run.",
            tg_bridge::SOCKS_ADDR,
            tg_bridge::MTP_ADDR
        );
        return Ok(());
    }

    let elevated = win::is_elevated();
    if !elevated && !args.iter().any(|a| a == "--no-elevate") {
        match win::relaunch_elevated(&args) {
            Ok(()) => {
                tracing::info!("relaunched elevated, exiting this instance");
                return Ok(());
            }
            Err(e) => tracing::warn!("elevation declined/failed ({e}); running without the packet engine"),
        }
    }

    let bridge_port = args
        .iter()
        .position(|a| a == "--bridge-port")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(tg_bridge::DEFAULT_BRIDGE_PORT);

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run(elevated, bridge_port))
}

#[cfg(windows)]
async fn run(elevated: bool, bridge_port: u16) -> anyhow::Result<()> {
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{error, info, warn};

    match win::primary_ipv4() {
        Some(ip) => info!("primary interface address: {ip}"),
        None => warn!("no IPv4 default route found; transparent Telegram redirect needs IPv4"),
    }

    let shared = prober::profile::shared_default();
    let nat = Arc::new(nat_table::NatTable::new());
    let dialer = Arc::new(tg_bridge::dialer::WsDialer::new(shared.clone(), nat.clone(), vec![]));
    let ctx = Arc::new(tg_bridge::Ctx::new(dialer, tg_bridge::load_secret()));

    // The transparent listener must exist before WinDivert starts reflecting SYNs into it.
    // Reflected flows arrive as inbound connections from Telegram addresses, so the firewall
    // has to let them reach the bridge port.
    if elevated {
        if let Err(e) = win::allow_bridge_port(bridge_port) {
            warn!("firewall rule for port {bridge_port} not installed: {e}");
        }
    }
    let transparent = if elevated {
        match tg_bridge::bind_transparent(bridge_port).await {
            Ok(l) => Some(l),
            Err(e) => {
                error!("cannot bind bridge port {bridge_port}: {e:#} (try --bridge-port)");
                None
            }
        }
    } else {
        None
    };

    // Engine A
    let engine = match &transparent {
        Some(_) => match windivert_engine::Engine::open(shared.clone(), nat.clone(), bridge_port) {
            Ok(e) => Some(Arc::new(e)),
            Err(e) => {
                error!("Engine A disabled: {e:#}");
                None
            }
        },
        None => None,
    };
    let a_thread = engine.as_ref().map(|e| {
        let e = e.clone();
        std::thread::Builder::new()
            .name("engine-a".into())
            .spawn(move || {
                if let Err(err) = e.run() {
                    error!("engine A stopped: {err:#}");
                }
            })
            .expect("spawn engine A thread")
    });

    // Engine B
    if let (Some(l), true) = (transparent, engine.is_some()) {
        tokio::spawn(tg_bridge::serve_transparent(l, ctx.clone()));
        info!("Telegram Desktop is redirected transparently, no proxy settings needed");
        let n = nat.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(10));
            loop {
                iv.tick().await;
                let removed = n.gc();
                if removed > 0 {
                    tracing::debug!("NAT: {removed} expired, {} active", n.len());
                }
            }
        });
    }
    tokio::spawn(log_err("SOCKS5", tg_bridge::serve_socks(ctx.clone())));
    tokio::spawn(log_err("MTProxy", tg_bridge::serve_mtproxy(ctx.clone())));
    info!("manual fallback: SOCKS5 {} or {}", tg_bridge::SOCKS_ADDR, tg_bridge::proxy_link(&ctx.secret));

    // Engine C
    tokio::spawn(prober::run(shared.clone(), ctx.clone(), engine.is_some()));

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    if let Some(e) = &engine {
        e.shutdown();
    }
    if let Some(t) = a_thread {
        let _ = t.join();
    }
    Ok(())
}

#[cfg(windows)]
async fn log_err(what: &'static str, f: impl std::future::Future<Output = anyhow::Result<()>>) {
    if let Err(e) = f.await {
        tracing::error!("{what}: {e:#}");
    }
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

    const FW_RULE: &str = "dpi-bypass Telegram bridge";

    /// (Re)creates an inbound allow rule for this exe on the bridge port.
    pub fn allow_bridge_port(port: u16) -> std::io::Result<()> {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let exe = std::env::current_exe()?;
        let netsh = |args: &[String]| {
            Command::new("netsh")
                .args(["advfirewall", "firewall"])
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status()
        };
        let _ = netsh(&["delete".into(), "rule".into(), format!("name={FW_RULE}")]);
        let st = netsh(&[
            "add".into(),
            "rule".into(),
            format!("name={FW_RULE}"),
            "dir=in".into(),
            "action=allow".into(),
            "protocol=TCP".into(),
            format!("localport={port}"),
            format!("program={}", exe.display()),
            "enable=yes".into(),
        ])?;
        if st.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!("netsh exited with {st}")))
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
