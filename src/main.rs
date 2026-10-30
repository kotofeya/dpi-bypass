//! Serverless DPI mitigation client for YouTube and Discord (Windows).
//!
//!  Engine A (windivert_engine) — packet-level desync (TLS/HTTP split + fakes, QUIC, voice UDP)
//!  Engine C (prober)           — strategy search and health checks
//!
//!  `--install` registers a logon task (Task Scheduler) that runs it elevated with `--background`.

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

    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "dpi-bypass [-v | --log <filter>] [--background]\n\
             dpi-bypass --install | --uninstall\n\n\
             Needs Administrator rights (relaunches itself via UAC) to load the WinDivert driver.\n\
             -v            packet-level debug logs\n\
             --background  no console window; logs go to dpi-bypass.log next to the exe\n\
             --install     start automatically at every logon (scheduled task, elevated, no UAC prompt)\n\
             --uninstall   remove that task"
        );
        return Ok(());
    }
    if args.iter().any(|a| a == "--install" || a == "--uninstall") {
        // runs from an Administrator console so the result stays on screen
        // release builds abort on panic; make sure the reason reaches the log first
    std::panic::set_hook(Box::new(|info| tracing::error!("panic: {info}")));

    if !win::is_elevated() {
            anyhow::bail!("run this from an Administrator PowerShell (right-click PowerShell -> Run as administrator)");
        }
        return if args.iter().any(|a| a == "--install") { win::install_task() } else { win::uninstall_task() };
    }

    // Log filter: --log <filter>, -v / --verbose (= debug), else RUST_LOG, else info.
    // The UAC relaunch does not inherit environment variables, so RUST_LOG is forwarded as --log.
    let filter = arg_value(&args, "--log")
        .or_else(|| args.iter().any(|a| a == "-v" || a == "--verbose").then(|| "debug".to_string()))
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|_| "info".into());
    let background = args.iter().any(|a| a == "--background");
    match background.then(win::open_log_file).and_then(Result::ok) {
        Some(file) => {
            win::detach_console();
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file))
                .with_env_filter(env_filter)
                .init();
        }
        None => tracing_subscriber::fmt().with_ansi(win::enable_ansi()).with_env_filter(env_filter).init(),
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
            let res = e.run();
            if !e.stopping() {
                // the packet loop is the whole program: without it nothing is being fixed, so
                // exit non-zero and let Task Scheduler start a fresh copy
                match res {
                    Err(err) => tracing::error!("engine A stopped: {err:#}"),
                    Ok(()) => tracing::error!("engine A stopped unexpectedly"),
                }
                std::process::exit(1);
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

    const TASK_NAME: &str = "dpi-bypass";

    fn exe_dir() -> std::io::Result<std::path::PathBuf> {
        let exe = std::env::current_exe()?;
        exe.parent().map(|p| p.to_path_buf()).ok_or_else(|| std::io::Error::other("exe has no parent folder"))
    }

    /// `dpi-bypass.log` next to the exe, restarted when it grows past 2 MB.
    pub fn open_log_file() -> std::io::Result<std::fs::File> {
        let path = exe_dir()?.join("dpi-bypass.log");
        let big = std::fs::metadata(&path).map(|m| m.len() > 2 * 1024 * 1024).unwrap_or(false);
        std::fs::OpenOptions::new().create(true).append(true).truncate(false).open(&path).and_then(|f| {
            if big {
                f.set_len(0)?;
            }
            Ok(f)
        })
    }

    /// Closes the console window this process owns (no flicker when started by Task Scheduler).
    pub fn detach_console() {
        unsafe { windows_sys::Win32::System::Console::FreeConsole() };
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    fn schtasks(args: &[&str]) -> std::io::Result<std::process::Output> {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("schtasks").args(args).creation_flags(0x0800_0000).output()
    }

    /// Registers a task that runs this exe at every logon, elevated (no UAC prompt), without a
    /// time limit, also on battery, and restarts it up to 3 times if it crashes.
    pub fn install_task() -> anyhow::Result<()> {
        let exe = std::env::current_exe()?;
        let dir = exe_dir()?;
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts dpi-bypass (YouTube/Discord DPI workaround) at logon.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>{}</Command><Arguments>--background</Arguments><WorkingDirectory>{}</WorkingDirectory>
  </Exec></Actions>
</Task>
"#,
            xml_escape(&exe.display().to_string()),
            xml_escape(&dir.display().to_string())
        );
        // schtasks wants the file as UTF-16 LE with a byte order mark
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(xml.encode_utf16().flat_map(|u| u.to_le_bytes()));
        let tmp = std::env::temp_dir().join("dpi-bypass-task.xml");
        std::fs::write(&tmp, bytes)?;
        let out = schtasks(&["/Create", "/TN", TASK_NAME, "/XML", &tmp.display().to_string(), "/F"]);
        let _ = std::fs::remove_file(&tmp);
        let out = out?;
        if !out.status.success() {
            anyhow::bail!(
                "schtasks failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        println!("Installed: {} will start at every logon (task \"{TASK_NAME}\").", exe.display());
        println!("Logs: {}", dir.join("dpi-bypass.log").display());
        println!("Do not move or rebuild the exe while it runs; run --uninstall first, or install again after moving it.");
        println!("Start it now without logging out:  schtasks /Run /TN {TASK_NAME}");
        Ok(())
    }

    pub fn uninstall_task() -> anyhow::Result<()> {
        let _ = schtasks(&["/End", "/TN", TASK_NAME]);
        let out = schtasks(&["/Delete", "/TN", TASK_NAME, "/F"])?;
        if !out.status.success() {
            anyhow::bail!("schtasks failed (is it installed?): {}", String::from_utf8_lossy(&out.stderr));
        }
        println!("Removed task \"{TASK_NAME}\". A copy that is still running keeps running until you close it.");
        Ok(())
    }

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
