# dpi-bypass

A standalone Windows client that works around ISP DPI for YouTube and Discord (HTTPS and voice).
It needs no VPS and no proxy settings in the apps.

| Engine | Module | What it does |
|---|---|---|
| A | `windivert_engine` | WinDivert packet loop: TLS/HTTP split + fake/disorder, YouTube QUIC drop, Discord voice decoys |
| C | `prober` | Finds a working strategy at startup, re-probes when YouTube/Discord checks keep failing |

Telegram support was removed: where Telegram's IP addresses are blocked outright, no local
trick can reach its servers.

## Build

`build.rs` downloads WinDivert 2.2.2-A (checks its SHA-256), extracts the x64 DLL, driver and
import library into `vendor/windivert/`, and links `WinDivert.lib` as a delay-loaded import. The
DLL and driver are embedded in the exe and extracted next to it at startup.

```bash
cargo build --release
```

To cross-compile from Linux:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

For offline builds, set `WINDIVERT_ZIP=<path to WinDivert-2.2.2-A.zip>` or copy the three files
into `vendor/windivert/`.

Microsoft Defender flags WinDivert as a "HackTool" (it is a packet-capture driver). Add an
exclusion for the project folder if the build reports that the zip "contains a virus".

## Run

Start `dpi-bypass.exe`. If it is not elevated, it relaunches itself through UAC. Add `-v` for
per-packet debug logs. Wait for `locked profile` in the log before testing.

## Start at logon

From an Administrator PowerShell:

```powershell
.\dpi-bypass.exe --install
```

This registers a Task Scheduler task (elevated, no UAC prompt, no console window) that starts the
exe at every logon and restarts it if it crashes. Logs go to `dpi-bypass.log` next to the exe.
`--uninstall` removes the task. Stop the running copy before rebuilding or moving the exe.

