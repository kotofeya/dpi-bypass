# dpi-bypass

A standalone Windows client that works around ISP DPI for YouTube, Discord (HTTPS and voice) and
Telegram Desktop. It needs no VPS and no proxy settings in the apps.

| Engine | Module | What it does |
|---|---|---|
| A | `windivert_engine` | WinDivert packet loop: TLS/HTTP split + fake/disorder, YouTube QUIC drop, Discord voice fakes, transparent Telegram redirect |
| B | `tg_bridge` | Carries Telegram MTProto (obfuscated2) over `wss://kws{1..5}.web.telegram.org/apiws` |
| C | `prober` | Searches for a working strategy, re-probes on failure, tracks gateway and Cloudflare DoH health |
| — | `nat_table` | DashMap stateful NAT between Engine A's reflected flows and Engine B |
| — | `obfs2` | AES-256-CTR obfuscated2 parser and generator, Telegram IP-to-DC map |

## Build

`build.rs` downloads WinDivert 2.2.2-A (checks its SHA-256), extracts the x64 DLL, driver and
import library into `vendor/windivert/`, and links `WinDivert.lib` as a delay-loaded import. The
DLL and driver are embedded in the exe and extracted next to it at startup.

```bash
cargo build --release
```

To cross-compile from Linux, use either of these:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

For offline builds, set `WINDIVERT_ZIP=<path to WinDivert-2.2.2-A.zip>` or copy the three files
into `vendor/windivert/`.

## Run

Start `dpi-bypass.exe`. If it is not elevated, it relaunches itself through UAC. When elevated it
adds an inbound firewall rule for the bridge port (17443; change it with `--bridge-port N`).
Set `RUST_LOG=debug` for per-packet logs.

If the driver can't be loaded, only these fallbacks run: SOCKS5 on `127.0.0.1:1080`, and an
MTProxy on `127.0.0.1:1443` whose `tg://proxy` link is printed at startup.
