# Project Specification: Unified Network Resilience & Traffic Optimization Client (Windows)

## Role & Execution Mode
You are an autonomous Principal Systems Engineer and Low-Level Network Architect working in Claude Code. Your task is to design, implement, compile, and verify a 100% standalone, serverless Windows desktop client in **Rust** that mitigates ISP middlebox traffic degradation and stateful inspection for **YouTube**, **Discord (HTTPS + WebRTC Voice)**, and **Telegram Desktop** without requiring external VPS servers or manual proxy configuration in user apps.

## Core Directives for Claude Code
1. **Zero Placeholders:** Never write `// TODO`, `unimplemented!()`, or stub functions. Write complete byte-level packet parsing, cryptographic, and socket handling logic.
2. **Autonomous Compilation & Linker Setup:** Automatically download the official `WinDivert` binary release (`v2.2.2-A` from `basil00/Divert` on GitHub) using PowerShell/curl if not present, extract `x64/WinDivert.dll`, `x64/WinDivert64.sys`, and `x64/WinDivert.lib`, and configure `build.rs` so `cargo check` and `cargo build --release` succeed without manual user intervention.
3. **Self-Correction:** After writing or modifying modules, always run `cargo check` to catch borrow-checker, type, or API issues, and fix them iteratively until the build is completely clean.

---

## Target Project Structure
```text
.
├── Cargo.toml
├── build.rs                 # WinDivert.lib linking & binary extraction
├── vendor/windivert/        # Downloaded WinDivert.dll, WinDivert64.sys, WinDivert.lib
└── src/
    ├── main.rs              # Privilege check, NIC IP discovery, engine orchestration
    ├── nat_table.rs         # Lock-free DashMap Stateful NAT for transparent redirection
    ├── windivert_engine.rs  # Engine A: WinDivert packet loop (TLS split, Fake, UDP, NAT)
    ├── obfs2.rs             # AES-256-CTR MTProto Obfuscated2 parser & IP-to-DC mapper
    ├── tg_bridge.rs         # Engine B: Transparent TCP -> WSS (kws1..5.web.telegram.org)
    └── prober.rs            # Engine C: Background strategy & Cloudflare/Gateway health prober