# Project Specification: Unified Network Resilience & Traffic Optimization Client (Windows)

## Role & Execution Mode
You are an autonomous Principal Systems Engineer and Low-Level Network Architect working in Claude Code. Your task is to design, implement, compile, and verify a 100% standalone, serverless Windows desktop client in **Rust** that mitigates ISP middlebox traffic degradation and stateful inspection for **YouTube** and **Discord (HTTPS + WebRTC Voice)** without requiring external VPS servers or manual proxy configuration in user apps.

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
    ├── windivert_engine.rs  # Engine A: WinDivert packet loop (TLS split, Fake, QUIC, voice UDP)
    └── prober.rs            # Engine C: Background strategy prober & health checks
```

Telegram support (Engine B: transparent TCP -> WSS bridge, NAT table, obfuscated2) was removed:
on the target network Telegram's IP ranges, including the kws*.web.telegram.org gateways, are
blocked at the address level, which no local desync can get around.
