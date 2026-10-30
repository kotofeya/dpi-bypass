//! Engine A — WinDivert packet loop (IPv4).
//!
//!  * TCP/443 TLS ClientHello with a target SNI  -> [fake(s)] + split + (disorder)
//!  * TCP/80  HTTP request with a target Host     -> same, split inside "Host"
//!  * UDP/443 QUIC Initial with a YouTube SNI     -> dropped (browser falls back to TCP/TLS)
//!  * UDP/50000+ 74-byte Discord IP-discovery     -> N fake datagrams injected first
//!
//! Everything not matched is re-injected untouched. Packets we inject via WinDivertSend are
//! not captured again by this handle, so there is no feedback loop.

use crate::divert::{Address, Divert};
use crate::profile::{is_target, is_youtube, Profile, Shared};
use crate::{quic, tls};
use anyhow::Result;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const FILTER: &str = "outbound and ip and !loopback and (\
 (tcp.DstPort == 443 and tcp.Payload[0] == 22 and tcp.Payload[5] == 1) or \
 (tcp.DstPort == 80 and tcp.PayloadLength > 0 and tcp.Payload[0] >= 65 and tcp.Payload[0] <= 90) or \
 (udp.DstPort == 443 and udp.PayloadLength >= 1200) or \
 (udp.DstPort >= 50000 and udp.PayloadLength == 74))";

static IP_ID: AtomicU16 = AtomicU16::new(0x4a21);

enum Action {
    /// caller re-injects the original packet
    Pass,
    /// we already injected replacements (or intentionally dropped it)
    Consumed,
}

pub fn run(dv: Arc<Divert>, profile: Shared) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    tracing::info!("engine A: packet loop running");
    loop {
        let (n, addr) = match dv.recv(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                if dv.is_closed() {
                    return Ok(());
                }
                tracing::warn!("WinDivertRecv: {e}");
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        let p = profile.load_full();
        let pkt = &buf[..n];
        let act = handle(&dv, &p, pkt, &addr).unwrap_or_else(|e| {
            tracing::debug!("handle: {e:#}");
            Action::Pass
        });
        if let Action::Pass = act {
            if let Err(e) = dv.send(pkt, &addr) {
                tracing::debug!("reinject: {e}");
            }
        }
    }
}

fn handle(dv: &Divert, p: &Profile, pkt: &[u8], addr: &Address) -> Result<Action> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return Ok(Action::Pass);
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    match pkt[9] {
        6 => on_tcp(dv, p, pkt, addr, ihl),
        17 => on_udp(dv, p, pkt, addr, ihl),
        _ => Ok(Action::Pass),
    }
}

// ------------------------------------------------------------------ TCP

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// returns (index of the "\r\nHost:" header start, host value)
fn http_host(payload: &[u8]) -> Option<(usize, String)> {
    let i = find(payload, b"\r\nHost:").or_else(|| find(payload, b"\r\nhost:"))?;
    let rest = &payload[i + 7..];
    let end = rest.iter().position(|&b| b == b'\r').unwrap_or(rest.len());
    let host = std::str::from_utf8(&rest[..end]).ok()?.trim().split(':').next()?.to_string();
    Some((i, host))
}

fn on_tcp(dv: &Divert, p: &Profile, pkt: &[u8], addr: &Address, ihl: usize) -> Result<Action> {
    if pkt.len() < ihl + 20 {
        return Ok(Action::Pass);
    }
    let thl = ((pkt[ihl + 12] >> 4) as usize) * 4;
    let ps = ihl + thl;
    if thl < 20 || ps >= pkt.len() {
        return Ok(Action::Pass);
    }
    let payload = &pkt[ps..];
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

    let (split, fake) = if dport == 443 {
        let Some(h) = tls::parse_client_hello(payload) else { return Ok(Action::Pass) };
        if !is_target(&h.sni) {
            return Ok(Action::Pass);
        }
        tracing::debug!("TLS {} -> split", h.sni);
        (p.split.resolve(h.sni_off, h.sni.len(), payload.len()), tls::build_fake_client_hello(&p.fake_sni))
    } else {
        let Some((i, host)) = http_host(payload) else { return Ok(Action::Pass) };
        if !is_target(&host) {
            return Ok(Action::Pass);
        }
        let k = (i + 4).clamp(1, payload.len() - 1); // "\r\nHo|st:"
        (k, format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", p.fake_sni).into_bytes())
    };

    // 1) decoys: same 4-tuple + same seq as the real data, but never accepted by the server
    let ttl = (p.fake_ttl > 0).then_some(p.fake_ttl);
    if p.fake_count > 0 && (ttl.is_some() || p.bad_sum) {
        for _ in 0..p.fake_count {
            emit(dv, addr, build_tcp(pkt, ihl, ps, 0, &fake, ttl), ihl + 16, p.bad_sum)?;
        }
    }

    // 2) real data in two segments, optionally out of order
    let s1 = build_tcp(pkt, ihl, ps, 0, &payload[..split], None);
    let s2 = build_tcp(pkt, ihl, ps, split as u32, &payload[split..], None);
    if p.disorder {
        emit(dv, addr, s2, ihl + 16, false)?;
        emit(dv, addr, s1, ihl + 16, false)?;
    } else {
        emit(dv, addr, s1, ihl + 16, false)?;
        emit(dv, addr, s2, ihl + 16, false)?;
    }
    Ok(Action::Consumed)
}

/// Clone IP+TCP headers (options included) of `orig`, attach `payload`, shift seq by `seq_add`.
fn build_tcp(orig: &[u8], ihl: usize, ps: usize, seq_add: u32, payload: &[u8], ttl: Option<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(ps + payload.len());
    v.extend_from_slice(&orig[..ps]);
    v.extend_from_slice(payload);
    let total = v.len() as u16;
    v[2..4].copy_from_slice(&total.to_be_bytes());
    let id = IP_ID.fetch_add(1, Ordering::Relaxed);
    v[4..6].copy_from_slice(&id.to_be_bytes());
    if let Some(t) = ttl {
        v[8] = t;
    }
    v[10] = 0;
    v[11] = 0;
    let seq = u32::from_be_bytes([v[ihl + 4], v[ihl + 5], v[ihl + 6], v[ihl + 7]]).wrapping_add(seq_add);
    v[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
    v[ihl + 16] = 0;
    v[ihl + 17] = 0;
    v
}

/// Fix checksums, optionally corrupt the L4 checksum afterwards (the "BadSum" fake), inject.
fn emit(dv: &Divert, addr: &Address, mut v: Vec<u8>, l4_csum_off: usize, corrupt: bool) -> Result<()> {
    let mut a = *addr;
    dv.calc_checksums(&mut v, &mut a);
    if corrupt {
        v[l4_csum_off] ^= 0xff;
    }
    dv.send(&v, &a)?;
    Ok(())
}

// ------------------------------------------------------------------ UDP

fn on_udp(dv: &Divert, p: &Profile, pkt: &[u8], addr: &Address, ihl: usize) -> Result<Action> {
    if pkt.len() < ihl + 8 {
        return Ok(Action::Pass);
    }
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let payload = &pkt[ihl + 8..];

    if dport == 443 {
        if !p.drop_quic {
            return Ok(Action::Pass);
        }
        return Ok(match quic::initial_sni(payload) {
            Some(s) if is_youtube(&s) => {
                tracing::debug!("QUIC {s} dropped -> TCP fallback");
                Action::Consumed
            }
            _ => Action::Pass,
        });
    }

    // Discord voice IP discovery: type=0x0001, length=70, SSRC, 64B address, 2B port = 74 bytes
    if dport >= 50000 && payload.len() == 74 && payload[..4] == [0, 1, 0, 70] {
        let ttl = (p.fake_ttl > 0).then_some(p.fake_ttl);
        for i in 0..p.discord_fakes.clamp(0, 4) {
            let fake: Vec<u8> = match i % 3 {
                0 => vec![0u8; 74],
                1 => (0..74).map(|_| fastrand::u8(..)).collect(),
                _ => (0..fastrand::usize(40..=120)).map(|_| fastrand::u8(..)).collect(),
            };
            emit(dv, addr, build_udp(pkt, ihl, &fake, ttl), ihl + 6, p.bad_sum)?;
        }
        tracing::debug!("discord voice handshake: {} fakes", p.discord_fakes);
        return Ok(Action::Pass); // real packet follows the decoys
    }
    Ok(Action::Pass)
}

fn build_udp(orig: &[u8], ihl: usize, payload: &[u8], ttl: Option<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(ihl + 8 + payload.len());
    v.extend_from_slice(&orig[..ihl + 8]);
    v.extend_from_slice(payload);
    let total = v.len() as u16;
    v[2..4].copy_from_slice(&total.to_be_bytes());
    let id = IP_ID.fetch_add(1, Ordering::Relaxed);
    v[4..6].copy_from_slice(&id.to_be_bytes());
    if let Some(t) = ttl {
        v[8] = t;
    }
    v[10] = 0;
    v[11] = 0;
    let ulen = (8 + payload.len()) as u16;
    v[ihl + 4..ihl + 6].copy_from_slice(&ulen.to_be_bytes());
    v[ihl + 6] = 0;
    v[ihl + 7] = 0;
    v
}
