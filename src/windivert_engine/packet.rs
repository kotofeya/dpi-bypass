//! Pure IPv4/IPv6 + TCP/UDP packet surgery used by the WinDivert loop. Checksums are left
//! zeroed here; the caller recomputes them with WinDivertHelperCalcChecksums before injecting.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static IP_ID: AtomicU16 = AtomicU16::new(0x4a21);

/// Parsed offsets of an IPv4 TCP segment.
#[derive(Clone, Copy, Debug)]
pub struct Tcp4 {
    pub ihl: usize,
    /// payload start (IP header + TCP header)
    pub ps: usize,
    pub dport: u16,
}

impl Tcp4 {
    pub fn parse(pkt: &[u8]) -> Option<Self> {
        if pkt.len() < 40 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
            return None;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl + 20 {
            return None;
        }
        let thl = ((pkt[ihl + 12] >> 4) as usize) * 4;
        if thl < 20 || pkt.len() < ihl + thl {
            return None;
        }
        Some(Tcp4 {
            ihl,
            ps: ihl + thl,
            dport: u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
        })
    }
}

/// Clone IP+TCP headers (options included) of `orig`, attach `payload`, shift seq by `seq_add`.
pub fn build_tcp(orig: &[u8], ihl: usize, ps: usize, seq_add: u32, payload: &[u8], ttl: Option<u8>) -> Vec<u8> {
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

/// Clone IP+UDP headers of `orig` around a new payload.
pub fn build_udp(orig: &[u8], ihl: usize, payload: &[u8], ttl: Option<u8>) -> Vec<u8> {
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

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Returns (index of the "\r\nHost:" header start, host value) of an HTTP request.
pub fn http_host(payload: &[u8]) -> Option<(usize, String)> {
    let i = find(payload, b"\r\nHost:").or_else(|| find(payload, b"\r\nhost:"))?;
    let rest = &payload[i + 7..];
    let end = rest.iter().position(|&b| b == b'\r').unwrap_or(rest.len());
    let host = std::str::from_utf8(&rest[..end]).ok()?.trim().split(':').next()?.to_string();
    Some((i, host))
}

/// Ports carrying TLS we desync: HTTPS plus the Cloudflare alternate ports Discord's voice
/// servers (*.discord.media) use for their WebSocket signalling.
pub const TLS_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];

/// UDP port ranges of Discord voice (RTC) servers.
pub const DISCORD_VOICE_PORTS: [(u16, u16); 2] = [(19294, 19344), (50000, 50100)];

pub fn is_discord_voice_port(p: u16) -> bool {
    DISCORD_VOICE_PORTS.iter().any(|(lo, hi)| (*lo..=*hi).contains(&p))
}

/// Number of leading packets of a voice flow that get decoys in front of them (zapret's
/// "cutoff=d3"): the blocking decision is made on the first datagrams only.
pub const VOICE_CUTOFF: u8 = 3;
const VOICE_FLOW_IDLE: Duration = Duration::from_secs(120);

/// Per-flow packet counter for outbound voice UDP, keyed by (src port, dst ip, dst port).
#[derive(Default)]
pub struct VoiceFlows {
    flows: HashMap<(u16, Ipv4Addr, u16), (u8, Instant)>,
}

impl VoiceFlows {
    /// Counts a packet; true while the flow is still within the first `VOICE_CUTOFF` packets.
    pub fn needs_decoys(&mut self, sport: u16, dst: Ipv4Addr, dport: u16, now: Instant) -> bool {
        if self.flows.len() > 4096 {
            self.flows.retain(|_, (_, t)| now.duration_since(*t) < VOICE_FLOW_IDLE);
        }
        let e = self.flows.entry((sport, dst, dport)).or_insert((0, now));
        if now.duration_since(e.1) >= VOICE_FLOW_IDLE {
            e.0 = 0; // port reused for a new call
        }
        e.1 = now;
        if e.0 >= VOICE_CUTOFF {
            return false;
        }
        e.0 += 1;
        true
    }
}

/// Decoy datagram number `i` for a voice flow: alternates between a Discord IP-discovery
/// request with a random SSRC, a STUN Binding request, zeros and random noise.
pub fn voice_decoy(i: u8) -> Vec<u8> {
    match i % 4 {
        0 => {
            let mut v = vec![0u8; 74];
            v[..4].copy_from_slice(&[0, 1, 0, 70]);
            v[4..8].iter_mut().for_each(|b| *b = fastrand::u8(..));
            v
        }
        1 => {
            let mut v = vec![0u8; 20];
            v[..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
            v[4..8].copy_from_slice(&0x2112_a442u32.to_be_bytes()); // magic cookie
            v[8..20].iter_mut().for_each(|b| *b = fastrand::u8(..));
            v
        }
        2 => vec![0u8; 74],
        _ => (0..fastrand::usize(40..=120)).map(|_| fastrand::u8(..)).collect(),
    }
}

/// The single WinDivert filter for Engine A.
pub fn filter() -> String {
    let voice = DISCORD_VOICE_PORTS
        .iter()
        .map(|(lo, hi)| format!("(udp.DstPort >= {lo} and udp.DstPort <= {hi})"))
        .collect::<Vec<_>>()
        .join(" or ");
    let tls = TLS_PORTS.iter().map(|p| format!("tcp.DstPort == {p}")).collect::<Vec<_>>().join(" or ");
    format!(
        "outbound and !loopback and ip and (\
 (({tls}) and tcp.PayloadLength > 5 and tcp.Payload[0] == 22 and tcp.Payload[5] == 1) or \
 (tcp.DstPort == 80 and tcp.PayloadLength > 0 and tcp.Payload[0] >= 65 and tcp.Payload[0] <= 90) or \
 (udp.DstPort == 443 and udp.PayloadLength >= 1200) or \
 (udp.PayloadLength > 0 and ({voice})))"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 192.168.1.10:50000 -> 162.159.135.232:443, SYN, with 4 bytes of TCP options.
    fn syn() -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[8] = 128;
        p[9] = 6;
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[162, 159, 135, 232]);
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[32] = 6 << 4;
        p[33] = 0x02;
        p[40..44].copy_from_slice(&[2, 4, 5, 0xb4]);
        p
    }

    #[test]
    fn build_segments() {
        let p = syn();
        let t = Tcp4::parse(&p).unwrap();
        assert_eq!((t.dport, t.ps), (443, 44));
        let s = build_tcp(&p, t.ihl, t.ps, 7, b"abc", Some(5));
        assert_eq!(s.len(), 47);
        assert_eq!(u16::from_be_bytes([s[2], s[3]]), 47);
        assert_eq!(s[8], 5);
        assert_eq!(u32::from_be_bytes([s[24], s[25], s[26], s[27]]), 1007);
        assert_eq!(&s[44..], b"abc");
    }

    #[test]
    fn http_and_filter() {
        let (i, h) = http_host(b"GET / HTTP/1.1\r\nHost: t.me:80\r\n\r\n").unwrap();
        assert_eq!((i, h.as_str()), (14, "t.me"));
        let f = filter();
        assert!(f.contains("tcp.DstPort == 2053"));
        assert!(f.contains("(udp.DstPort >= 19294 and udp.DstPort <= 19344)"));
    }

    #[test]
    fn voice_cutoff_and_decoys() {
        let mut v = VoiceFlows::default();
        let ip = Ipv4Addr::new(66, 22, 196, 10);
        let t = Instant::now();
        let hits: Vec<bool> = (0..5).map(|_| v.needs_decoys(60000, ip, 50004, t)).collect();
        assert_eq!(hits, [true, true, true, false, false]);
        assert!(v.needs_decoys(60001, ip, 50004, t)); // new flow
        assert!(v.needs_decoys(60000, ip, 50004, t + VOICE_FLOW_IDLE)); // reused after idle
        assert!(is_discord_voice_port(19300) && is_discord_voice_port(50100) && !is_discord_voice_port(50101));

        let d = voice_decoy(0);
        assert_eq!((d.len(), &d[..4]), (74, &[0u8, 1, 0, 70][..]));
        let s = voice_decoy(1);
        assert_eq!((s.len(), &s[4..8]), (20, &[0x21u8, 0x12, 0xa4, 0x42][..]));
    }
}
