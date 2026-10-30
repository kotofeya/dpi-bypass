//! Pure IPv4/IPv6 + TCP/UDP packet surgery used by the WinDivert loop. Checksums are left
//! zeroed here; the caller recomputes them with WinDivertHelperCalcChecksums before injecting.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

static IP_ID: AtomicU16 = AtomicU16::new(0x4a21);

/// Parsed offsets of an IPv4 TCP segment.
#[derive(Clone, Copy, Debug)]
pub struct Tcp4 {
    pub ihl: usize,
    /// payload start (IP header + TCP header)
    pub ps: usize,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
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
            src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
            sport: u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
            dport: u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
            flags: pkt[ihl + 13],
        })
    }

    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// Swap source/destination IPv4 addresses and optionally replace the ports — the core of the
/// "reflect" trick: an outbound packet becomes an inbound one addressed to ourselves.
pub fn reflect4(pkt: &mut [u8], ihl: usize, new_sport: Option<u16>, new_dport: Option<u16>) {
    let mut src = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    pkt.copy_within(16..20, 12);
    pkt[16..20].copy_from_slice(&src);
    if let Some(p) = new_sport {
        pkt[ihl..ihl + 2].copy_from_slice(&p.to_be_bytes());
    }
    if let Some(p) = new_dport {
        pkt[ihl + 2..ihl + 4].copy_from_slice(&p.to_be_bytes());
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

/// For an outbound IPv6 TCP SYN: the destination address and, if it is a SYN, an inbound
/// RST|ACK answering it (so the application fails over to IPv4 immediately).
pub fn ipv6_syn_rst(pkt: &[u8]) -> Option<(Ipv6Addr, Vec<u8>)> {
    if pkt.len() < 60 || pkt[0] >> 4 != 6 || pkt[6] != 6 {
        return None; // no extension headers expected on a plain SYN
    }
    let t = 40;
    let flags = pkt[t + 13];
    if flags & SYN == 0 || flags & ACK != 0 {
        return None;
    }
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    let seq = u32::from_be_bytes([pkt[t + 4], pkt[t + 5], pkt[t + 6], pkt[t + 7]]);

    let mut v = vec![0u8; 60];
    v[..8].copy_from_slice(&pkt[..8]);
    v[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload length
    v[7] = 64; // hop limit
    v[8..24].copy_from_slice(&pkt[24..40]); // src <- original dst
    v[24..40].copy_from_slice(&pkt[8..24]); // dst <- original src
    v[t..t + 2].copy_from_slice(&pkt[t + 2..t + 4]);
    v[t + 2..t + 4].copy_from_slice(&pkt[t..t + 2]);
    v[t + 8..t + 12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes()); // ack
    v[t + 12] = 5 << 4;
    v[t + 13] = RST | ACK;
    Some((dst, v))
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

/// MTProto destination ports Telegram clients use.
pub const TG_PORTS: [u16; 3] = [443, 80, 5222];

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
pub fn filter(bridge_port: u16) -> String {
    let ranges = crate::obfs2::telegram_v4_ranges()
        .iter()
        .map(|(lo, hi)| format!("(ip.DstAddr >= {lo} and ip.DstAddr <= {hi})"))
        .collect::<Vec<_>>()
        .join(" or ");
    let voice = DISCORD_VOICE_PORTS
        .iter()
        .map(|(lo, hi)| format!("(udp.DstPort >= {lo} and udp.DstPort <= {hi})"))
        .collect::<Vec<_>>()
        .join(" or ");
    let ports = TG_PORTS.iter().map(|p| format!("tcp.DstPort == {p}")).collect::<Vec<_>>().join(" or ");
    format!(
        "outbound and !loopback and (\
 (ip and tcp.SrcPort == {bridge_port}) or \
 (ip and tcp and ({ports}) and ({ranges})) or \
 (ip and tcp.DstPort == 443 and tcp.PayloadLength > 5 and tcp.Payload[0] == 22 and tcp.Payload[5] == 1) or \
 (ip and tcp.DstPort == 80 and tcp.PayloadLength > 0 and tcp.Payload[0] >= 65 and tcp.Payload[0] <= 90) or \
 (ip and udp.DstPort == 443 and udp.PayloadLength >= 1200) or \
 (ip and udp.PayloadLength > 0 and ({voice})) or \
 (ipv6 and tcp.Syn and !tcp.Ack and ({ports})))"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 192.168.1.10:50000 -> 149.154.167.51:443, SYN, with 4 bytes of TCP options.
    fn syn() -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[8] = 128;
        p[9] = 6;
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[149, 154, 167, 51]);
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[32] = 6 << 4;
        p[33] = SYN;
        p[40..44].copy_from_slice(&[2, 4, 5, 0xb4]);
        p
    }

    #[test]
    fn parse_and_reflect() {
        let mut p = syn();
        let t = Tcp4::parse(&p).unwrap();
        assert_eq!((t.sport, t.dport, t.ps), (50000, 443, 44));
        assert!(t.has(SYN) && !t.has(ACK));
        reflect4(&mut p, t.ihl, None, Some(17443));
        let r = Tcp4::parse(&p).unwrap();
        assert_eq!(r.src, Ipv4Addr::new(149, 154, 167, 51));
        assert_eq!(r.dst, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!((r.sport, r.dport), (50000, 17443));
    }

    #[test]
    fn build_segments() {
        let p = syn();
        let t = Tcp4::parse(&p).unwrap();
        let s = build_tcp(&p, t.ihl, t.ps, 7, b"abc", Some(5));
        assert_eq!(s.len(), 47);
        assert_eq!(u16::from_be_bytes([s[2], s[3]]), 47);
        assert_eq!(s[8], 5);
        assert_eq!(u32::from_be_bytes([s[24], s[25], s[26], s[27]]), 1007);
        assert_eq!(&s[44..], b"abc");
    }

    #[test]
    fn v6_rst() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = 6;
        p[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"2001:b28:f23d:f001::a".parse::<Ipv6Addr>().unwrap().octets());
        p[40..42].copy_from_slice(&51000u16.to_be_bytes());
        p[42..44].copy_from_slice(&443u16.to_be_bytes());
        p[44..48].copy_from_slice(&41u32.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = SYN;
        let (dst, r) = ipv6_syn_rst(&p).unwrap();
        assert!(crate::obfs2::is_telegram_v6(dst));
        assert_eq!(&r[8..24], &p[24..40]);
        assert_eq!(u16::from_be_bytes([r[42], r[43]]), 51000);
        assert_eq!(u32::from_be_bytes([r[48], r[49], r[50], r[51]]), 42);
        assert_eq!(r[53], RST | ACK);
    }

    #[test]
    fn http_and_filter() {
        let (i, h) = http_host(b"GET / HTTP/1.1\r\nHost: t.me:80\r\n\r\n").unwrap();
        assert_eq!((i, h.as_str()), (14, "t.me"));
        let f = filter(17443);
        assert!(f.contains("tcp.SrcPort == 17443"));
        assert!(f.contains("ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255"));
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
