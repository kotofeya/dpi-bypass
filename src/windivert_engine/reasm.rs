//! Collects a TLS ClientHello that spans several TCP segments.
//!
//! Chromium (so Discord's Electron app and every browser) shuffles its extension order and adds
//! a ~1.2 KB post-quantum key share, so the hello is ~1.8 KB and the server_name extension is
//! often in the *second* segment. A first segment without an SNI is therefore held back until
//! the following segment(s) arrive, then the strategy runs on the whole message.
//!
//! Held packets are never lost: a retransmission, a gap, a size limit or the hold timeout all
//! release them unchanged, in their original order. Because the client keeps retransmitting
//! until it gets an ACK, even a total failure of the hold only costs one retransmission timer.

use super::packet::Tcp4;
use super::tls::{self, Hello};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Segments held per hello (a post-quantum hello is 2, a very large one 3-4).
const MAX_SEGS: usize = 6;
/// A TLS record holds at most 16 KiB (+5 header).
const MAX_BYTES: usize = 16 * 1024 + 5;
/// Flows waited on at the same time; beyond this new ones are passed through.
const MAX_PENDING: usize = 256;
/// How long the first segment may be held while waiting for the rest. The continuation is sent
/// back to back with it, so this is only ever reached when something is wrong.
pub const HOLD_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
}

impl FlowKey {
    pub fn of(t: &Tcp4) -> Self {
        Self { src: t.src, sport: t.sport, dst: t.dst, dport: t.dport }
    }
}

/// A captured packet together with the opaque capture metadata needed to re-inject it.
pub struct Held<A> {
    pub pkt: Vec<u8>,
    pub addr: A,
}

/// A complete (as far as the SNI goes) multi-segment hello.
pub struct Assembled<A> {
    /// the original segments, in order; `segs[0]` carries the header template
    pub segs: Vec<Held<A>>,
    /// concatenated TCP payload, starting at the sequence number of `segs[0]`
    pub data: Vec<u8>,
    /// largest payload seen in a segment: the path's MSS as far as we can tell
    pub mss: usize,
    pub hello: Hello,
}

pub enum Step<A> {
    /// not a ClientHello we are interested in: re-inject the packet as it is
    Pass,
    /// the packet was stored; inject nothing
    Hold,
    /// this single packet carries the SNI; treat it directly
    Hello(Hello),
    /// the rest of a held hello arrived
    Assembled(Assembled<A>),
    /// stop waiting: re-inject these packets unchanged, in this order
    Release(Vec<Held<A>>),
}

struct Pending<A> {
    segs: Vec<Held<A>>,
    base_seq: u32,
    data: Vec<u8>,
    mss: usize,
    since: Instant,
}

pub struct Reassembler<A> {
    pending: HashMap<FlowKey, Pending<A>>,
}

impl<A> Default for Reassembler<A> {
    fn default() -> Self {
        Self { pending: HashMap::new() }
    }
}

fn is_hello_start(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 3 && p[5] == 1
}

/// Does the TLS record that starts `data` extend past the end of `data`?
fn record_incomplete(data: &[u8]) -> bool {
    data.len() >= 5 && data.len() < 5 + u16::from_be_bytes([data[3], data[4]]) as usize
}

impl<A> Reassembler<A> {
    #[cfg(test)]
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }

    /// Packets held for longer than `HOLD_TIMEOUT`; the caller sends them as they were.
    pub fn sweep(&mut self, now: Instant) -> Vec<Held<A>> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let expired: Vec<FlowKey> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.since) >= HOLD_TIMEOUT)
            .map(|(k, _)| *k)
            .collect();
        expired.into_iter().filter_map(|k| self.pending.remove(&k)).flat_map(|p| p.segs).collect()
    }

    /// Feeds one outbound data segment of a TLS-port flow. `pkt` is the whole IP packet.
    pub fn on_data(&mut self, pkt: &[u8], addr: A, t: &Tcp4, now: Instant) -> Step<A> {
        let payload = &pkt[t.ps..];
        let key = FlowKey::of(t);

        if let Some(mut p) = self.pending.remove(&key) {
            let expected = p.base_seq.wrapping_add(p.data.len() as u32);
            let fits = p.segs.len() < MAX_SEGS && p.data.len() + payload.len() <= MAX_BYTES;
            if t.seq != expected || !fits {
                // retransmission, reordering or an oversized message: stop waiting
                p.segs.push(Held { pkt: pkt.to_vec(), addr });
                return Step::Release(p.segs);
            }
            p.data.extend_from_slice(payload);
            p.mss = p.mss.max(payload.len());
            p.segs.push(Held { pkt: pkt.to_vec(), addr });
            if let Some(hello) = tls::parse_client_hello(&p.data) {
                return Step::Assembled(Assembled { segs: p.segs, data: p.data, mss: p.mss, hello });
            }
            if record_incomplete(&p.data) {
                self.pending.insert(key, p);
                return Step::Hold;
            }
            // whole record present and it names no server
            return Step::Release(p.segs);
        }

        if !is_hello_start(payload) {
            return Step::Pass;
        }
        if let Some(h) = tls::parse_client_hello(payload) {
            return Step::Hello(h);
        }
        if !record_incomplete(payload) || self.pending.len() >= MAX_PENDING {
            return Step::Pass; // complete hello without SNI, or no room to wait
        }
        self.pending.insert(
            key,
            Pending {
                segs: vec![Held { pkt: pkt.to_vec(), addr }],
                base_seq: t.seq,
                data: payload.to_vec(),
                mss: payload.len(),
                since: now,
            },
        );
        Step::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 192.168.1.10:`sport` -> 162.159.135.232:443, ACK|PSH, 20-byte TCP header.
    fn seg(sport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        p[8] = 128;
        p[9] = 6;
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[162, 159, 135, 232]);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = 0x18;
        p.extend_from_slice(payload);
        p
    }

    fn feed(r: &mut Reassembler<u8>, p: &[u8], now: Instant) -> Step<u8> {
        let t = Tcp4::parse(p).unwrap();
        r.on_data(p, 0, &t, now)
    }

    fn late_hello() -> Vec<u8> {
        tls::build_probe_client_hello("gateway.discord.gg", 1780)
    }

    #[test]
    fn sni_in_first_segment_is_handled_directly() {
        let mut r = Reassembler::<u8>::default();
        let hello = tls::build_fake_client_hello_len("discord.com", 1780);
        let p = seg(40000, 100, &hello[..1460]);
        assert!(matches!(feed(&mut r, &p, Instant::now()), Step::Hello(h) if h.sni == "discord.com"));
        assert!(r.is_idle());
    }

    #[test]
    fn sni_in_second_segment_is_assembled() {
        let mut r = Reassembler::<u8>::default();
        let (h, now) = (late_hello(), Instant::now());
        let s1 = seg(40001, 5000, &h[..1460]);
        let s2 = seg(40001, 5000 + 1460, &h[1460..]);
        assert!(matches!(feed(&mut r, &s1, now), Step::Hold));
        assert!(!r.is_idle());
        match feed(&mut r, &s2, now) {
            Step::Assembled(a) => {
                assert_eq!(a.hello.sni, "gateway.discord.gg");
                assert_eq!(a.data, h);
                assert_eq!(a.mss, 1460);
                assert_eq!(a.segs.len(), 2);
                assert_eq!(a.segs[0].pkt, s1);
            }
            _ => panic!("expected an assembled hello"),
        }
        assert!(r.is_idle());
    }

    #[test]
    fn gaps_retransmits_and_timeouts_release_packets_unchanged() {
        let (h, now) = (late_hello(), Instant::now());
        let s1 = seg(40002, 7000, &h[..1460]);

        // out-of-order continuation
        let mut r = Reassembler::<u8>::default();
        assert!(matches!(feed(&mut r, &s1, now), Step::Hold));
        let far = seg(40002, 7000 + 3000, &h[1460..]);
        match feed(&mut r, &far, now) {
            Step::Release(v) => assert_eq!((v.len(), &v[0].pkt, &v[1].pkt), (2, &s1, &far)),
            _ => panic!("expected a release"),
        }
        assert!(r.is_idle());

        // the client retransmits the first segment
        assert!(matches!(feed(&mut r, &s1, now), Step::Hold));
        assert!(matches!(feed(&mut r, &s1, now), Step::Release(v) if v.len() == 2));

        // nothing follows: the sweeper hands the packet back
        assert!(matches!(feed(&mut r, &s1, now), Step::Hold));
        assert!(r.sweep(now).is_empty());
        let late = r.sweep(now + HOLD_TIMEOUT);
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].pkt, s1);
        assert!(r.is_idle());
    }

    #[test]
    fn unrelated_data_and_flows_are_independent() {
        let mut r = Reassembler::<u8>::default();
        let (h, now) = (late_hello(), Instant::now());
        assert!(matches!(feed(&mut r, &seg(1, 1, b"\x17\x03\x03\x00\x05hello"), now), Step::Pass));
        assert!(matches!(feed(&mut r, &seg(2, 10, &h[..1460]), now), Step::Hold));
        assert!(matches!(feed(&mut r, &seg(3, 20, &h[..1460]), now), Step::Hold));
        assert!(matches!(feed(&mut r, &seg(3, 20 + 1460, &h[1460..]), now), Step::Assembled(_)));
        assert!(matches!(feed(&mut r, &seg(2, 10 + 1460, &h[1460..]), now), Step::Assembled(_)));
        assert!(r.is_idle());
    }
}
