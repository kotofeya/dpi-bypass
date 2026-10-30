//! Engine A — WinDivert packet loop (network layer).
//!
//!  * TLS ClientHello with a target SNI (443 and Discord's 2053/2083/2087/2096/8443),
//!    HTTP/80 request with a target Host -> "seqovl" split, fakes only, or fakes + split
//!    (+ disorder); fakes fooled by TTL, bad checksum or bad sequence numbers
//!  * UDP/443 QUIC Initial with a target SNI      -> dropped (app falls back to TCP/TLS)
//!  * UDP to Discord voice ports (19294-19344, 50000-50100) -> N decoy datagrams before
//!    each of the first 3 packets of a flow
//!
//! Everything not matched is re-injected untouched. Packets we inject via WinDivertSend are
//! not captured again by this handle, so there is no feedback loop.

#[cfg(windows)]
pub mod ffi;
pub mod packet;
pub mod quic;
pub mod tls;

#[cfg(windows)]
pub use imp::Engine;

#[cfg(windows)]
mod imp {
    use super::ffi::{Address, Divert};
    use super::packet::{self, Tcp4};
    use super::{quic, tls};
    use crate::prober::profile::{is_google, is_target, Fooling, Method, Profile, Shared};
    use anyhow::Result;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// zapret's badseq defaults: the fake sits 10000 bytes before the real data and acks
    /// 66000 bytes back, so the server discards it while a stateless DPI still parses it.
    const BADSEQ_SEQ: u32 = 10000;
    const BADSEQ_ACK: u32 = 66000;

    enum Action {
        /// caller re-injects the original packet
        Pass,
        /// we already injected replacements (or intentionally dropped it)
        Consumed,
    }

    pub struct Engine {
        dv: Arc<Divert>,
        profile: Shared,
        voice: Mutex<packet::VoiceFlows>,
    }

    impl Engine {
        pub fn open(profile: Shared) -> Result<Self> {
            let dv = Arc::new(Divert::open(&packet::filter(), 0)?);
            Ok(Self { dv, profile, voice: Mutex::new(packet::VoiceFlows::default()) })
        }

        /// Stops `run` (from any thread).
        pub fn shutdown(&self) {
            self.dv.shutdown();
        }

        pub fn run(&self) -> Result<()> {
            let mut buf = vec![0u8; 65535];
            tracing::info!("engine A: packet loop running");
            loop {
                let (n, addr) = match self.dv.recv(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if self.dv.is_closed() {
                            return Ok(());
                        }
                        tracing::warn!("WinDivertRecv: {e}");
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                };
                let p = self.profile.load_full();
                let pkt = &buf[..n];
                let act = self.handle(&p, pkt, &addr).unwrap_or_else(|e| {
                    tracing::debug!("handle: {e:#}");
                    Action::Pass
                });
                if let Action::Pass = act {
                    if let Err(e) = self.dv.send(pkt, &addr) {
                        tracing::debug!("reinject: {e}");
                    }
                }
            }
        }

        fn handle(&self, p: &Profile, pkt: &[u8], addr: &Address) -> Result<Action> {
            if pkt.len() < 28 || pkt[0] >> 4 != 4 {
                return Ok(Action::Pass);
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            match pkt[9] {
                6 => self.on_tcp(p, pkt, addr),
                17 => self.on_udp(p, pkt, addr, ihl),
                _ => Ok(Action::Pass),
            }
        }

        // -------------------------------------------------------------- TCP

        fn on_tcp(&self, p: &Profile, pkt: &[u8], addr: &Address) -> Result<Action> {
            let Some(t) = Tcp4::parse(pkt) else { return Ok(Action::Pass) };
            if t.ps < pkt.len() && (t.dport == 80 || packet::TLS_PORTS.contains(&t.dport)) {
                return self.desync(p, pkt, addr, &t);
            }
            Ok(Action::Pass)
        }

        fn desync(&self, p: &Profile, pkt: &[u8], addr: &Address, t: &Tcp4) -> Result<Action> {
            let (ihl, ps) = (t.ihl, t.ps);
            let payload = &pkt[ps..];

            if payload.len() < 2 {
                return Ok(Action::Pass);
            }
            let (host, split, fake) = if t.dport != 80 {
                let Some(h) = tls::parse_client_hello(payload) else { return Ok(Action::Pass) };
                if !is_target(&h.sni) {
                    return Ok(Action::Pass);
                }
                let k = p.split.resolve(h.sni_off, h.sni.len(), payload.len());
                (h.sni, k, tls::build_fake_client_hello(&p.fake_sni))
            } else {
                let Some((i, host)) = packet::http_host(payload) else { return Ok(Action::Pass) };
                if !is_target(&host) {
                    return Ok(Action::Pass);
                }
                let k = (i + 4).clamp(1, payload.len() - 1); // "\r\nHo|st:"
                (host, k, format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", p.fake_sni).into_bytes())
            };

            if p.method == Method::SeqOvl {
                // [fake hello bytes | payload[0]] at seq-ovl, then payload[1..]: the DPI sees the
                // fake SNI first, the server trims the bytes that precede its receive window.
                let google = is_google(&host);
                let (sni, unit, ovl) = if google { ("www.google.com", 681, 681) } else { ("4pda.to", 284, 568) };
                let pattern = tls::seqovl_pattern(sni, unit, ovl);
                let mut first = pattern;
                first.push(payload[0]);
                let mut s1 = packet::build_tcp(pkt, ihl, ps, 0u32.wrapping_sub(ovl as u32), &first, None);
                let mut s2 = packet::build_tcp(pkt, ihl, ps, 1, &payload[1..], None);
                if google {
                    // ip-id=zero, as zapret does for Google
                    s1[4..6].fill(0);
                    s2[4..6].fill(0);
                }
                tracing::debug!("{} {host}:{} -> seqovl {ovl}", if t.dport == 80 { "HTTP" } else { "TLS" }, t.dport);
                self.emit(addr, s1, ihl + 16, false)?;
                self.emit(addr, s2, ihl + 16, false)?;
                return Ok(Action::Consumed);
            }
            let kind = if t.dport == 80 { "HTTP" } else { "TLS" };
            tracing::debug!("{kind} {host}:{} -> {:?} x{} {:?}", t.dport, p.method, p.fake_count, p.fooling);

            // 1) decoys: same 4-tuple as the real data, but never accepted by the server
            for _ in 0..p.fake_count.max(1) {
                self.emit_fake(p.fooling, addr, pkt, ihl, ps, &fake)?;
            }
            if p.method == Method::Fake {
                return Ok(Action::Pass); // the original segment follows the decoys
            }

            // 2) real data in two segments, optionally out of order
            let s1 = packet::build_tcp(pkt, ihl, ps, 0, &payload[..split], None);
            let s2 = packet::build_tcp(pkt, ihl, ps, split as u32, &payload[split..], None);
            if p.disorder {
                self.emit(addr, s2, ihl + 16, false)?;
                self.emit(addr, s1, ihl + 16, false)?;
            } else {
                self.emit(addr, s1, ihl + 16, false)?;
                self.emit(addr, s2, ihl + 16, false)?;
            }
            Ok(Action::Consumed)
        }

        /// One fake TCP segment carrying `fake`, made unacceptable to the server by `fooling`.
        fn emit_fake(&self, fooling: Fooling, addr: &Address, pkt: &[u8], ihl: usize, ps: usize, fake: &[u8]) -> Result<()> {
            match fooling {
                Fooling::Ttl(ttl) => self.emit(addr, packet::build_tcp(pkt, ihl, ps, 0, fake, Some(ttl)), ihl + 16, false),
                Fooling::BadSum => self.emit(addr, packet::build_tcp(pkt, ihl, ps, 0, fake, None), ihl + 16, true),
                Fooling::BadSeq => {
                    let mut v = packet::build_tcp(pkt, ihl, ps, 0u32.wrapping_sub(BADSEQ_SEQ), fake, None);
                    packet::shift_ack(&mut v, ihl, BADSEQ_ACK);
                    self.emit(addr, v, ihl + 16, false)
                }
            }
        }

        /// Fix checksums, optionally corrupt the L4 checksum afterwards (the "BadSum" fake), inject.
        fn emit(&self, addr: &Address, mut v: Vec<u8>, l4_csum_off: usize, corrupt: bool) -> Result<()> {
            let mut a = *addr;
            self.dv.calc_checksums(&mut v, &mut a);
            if corrupt {
                v[l4_csum_off] ^= 0xff;
            }
            self.dv.send(&v, &a)?;
            Ok(())
        }

        // -------------------------------------------------------------- UDP

        fn on_udp(&self, p: &Profile, pkt: &[u8], addr: &Address, ihl: usize) -> Result<Action> {
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
                    Some(s) if is_target(&s) => {
                        tracing::debug!("QUIC {s} dropped -> TCP fallback");
                        Action::Consumed
                    }
                    _ => Action::Pass,
                });
            }

            // Discord voice (RTC): decoys in front of the first datagrams of every flow, whatever
            // they carry (IP discovery, STUN, or encrypted RTP straight away).
            if packet::is_discord_voice_port(dport) && !payload.is_empty() {
                let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                let first = self.voice.lock().unwrap().needs_decoys(sport, dst, dport, Instant::now());
                if first {
                    // UDP has no sequence numbers: "badseq" decoys simply go out as they are
                    let (ttl, bad_sum) = match p.fooling {
                        Fooling::Ttl(t) => (Some(t), false),
                        Fooling::BadSum => (None, true),
                        Fooling::BadSeq => (None, false),
                    };
                    let n = p.discord_fakes.clamp(1, 10);
                    for i in 0..n {
                        let fake = packet::voice_decoy(i);
                        self.emit(addr, packet::build_udp(pkt, ihl, &fake, ttl), ihl + 6, bad_sum)?;
                    }
                    tracing::debug!("discord voice {dst}:{dport} ({} bytes): {n} decoys", payload.len());
                }
            }
            Ok(Action::Pass) // the real datagram follows the decoys
        }
    }
}
