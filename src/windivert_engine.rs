//! Engine A — WinDivert packet loop (network layer).
//!
//!  * TLS ClientHello with a target SNI (443 and Discord's 2053/2083/2087/2096/8443); a hello
//!    whose SNI is not in the first segment is held until the next one arrives (reasm.rs);
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
pub mod reasm;
pub mod tls;

#[cfg(windows)]
pub use imp::Engine;

#[cfg(windows)]
mod imp {
    use super::ffi::{Address, Divert};
    use super::packet::{self, Tcp4};
    use super::reasm::{Held, Reassembler, Step};
    use super::tls::Hello;
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
        reasm: Mutex<Reassembler<Address>>,
        quic: Mutex<quic::QuicTracker>,
    }

    impl Engine {
        pub fn open(profile: Shared) -> Result<Self> {
            let dv = Arc::new(Divert::open(&packet::filter(), 0)?);
            Ok(Self {
                dv,
                profile,
                voice: Mutex::new(packet::VoiceFlows::default()),
                reasm: Mutex::new(Reassembler::default()),
                quic: Mutex::new(quic::QuicTracker::default()),
            })
        }

        /// Stops `run` (from any thread).
        pub fn shutdown(&self) {
            self.dv.shutdown();
        }

        /// True once `shutdown` was requested, i.e. `run` returning is expected.
        pub fn stopping(&self) -> bool {
            self.dv.is_closed()
        }

        pub fn run(&self) -> Result<()> {
            let mut buf = vec![0u8; 65535];
            let mut errors = 0u32;
            tracing::info!("engine A: packet loop running");
            loop {
                let (n, addr) = match self.dv.recv(&mut buf) {
                    Ok(v) => {
                        errors = 0;
                        v
                    }
                    Err(e) => {
                        if self.dv.is_closed() {
                            return Ok(());
                        }
                        errors += 1;
                        if errors <= 3 {
                            tracing::warn!("WinDivertRecv: {e}");
                        }
                        if errors >= 100 {
                            // the handle is dead (driver reset, adapter change): let the caller
                            // restart the whole process, which reopens the driver
                            anyhow::bail!("WinDivertRecv keeps failing: {e}");
                        }
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
            if t.ps >= pkt.len() {
                return Ok(Action::Pass);
            }
            if t.dport == 80 {
                return self.on_http(p, pkt, addr, &t);
            }
            if !packet::TLS_PORTS.contains(&t.dport) {
                return Ok(Action::Pass);
            }

            let now = Instant::now();
            let (stale, step) = {
                let mut r = self.reasm.lock().unwrap();
                (r.sweep(now), r.on_data(pkt, *addr, &t, now))
            };
            self.release(stale);
            match step {
                Step::Pass => Ok(Action::Pass),
                Step::Hold => Ok(Action::Consumed),
                Step::Hello(h) => {
                    let payload = &pkt[t.ps..];
                    self.on_hello(p, pkt, addr, &t, payload, payload.len(), &h)
                }
                Step::Assembled(a) => {
                    let first = &a.segs[0];
                    let res = match Tcp4::parse(&first.pkt) {
                        Some(t0) => self.on_hello(p, &first.pkt, &first.addr, &t0, &a.data, a.mss, &a.hello),
                        None => Ok(Action::Pass),
                    };
                    if !matches!(res, Ok(Action::Consumed)) {
                        // nothing was sent in place of the held segments: send them as they were
                        if let Err(e) = &res {
                            tracing::debug!("assembled hello: {e:#}");
                        }
                        self.release(a.segs);
                    }
                    Ok(Action::Consumed)
                }
                Step::Release(v) => {
                    self.release(v);
                    Ok(Action::Consumed)
                }
            }
        }

        /// Re-injects held packets unchanged.
        fn release(&self, held: Vec<Held<Address>>) {
            for h in held {
                if let Err(e) = self.dv.send(&h.pkt, &h.addr) {
                    tracing::debug!("release: {e}");
                }
            }
        }

        /// A TLS ClientHello whose SNI is known. `payload` is the whole (possibly reassembled)
        /// message starting at the sequence number of `pkt`.
        #[allow(clippy::too_many_arguments)]
        fn on_hello(
            &self,
            p: &Profile,
            pkt: &[u8],
            addr: &Address,
            t: &Tcp4,
            payload: &[u8],
            mss: usize,
            h: &Hello,
        ) -> Result<Action> {
            if !is_target(&h.sni) || payload.len() < 2 {
                return Ok(Action::Pass);
            }
            let split = p.split.resolve(h.sni_off, h.sni.len(), payload.len());
            let fake = tls::build_fake_client_hello(&p.fake_sni);
            self.apply(p, pkt, addr, t, payload, mss, &h.sni, split, &fake)
        }

        fn on_http(&self, p: &Profile, pkt: &[u8], addr: &Address, t: &Tcp4) -> Result<Action> {
            let payload = &pkt[t.ps..];
            let Some((i, host)) = packet::http_host(payload) else { return Ok(Action::Pass) };
            if !is_target(&host) || payload.len() < 2 {
                return Ok(Action::Pass);
            }
            let split = (i + 4).clamp(1, payload.len() - 1); // "\r\nHo|st:"
            let fake = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", p.fake_sni).into_bytes();
            self.apply(p, pkt, addr, t, payload, payload.len(), &host, split, &fake)
        }

        /// Runs the strategy on `payload`, the message that starts at the sequence number of
        /// `pkt`. Every injected segment carries at most `mss` payload bytes, so a reassembled
        /// hello re-cut at an arbitrary offset never exceeds the MTU. Returns `Pass` when the
        /// original data is still to be sent by the caller (plain fakes).
        #[allow(clippy::too_many_arguments)]
        fn apply(
            &self,
            p: &Profile,
            pkt: &[u8],
            addr: &Address,
            t: &Tcp4,
            payload: &[u8],
            mss: usize,
            host: &str,
            split: usize,
            fake: &[u8],
        ) -> Result<Action> {
            let (ihl, ps) = (t.ihl, t.ps);
            let kind = if t.dport == 80 { "HTTP" } else { "TLS" };

            if p.method == Method::SeqOvl {
                // [fake hello bytes | payload[0]] placed `ovl` bytes before the real data, then
                // payload[1..]: the DPI reads the fake SNI first, the server trims the bytes that
                // precede its receive window.
                let google = is_google(host);
                let (sni, unit, ovl) = if google { ("www.google.com", 681, 681) } else { ("4pda.to", 284, 568) };
                let mut first = tls::seqovl_pattern(sni, unit, ovl);
                first.push(payload[0]);
                let mut out = packet::segments(pkt, ihl, ps, 0u32.wrapping_sub(ovl as u32), &first, mss);
                out.extend(packet::segments(pkt, ihl, ps, 1, &payload[1..], mss));
                if google {
                    // ip-id=zero, as zapret does for Google
                    out.iter_mut().for_each(|s| s[4..6].fill(0));
                }
                tracing::debug!("{kind} {host}:{} -> seqovl {ovl}, {} segments", t.dport, out.len());
                for s in out {
                    self.emit(addr, s, ihl + 16, false)?;
                }
                return Ok(Action::Consumed);
            }
            tracing::debug!("{kind} {host}:{} -> {:?} x{} {:?}", t.dport, p.method, p.fake_count, p.fooling);

            // 1) decoys: same 4-tuple as the real data, but never accepted by the server
            for _ in 0..p.fake_count.max(1) {
                self.emit_fake(p.fooling, addr, pkt, ihl, ps, fake)?;
            }
            if p.method == Method::Fake {
                return Ok(Action::Pass); // the original segment(s) follow the decoys
            }

            // 2) real data cut at `split`, optionally sent in reverse order
            let mut out = packet::segments(pkt, ihl, ps, 0, &payload[..split], mss);
            out.extend(packet::segments(pkt, ihl, ps, split as u32, &payload[split..], mss));
            if p.disorder {
                out.reverse();
            }
            for s in out {
                self.emit(addr, s, ihl + 16, false)?;
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
                let drop = self.quic.lock().unwrap().should_drop(payload, Instant::now(), is_target);
                return Ok(if drop == Some(true) { Action::Consumed } else { Action::Pass });
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
