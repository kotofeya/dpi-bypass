//! Engine A — WinDivert packet loop (network layer).
//!
//!  * TCP to Telegram (443/80/5222) -> reflected into Engine B's transparent listener via the
//!    NAT table (see nat_table.rs); replies from the listener are reflected back
//!  * IPv6 SYN to Telegram           -> answered with RST so the app uses IPv4 (reflectable)
//!  * TCP/443 TLS ClientHello with a target SNI  -> [fake(s)] + split + (disorder)
//!  * TCP/80  HTTP request with a target Host     -> same, split inside "Host"
//!  * UDP/443 QUIC Initial with a YouTube SNI     -> dropped (browser falls back to TCP/TLS)
//!  * UDP/50000+ 74-byte Discord IP-discovery     -> N fake datagrams injected first
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
    use super::packet::{self, Tcp4, ACK, FIN, RST, SYN};
    use super::{quic, tls};
    use crate::nat_table::{self, FlowKey, NatTable};
    use crate::obfs2;
    use crate::prober::profile::{is_target, is_youtube, Profile, Shared};
    use anyhow::Result;
    use std::sync::Arc;
    use std::time::Duration;

    enum Action {
        /// caller re-injects the original packet
        Pass,
        /// we already injected replacements (or intentionally dropped it)
        Consumed,
    }

    pub struct Engine {
        dv: Arc<Divert>,
        profile: Shared,
        nat: Arc<NatTable>,
        bridge_port: u16,
    }

    impl Engine {
        pub fn open(profile: Shared, nat: Arc<NatTable>, bridge_port: u16) -> Result<Self> {
            let dv = Arc::new(Divert::open(&packet::filter(bridge_port), 0)?);
            Ok(Self { dv, profile, nat, bridge_port })
        }

        /// Stops `run` (from any thread).
        pub fn shutdown(&self) {
            self.dv.shutdown();
        }

        pub fn run(&self) -> Result<()> {
            let mut buf = vec![0u8; 65535];
            tracing::info!("engine A: packet loop running (bridge port {})", self.bridge_port);
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
                let pkt = &mut buf[..n];
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

        fn handle(&self, p: &Profile, pkt: &mut [u8], addr: &Address) -> Result<Action> {
            if pkt.is_empty() {
                return Ok(Action::Pass);
            }
            if pkt[0] >> 4 == 6 {
                return self.on_ipv6(pkt, addr);
            }
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

        /// Inject a rewritten packet with fresh checksums.
        fn inject(&self, pkt: &mut [u8], addr: &mut Address) -> Result<()> {
            self.dv.calc_checksums(pkt, addr);
            self.dv.send(pkt, addr)?;
            Ok(())
        }

        // -------------------------------------------------------------- IPv6

        fn on_ipv6(&self, pkt: &[u8], addr: &Address) -> Result<Action> {
            let Some((dst, mut rst)) = packet::ipv6_syn_rst(pkt) else { return Ok(Action::Pass) };
            if !obfs2::is_telegram_v6(dst) {
                return Ok(Action::Pass);
            }
            let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
            if self.nat.is_bypassed(sport) {
                return Ok(Action::Pass);
            }
            let mut a = *addr;
            a.set_outbound(false);
            self.inject(&mut rst, &mut a)?;
            tracing::debug!("IPv6 SYN to {dst} refused -> IPv4 fallback");
            Ok(Action::Consumed)
        }

        // -------------------------------------------------------------- TCP

        fn on_tcp(&self, p: &Profile, pkt: &mut [u8], addr: &Address) -> Result<Action> {
            let Some(t) = Tcp4::parse(pkt) else { return Ok(Action::Pass) };

            if t.sport == self.bridge_port {
                return self.reflect_reply(pkt, addr, &t);
            }
            if packet::TG_PORTS.contains(&t.dport) && obfs2::is_telegram_v4(t.dst) {
                if let Some(a) = self.reflect_client(pkt, addr, &t)? {
                    return Ok(a);
                }
            }
            if t.ps < pkt.len() && (t.dport == 443 || t.dport == 80) {
                return self.desync(p, pkt, addr, &t);
            }
            Ok(Action::Pass)
        }

        /// Client -> Telegram: L:cport -> T:dport  becomes  T:cport -> L:BRIDGE (inbound).
        /// Returns None when the flow is not ours (bypassed / pre-existing connection).
        fn reflect_client(&self, pkt: &mut [u8], addr: &Address, t: &Tcp4) -> Result<Option<Action>> {
            let key = FlowKey { remote: t.dst, client_port: t.sport };
            let entry = if t.has(SYN) && !t.has(ACK) {
                if self.nat.is_bypassed(t.sport) {
                    self.nat.remove(&key);
                    return Ok(None);
                }
                tracing::debug!("redirect {}:{} -> {}:{}", t.src, t.sport, t.dst, t.dport);
                self.nat.on_syn(key, t.src, t.dport)
            } else {
                match self.nat.lookup(&key) {
                    Some(e) => {
                        let mut f = nat_table::ESTABLISHED;
                        if t.has(FIN) {
                            f |= nat_table::CLIENT_FIN;
                        }
                        if t.has(RST) {
                            f |= nat_table::RESET;
                        }
                        self.nat.mark(&e, f);
                        e
                    }
                    None => return Ok(None),
                }
            };
            if entry.orig_port != t.dport {
                return Ok(None); // same client port towards another Telegram port: not this flow
            }
            packet::reflect4(pkt, t.ihl, None, Some(self.bridge_port));
            let mut a = *addr;
            a.set_outbound(false);
            self.inject(pkt, &mut a)?;
            Ok(Some(Action::Consumed))
        }

        /// Bridge -> client: L:BRIDGE -> T:cport  becomes  T:dport -> L:cport (inbound).
        fn reflect_reply(&self, pkt: &mut [u8], addr: &Address, t: &Tcp4) -> Result<Action> {
            let key = FlowKey { remote: t.dst, client_port: t.dport };
            let Some(e) = self.nat.lookup(&key) else {
                // not a reflected flow (e.g. a stray RST): never leak the bridge port to the wire
                return Ok(Action::Consumed);
            };
            let mut f = 0;
            if t.has(FIN) {
                f |= nat_table::BRIDGE_FIN;
            }
            if t.has(RST) {
                f |= nat_table::RESET;
            }
            if f != 0 {
                self.nat.mark(&e, f);
            }
            packet::reflect4(pkt, t.ihl, Some(e.orig_port), None);
            let mut a = *addr;
            a.set_outbound(false);
            self.inject(pkt, &mut a)?;
            Ok(Action::Consumed)
        }

        fn desync(&self, p: &Profile, pkt: &[u8], addr: &Address, t: &Tcp4) -> Result<Action> {
            let (ihl, ps) = (t.ihl, t.ps);
            let payload = &pkt[ps..];

            let (split, fake) = if t.dport == 443 {
                let Some(h) = tls::parse_client_hello(payload) else { return Ok(Action::Pass) };
                if !is_target(&h.sni) {
                    return Ok(Action::Pass);
                }
                tracing::debug!("TLS {} -> split", h.sni);
                (p.split.resolve(h.sni_off, h.sni.len(), payload.len()), tls::build_fake_client_hello(&p.fake_sni))
            } else {
                let Some((i, host)) = packet::http_host(payload) else { return Ok(Action::Pass) };
                if !is_target(&host) || payload.len() < 2 {
                    return Ok(Action::Pass);
                }
                let k = (i + 4).clamp(1, payload.len() - 1); // "\r\nHo|st:"
                (k, format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", p.fake_sni).into_bytes())
            };

            // 1) decoys: same 4-tuple + same seq as the real data, but never accepted by the server
            let ttl = (p.fake_ttl > 0).then_some(p.fake_ttl);
            if p.fake_count > 0 && (ttl.is_some() || p.bad_sum) {
                for _ in 0..p.fake_count {
                    self.emit(addr, packet::build_tcp(pkt, ihl, ps, 0, &fake, ttl), ihl + 16, p.bad_sum)?;
                }
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
                let n = p.discord_fakes.min(4);
                for i in 0..n {
                    let fake: Vec<u8> = match i % 3 {
                        0 => vec![0u8; 74],
                        1 => (0..74).map(|_| fastrand::u8(..)).collect(),
                        _ => (0..fastrand::usize(40..=120)).map(|_| fastrand::u8(..)).collect(),
                    };
                    self.emit(addr, packet::build_udp(pkt, ihl, &fake, ttl), ihl + 6, p.bad_sum)?;
                }
                tracing::debug!("discord voice handshake: {n} fakes");
                return Ok(Action::Pass); // real packet follows the decoys
            }
            Ok(Action::Pass)
        }
    }
}
