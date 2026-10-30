//! Engine B — Telegram bridge: MTProto streams are carried over
//! wss://kws{N}.web.telegram.org/apiws, which DPI boxes treat as ordinary web traffic.
//!
//! Entry points:
//!  * transparent (0.0.0.0:BRIDGE_PORT): connections Engine A reflected out of Telegram
//!    Desktop's own sockets — no proxy settings needed in the app. The NAT table restores the
//!    original destination; anything that is not MTProto is spliced to it directly.
//!  * SOCKS5 (127.0.0.1:1080) and MTProxy (127.0.0.1:1443): manual fallbacks for when the
//!    WinDivert driver cannot be loaded.
//!
//! Obfuscated2 clients are forwarded byte-for-byte (the gateway speaks the same transport);
//! plain abridged/intermediate clients are wrapped in a fresh obfuscated2 stream; MTProxy
//! clients are re-keyed from secret-keys to secret-less keys.

pub mod dialer;

use crate::nat_table::NatTable;
use crate::obfs2::{self, Aes256Ctr};
use anyhow::{anyhow, bail, Result};
use ctr::cipher::StreamCipher;
use dashmap::DashMap;
use dialer::{connect_bypassed, Ws, WsDialer};
use futures_util::{SinkExt, StreamExt};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

pub const SOCKS_ADDR: &str = "127.0.0.1:1080";
pub const MTP_ADDR: &str = "127.0.0.1:1443";
/// Port the reflected Telegram flows are delivered to (outside the ephemeral range).
pub const DEFAULT_BRIDGE_PORT: u16 = 17443;

/// How long a redirected client may take to send its first 64 bytes.
const PREFIX_TIMEOUT: Duration = Duration::from_secs(10);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(8);

// ---------------------------------------------------------------- gateway health

#[derive(Clone, Copy)]
struct GwStat {
    rtt: Duration,
    fails: u32,
    last_fail: Option<Instant>,
}

/// Per-hostname health of the WebSocket gateways, fed by real sessions and by the prober.
#[derive(Default)]
pub struct Gateways {
    stats: DashMap<String, GwStat>,
}

const FAIL_PENALTY: Duration = Duration::from_secs(120);

impl Gateways {
    pub fn record_ok(&self, host: &str, rtt: Duration) {
        self.stats.insert(host.to_string(), GwStat { rtt, fails: 0, last_fail: None });
    }

    pub fn record_fail(&self, host: &str) {
        let mut e = self
            .stats
            .entry(host.to_string())
            .or_insert(GwStat { rtt: Duration::from_secs(10), fails: 0, last_fail: None });
        e.fails = e.fails.saturating_add(1);
        e.last_fail = Some(Instant::now());
    }

    /// Candidate gateways for a DC, healthiest first.
    pub fn order(&self, dc: u8, media: bool) -> Vec<String> {
        let mut hosts = ws_hosts(dc, media);
        let score = |h: &String| -> (bool, u32, Duration) {
            match self.stats.get(h) {
                Some(s) => {
                    let penalized = s.fails > 0 && s.last_fail.is_some_and(|t| t.elapsed() < FAIL_PENALTY);
                    (penalized, if penalized { s.fails } else { 0 }, s.rtt)
                }
                None => (false, 0, Duration::from_secs(1)),
            }
        };
        // stable sort keeps the canonical order among equals
        hosts.sort_by_key(score);
        hosts
    }

    pub fn summary(&self) -> String {
        let mut v: Vec<String> = self
            .stats
            .iter()
            .map(|e| format!("{}={}ms/{}f", e.key(), e.rtt.as_millis(), e.fails))
            .collect();
        v.sort();
        v.join(" ")
    }
}

/// WebSocket endpoints serving a DC. `kwsN-1` carries media (file) traffic.
pub fn ws_hosts(dc: u8, media: bool) -> Vec<String> {
    const NAMES: [&str; 5] = ["pluto", "venus", "aurora", "vesta", "flora"];
    let mut v = vec![];
    if media {
        v.push(format!("kws{dc}-1.web.telegram.org"));
    }
    v.push(format!("kws{dc}.web.telegram.org"));
    v.push(format!("{}.web.telegram.org", NAMES[(dc as usize - 1) % 5]));
    v
}

/// Well-known production DC addresses, used to reach a DC directly from MTProxy sessions when
/// no gateway works (i.e. Telegram is not blocked after all).
fn dc_address(dc: u8) -> SocketAddr {
    let ip = match dc {
        1 => Ipv4Addr::new(149, 154, 175, 50),
        2 => Ipv4Addr::new(149, 154, 167, 51),
        3 => Ipv4Addr::new(149, 154, 175, 100),
        4 => Ipv4Addr::new(149, 154, 167, 91),
        _ => Ipv4Addr::new(149, 154, 171, 5),
    };
    SocketAddr::from((ip, 443))
}

// ---------------------------------------------------------------- context

pub struct Ctx {
    pub dialer: Arc<WsDialer>,
    pub nat: Arc<NatTable>,
    pub secret: [u8; 16],
    pub gateways: Gateways,
    /// notified after repeated WS failures; the prober waits on this to re-probe
    pub probe: Arc<Notify>,
    fails: AtomicU32,
}

impl Ctx {
    pub fn new(dialer: Arc<WsDialer>, secret: [u8; 16]) -> Self {
        Self {
            nat: dialer.nat().clone(),
            dialer,
            secret,
            gateways: Gateways::default(),
            probe: Arc::new(Notify::new()),
            fails: AtomicU32::new(0),
        }
    }

    fn failed(&self) {
        if self.fails.fetch_add(1, Ordering::Relaxed) + 1 >= 3 {
            self.fails.store(0, Ordering::Relaxed);
            self.probe.notify_one();
        }
    }

    fn ok(&self) {
        self.fails.store(0, Ordering::Relaxed);
    }

    /// Tries the gateways of `dc` in health order.
    async fn dial(&self, dc: u8, media: bool) -> Result<Ws> {
        let mut last = anyhow!("no gateway for DC{dc}");
        for h in self.gateways.order(dc, media) {
            let t0 = Instant::now();
            match self.dialer.connect(&h).await {
                Ok(w) => {
                    self.gateways.record_ok(&h, t0.elapsed());
                    self.ok();
                    debug!("DC{dc}{} via {h} in {:?}", if media { " (media)" } else { "" }, t0.elapsed());
                    return Ok(w);
                }
                Err(e) => {
                    self.gateways.record_fail(&h);
                    warn!("ws {h}: {e:#}");
                    last = e;
                }
            }
        }
        self.failed();
        Err(last)
    }
}

/// Persistent MTProxy secret (generated on first run, stored next to the exe).
pub fn load_secret() -> [u8; 16] {
    let path = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("secret.hex")));
    if let Some(p) = &path {
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Ok(b) = hex::decode(s.trim()) {
                if let Ok(a) = <[u8; 16]>::try_from(b) {
                    return a;
                }
            }
        }
    }
    let mut s = [0u8; 16];
    s.iter_mut().for_each(|b| *b = fastrand::u8(..));
    if let Some(p) = path {
        let _ = std::fs::write(p, hex::encode(s));
    }
    s
}

pub fn proxy_link(secret: &[u8; 16]) -> String {
    format!("tg://proxy?server=127.0.0.1&port=1443&secret=dd{}", hex::encode(secret))
}

// ---------------------------------------------------------------- listeners

/// Binds the transparent listener; done before WinDivert starts reflecting SYNs into it.
pub async fn bind_transparent(port: u16) -> Result<TcpListener> {
    Ok(TcpListener::bind(("0.0.0.0", port)).await?)
}

pub async fn serve_transparent(l: TcpListener, ctx: Arc<Ctx>) -> Result<()> {
    info!("transparent bridge listening on {}", l.local_addr()?);
    loop {
        let (s, peer) = l.accept().await?;
        let c = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = transparent_session(s, peer, &c).await {
                debug!("transparent {peer}: {e:#}");
            }
        });
    }
}

pub async fn serve_socks(ctx: Arc<Ctx>) -> Result<()> {
    let l = TcpListener::bind(SOCKS_ADDR).await?;
    info!("SOCKS5 listening on {SOCKS_ADDR}");
    loop {
        let (s, _) = l.accept().await?;
        let c = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = socks_session(s, &c).await {
                debug!("socks session: {e:#}");
            }
        });
    }
}

pub async fn serve_mtproxy(ctx: Arc<Ctx>) -> Result<()> {
    let l = TcpListener::bind(MTP_ADDR).await?;
    info!("MTProto proxy listening on {MTP_ADDR}");
    loop {
        let (s, _) = l.accept().await?;
        let c = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = mtproxy_session(s, &c).await {
                debug!("mtproxy session: {e:#}");
            }
        });
    }
}

// ---------------------------------------------------------------- transparent

/// Reads up to 64 bytes. Stops early for protocols that may legitimately send less and then
/// wait for the server (TLS / HTTP), and on EOF or timeout.
async fn read_prefix(c: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = [0u8; 64];
    let mut got = 0usize;
    let deadline = tokio::time::Instant::now() + PREFIX_TIMEOUT;
    while got < buf.len() {
        let n = match tokio::time::timeout_at(deadline, c.read(&mut buf[got..])).await {
            Ok(r) => r?,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        got += n;
        let tls = buf[0] == 0x16 && got >= 2 && buf[1] == 0x03;
        let http = buf[..got.min(8)].iter().take_while(|b| b.is_ascii_uppercase()).count() >= 3
            && buf[..got].contains(&b' ');
        if tls || http {
            break;
        }
    }
    Ok(buf[..got].to_vec())
}

async fn transparent_session(mut c: TcpStream, peer: SocketAddr, ctx: &Ctx) -> Result<()> {
    let SocketAddr::V4(peer) = peer else { bail!("unexpected IPv6 peer") };
    let Some(orig) = ctx.nat.original_dst(peer) else {
        bail!("no NAT entry (not a redirected flow), dropping");
    };
    c.set_nodelay(true)?;
    let server = *orig.ip();
    let pre = read_prefix(&mut c).await?;
    if pre.is_empty() {
        return Ok(());
    }

    // 1) obfuscated2 (what Telegram Desktop uses for direct DC connections)
    if let Ok(init) = <[u8; 64]>::try_from(pre.as_slice()) {
        if let Some(ci) = obfs2::parse_init(&init, None) {
            if let Some((dc, media)) = obfs2::resolve_dc(ci.dc, Some(server)) {
                match ctx.dial(dc, media).await {
                    Ok(ws) => {
                        info!("{orig} -> DC{dc}{} over WebSocket", if media { "m" } else { "" });
                        return bridge_ws(c, ws, init.to_vec(), vec![], vec![], vec![]).await;
                    }
                    Err(e) => debug!("{orig}: gateways failed ({e:#}), trying direct"),
                }
            }
            return direct(ctx, c, orig, &pre).await;
        }
    }

    // 2) plain MTProto transports: wrap them into obfuscated2
    if let Some((tag, marker)) = obfs2::plain_transport(&pre) {
        if let Some(dc) = obfs2::dc_for_ip(server) {
            match ctx.dial(dc, false).await {
                Ok(ws) => {
                    info!("{orig} -> DC{dc} ({tag:?}, wrapped) over WebSocket");
                    let up = obfs2::generate_init(tag, dc as i16);
                    return bridge_ws(c, ws, up.raw.to_vec(), pre[marker..].to_vec(), vec![up.enc], vec![up.dec])
                        .await;
                }
                Err(e) => debug!("{orig}: gateways failed ({e:#}), trying direct"),
            }
        }
    }

    // 3) anything else (TLS to web.telegram.org, HTTP, unknown DCs): splice to the original
    //    destination. That socket is bypassed, so Engine A's TLS desync still applies to it.
    direct(ctx, c, orig, &pre).await
}

async fn direct(ctx: &Ctx, mut c: TcpStream, to: SocketAddrV4, pre: &[u8]) -> Result<()> {
    let (mut up, _guard) = timeout(DIRECT_TIMEOUT, connect_bypassed(&ctx.nat, to.into()))
        .await
        .map_err(|_| anyhow!("direct connect to {to} timed out"))??;
    up.write_all(pre).await?;
    copy_bidirectional(&mut c, &mut up).await?;
    Ok(())
}

// ---------------------------------------------------------------- SOCKS5

enum Dest {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String),
}

async fn socks_session(mut c: TcpStream, ctx: &Ctx) -> Result<()> {
    c.set_nodelay(true)?;
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await?;
    if h[0] != 5 {
        bail!("not SOCKS5");
    }
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        c.write_all(&[5, 0xff]).await?;
        bail!("client requires authentication");
    }
    c.write_all(&[5, 0]).await?;

    let mut r = [0u8; 4];
    c.read_exact(&mut r).await?;
    if r[1] != 1 {
        c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("only CONNECT supported");
    }
    let dest = match r[3] {
        1 => {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await?;
            Dest::V4(Ipv4Addr::from(b))
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut n = vec![0u8; l[0] as usize];
            c.read_exact(&mut n).await?;
            Dest::Name(String::from_utf8_lossy(&n).into_owned())
        }
        4 => {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await?;
            Dest::V6(Ipv6Addr::from(b))
        }
        _ => bail!("bad ATYP"),
    };
    let mut pb = [0u8; 2];
    c.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    let target: SocketAddr = match dest {
        Dest::V4(ip) => (ip, port).into(),
        Dest::V6(ip) => (ip, port).into(),
        Dest::Name(n) => match timeout(DIRECT_TIMEOUT, tokio::net::lookup_host((n.as_str(), port))).await {
            Ok(Ok(mut it)) => match it.next() {
                Some(a) => a,
                None => {
                    c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    bail!("{n}: no addresses");
                }
            },
            _ => {
                c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                bail!("{n}: resolution failed");
            }
        },
    };
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

    let tg_v4 = match target {
        SocketAddr::V4(a) if obfs2::is_telegram_v4(*a.ip()) => Some(a),
        _ => None,
    };
    let tg_v6 = matches!(target, SocketAddr::V6(a) if obfs2::is_telegram_v6(*a.ip()));
    if tg_v4.is_some() || tg_v6 {
        let mut init = [0u8; 64];
        c.read_exact(&mut init).await?;
        if let Some(ci) = obfs2::parse_init(&init, None) {
            if let Some((dc, media)) = obfs2::resolve_dc(ci.dc, tg_v4.map(|a| *a.ip())) {
                if let Ok(ws) = ctx.dial(dc, media).await {
                    debug!("socks {target} -> DC{dc} over WebSocket");
                    return bridge_ws(c, ws, init.to_vec(), vec![], vec![], vec![]).await;
                }
            }
        }
        return splice_to(ctx, c, target, &init).await;
    }
    splice_to(ctx, c, target, &[]).await
}

async fn splice_to(ctx: &Ctx, mut c: TcpStream, to: SocketAddr, pre: &[u8]) -> Result<()> {
    let (mut up, _guard) = timeout(DIRECT_TIMEOUT, connect_bypassed(&ctx.nat, to))
        .await
        .map_err(|_| anyhow!("connect to {to} timed out"))??;
    up.write_all(pre).await?;
    copy_bidirectional(&mut c, &mut up).await?;
    Ok(())
}

// ---------------------------------------------------------------- MTProxy

async fn mtproxy_session(mut c: TcpStream, ctx: &Ctx) -> Result<()> {
    c.set_nodelay(true)?;
    let mut init = [0u8; 64];
    c.read_exact(&mut init).await?;
    let ci = obfs2::parse_init(&init, Some(&ctx.secret)).ok_or_else(|| anyhow!("bad secret / not MTProxy"))?;
    let (dc, media) = obfs2::resolve_dc(ci.dc, None).ok_or_else(|| anyhow!("unsupported DC {}", ci.dc))?;
    let up = obfs2::generate_init(ci.tag, ci.dc);

    match ctx.dial(dc, media).await {
        Ok(ws) => {
            debug!("mtproxy -> DC{dc} over WebSocket");
            bridge_ws(c, ws, up.raw.to_vec(), vec![], vec![ci.dec, up.enc], vec![up.dec, ci.enc]).await
        }
        Err(e) => {
            let addr = dc_address(dc);
            debug!("mtproxy DC{dc}: gateways failed ({e:#}), direct to {addr}");
            let (mut s, _guard) = timeout(DIRECT_TIMEOUT, connect_bypassed(&ctx.nat, addr))
                .await
                .map_err(|_| anyhow!("direct DC{dc} timed out"))??;
            s.write_all(&up.raw).await?;
            let (sr, sw) = s.into_split();
            let (cr, cw) = c.into_split();
            tokio::select! {
                r = pump(cr, sw, vec![ci.dec, up.enc]) => r,
                r = pump(sr, cw, vec![up.dec, ci.enc]) => r,
            }
        }
    }
}

// ---------------------------------------------------------------- pumps

fn apply(chain: &mut [Aes256Ctr], d: &mut [u8]) {
    for c in chain.iter_mut() {
        c.apply_keystream(d);
    }
}

async fn pump<R, W>(mut r: R, mut w: W, mut chain: Vec<Aes256Ctr>) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32768];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        apply(&mut chain, &mut buf[..n]);
        w.write_all(&buf[..n]).await?;
    }
}

/// client <-> WebSocket. `first` goes out verbatim as the first frame; `pending` is client
/// data already read (transformed by `up` like everything after it).
async fn bridge_ws(
    client: TcpStream,
    ws: Ws,
    first: Vec<u8>,
    mut pending: Vec<u8>,
    mut up: Vec<Aes256Ctr>,
    mut down: Vec<Aes256Ctr>,
) -> Result<()> {
    let (mut cr, mut cw) = client.into_split();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::Binary(first.into())).await?;
    if !pending.is_empty() {
        apply(&mut up, &mut pending);
        sink.send(Message::Binary(pending.into())).await?;
    }

    let a = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut d = buf[..n].to_vec();
            apply(&mut up, &mut d);
            sink.send(Message::Binary(d.into())).await?;
        }
        let _ = sink.close().await;
        Ok::<(), anyhow::Error>(())
    };
    let b = async move {
        while let Some(m) = stream.next().await {
            match m? {
                Message::Binary(bin) => {
                    let mut d = bin.to_vec();
                    apply(&mut down, &mut d);
                    cw.write_all(&d).await?;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = cw.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { r = a => r, r = b => r }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_order_prefers_healthy() {
        let g = Gateways::default();
        assert_eq!(g.order(2, false)[0], "kws2.web.telegram.org");
        g.record_fail("kws2.web.telegram.org");
        g.record_ok("venus.web.telegram.org", Duration::from_millis(80));
        let o = g.order(2, false);
        assert_eq!(o[0], "venus.web.telegram.org");
        assert_eq!(o[1], "kws2.web.telegram.org");
        assert_eq!(g.order(4, true)[0], "kws4-1.web.telegram.org");
    }
}
