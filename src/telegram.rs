//! Engine B — local SOCKS5 (127.0.0.1:1080) and MTProto-proxy (127.0.0.1:1443) listeners that
//! bridge Telegram's obfuscated2 stream into wss://kws{N}.web.telegram.org/apiws.
//!
//! Obfuscated2 init (64 bytes): [0..8) random | [8..40) key | [40..56) iv | [56..60) proto tag |
//! [60..62) dc id (i16 LE, negative = media) | [62..64) random. The whole 64 bytes are
//! AES-256-CTR encrypted with key/iv (SOCKS: raw key; MTProxy: sha256(key || secret)).

use crate::dialer::{Ws, WsDialer};
use anyhow::{bail, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub const SOCKS_ADDR: &str = "127.0.0.1:1080";
pub const MTP_ADDR: &str = "127.0.0.1:1443";

pub struct Ctx {
    pub dialer: Arc<WsDialer>,
    pub secret: [u8; 16],
    /// notified after repeated WS failures; Engine C waits on this to re-probe
    pub probe: Arc<Notify>,
    fails: AtomicU32,
}
impl Ctx {
    pub fn new(dialer: Arc<WsDialer>, secret: [u8; 16]) -> Self {
        Self { dialer, secret, probe: Arc::new(Notify::new()), fails: AtomicU32::new(0) }
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
            let _ = s.set_nodelay(true);
            let sec = c.secret;
            if let Err(e) = mtproto_session(s, Some(sec), &c, None).await {
                debug!("mtproxy session: {e:#}");
            }
        });
    }
}

// ---------------------------------------------------------------- SOCKS5

enum Dest {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String),
}

const NETS: &[([u8; 4], u8)] = &[
    ([149, 154, 160, 0], 20),
    ([91, 108, 4, 0], 22),
    ([91, 108, 8, 0], 22),
    ([91, 108, 12, 0], 22),
    ([91, 108, 16, 0], 22),
    ([91, 108, 56, 0], 22),
    ([185, 76, 151, 0], 24),
];
fn is_telegram(ip: Ipv4Addr) -> bool {
    let x = u32::from(ip);
    NETS.iter().any(|(n, b)| {
        let mask = !0u32 << (32 - *b as u32);
        x & mask == u32::from_be_bytes(*n) & mask
    })
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
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

    match dest {
        Dest::V4(ip) if is_telegram(ip) => {
            mtproto_session(c, None, ctx, Some(SocketAddr::from((ip, port)))).await
        }
        Dest::V4(ip) => direct(c, TcpStream::connect((ip, port)).await?, &[]).await,
        Dest::V6(ip) => direct(c, TcpStream::connect((ip, port)).await?, &[]).await,
        Dest::Name(n) => direct(c, TcpStream::connect((n.as_str(), port)).await?, &[]).await,
    }
}

async fn direct(mut c: TcpStream, mut up: TcpStream, pre: &[u8]) -> Result<()> {
    up.set_nodelay(true)?;
    up.write_all(pre).await?;
    copy_bidirectional(&mut c, &mut up).await?;
    Ok(())
}

// ---------------------------------------------------------------- obfuscated2

struct Keys {
    dk: [u8; 32],
    div: [u8; 16],
    ek: [u8; 32],
    eiv: [u8; 16],
}

fn derive(init: &[u8; 64], secret: Option<&[u8; 16]>) -> Keys {
    let mut rev: [u8; 48] = init[8..56].try_into().unwrap();
    rev.reverse();
    let mk = |raw: &[u8]| -> [u8; 32] {
        match secret {
            Some(s) => {
                let mut h = Sha256::new();
                h.update(raw);
                h.update(s);
                h.finalize().into()
            }
            None => raw.try_into().unwrap(),
        }
    };
    Keys {
        dk: mk(&init[8..40]),
        div: init[40..56].try_into().unwrap(),
        ek: mk(&rev[..32]),
        eiv: rev[32..48].try_into().unwrap(),
    }
}

/// Fresh secret-less init for the upstream gateway.
fn make_upstream(tag: [u8; 4], dc: i16) -> ([u8; 64], Aes256Ctr, Aes256Ctr) {
    let mut init = [0u8; 64];
    loop {
        init.iter_mut().for_each(|b| *b = fastrand::u8(..));
        if init[0] == 0xef || init[4..8] == [0, 0, 0, 0] {
            continue;
        }
        let w = [init[0], init[1], init[2], init[3]];
        if matches!(
            w,
            [0x48, 0x45, 0x41, 0x44] | [0x50, 0x4f, 0x53, 0x54] | [0x47, 0x45, 0x54, 0x20] | [0x4f, 0x50, 0x54, 0x49]
                | [0xdd, 0xdd, 0xdd, 0xdd] | [0xee, 0xee, 0xee, 0xee] | [0x16, 0x03, 0x01, 0x02]
        ) {
            continue;
        }
        break;
    }
    init[56..60].copy_from_slice(&tag);
    init[60..62].copy_from_slice(&dc.to_le_bytes());
    let k: [u8; 32] = init[8..40].try_into().unwrap();
    let iv: [u8; 16] = init[40..56].try_into().unwrap();
    let mut ue = Aes256Ctr::new(&k.into(), &iv.into());
    let mut rev: [u8; 48] = init[8..56].try_into().unwrap();
    rev.reverse();
    let rk: [u8; 32] = rev[..32].try_into().unwrap();
    let riv: [u8; 16] = rev[32..48].try_into().unwrap();
    let ud = Aes256Ctr::new(&rk.into(), &riv.into());
    let mut enc = init;
    ue.apply_keystream(&mut enc); // ue now sits at offset 64, ready for payload
    let mut out = init;
    out[56..64].copy_from_slice(&enc[56..64]);
    (out, ue, ud)
}

struct Up {
    c_dec: Aes256Ctr,
    u_enc: Aes256Ctr,
}
struct Down {
    u_dec: Aes256Ctr,
    c_enc: Aes256Ctr,
}

fn ws_hosts(dc: usize, media: bool) -> Vec<String> {
    let names = ["pluto", "venus", "aurora", "vesta", "flora"];
    let mut v = vec![];
    if media {
        v.push(format!("kws{dc}-1.web.telegram.org"));
    }
    v.push(format!("kws{dc}.web.telegram.org"));
    v.push(format!("{}.web.telegram.org", names[dc - 1]));
    v
}

async fn mtproto_session(mut c: TcpStream, secret: Option<[u8; 16]>, ctx: &Ctx, fallback: Option<SocketAddr>) -> Result<()> {
    let mut init = [0u8; 64];
    c.read_exact(&mut init).await?;
    let keys = derive(&init, secret.as_ref());
    let mut dec = Aes256Ctr::new(&keys.dk.into(), &keys.div.into());
    let mut plain = init;
    dec.apply_keystream(&mut plain);
    let tag = [plain[56], plain[57], plain[58], plain[59]];
    let valid = matches!(tag, [0xef, 0xef, 0xef, 0xef] | [0xee, 0xee, 0xee, 0xee] | [0xdd, 0xdd, 0xdd, 0xdd]);
    let dc = i16::from_le_bytes([plain[60], plain[61]]);
    let id = dc.unsigned_abs() as usize;

    if !valid || !(1..=5).contains(&id) {
        return match fallback {
            Some(a) => direct(c, TcpStream::connect(a).await?, &init).await,
            None => bail!("invalid obfuscated2 init"),
        };
    }

    let mut ws: Option<Ws> = None;
    for h in ws_hosts(id, dc < 0) {
        match ctx.dialer.connect(&h).await {
            Ok(w) => {
                debug!("DC{id} via {h}");
                ws = Some(w);
                break;
            }
            Err(e) => warn!("ws {h}: {e:#}"),
        }
    }
    let Some(ws) = ws else {
        ctx.failed();
        return match fallback {
            Some(a) => direct(c, TcpStream::connect(a).await?, &init).await,
            None => bail!("all gateways failed for DC{id}"),
        };
    };
    ctx.ok();

    let (first, x) = if secret.is_some() {
        let (iu, ue, ud) = make_upstream(tag, dc);
        let ce = Aes256Ctr::new(&keys.ek.into(), &keys.eiv.into());
        (iu.to_vec(), Some((Up { c_dec: dec, u_enc: ue }, Down { u_dec: ud, c_enc: ce })))
    } else {
        (init.to_vec(), None) // SOCKS mode: client init is already valid for the gateway
    };
    bridge(c, ws, first, x).await
}

async fn bridge(client: TcpStream, ws: Ws, first: Vec<u8>, x: Option<(Up, Down)>) -> Result<()> {
    let (mut cr, mut cw) = client.into_split();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::Binary(first.into())).await?;
    let (mut up, mut down) = match x {
        Some((u, d)) => (Some(u), Some(d)),
        None => (None, None),
    };

    let a = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut d = buf[..n].to_vec();
            if let Some(u) = up.as_mut() {
                u.c_dec.apply_keystream(&mut d);
                u.u_enc.apply_keystream(&mut d);
            }
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
                    if let Some(dn) = down.as_mut() {
                        dn.u_dec.apply_keystream(&mut d);
                        dn.c_enc.apply_keystream(&mut d);
                    }
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
