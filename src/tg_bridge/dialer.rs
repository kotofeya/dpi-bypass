//! WebSocket dialer for Engine B: DNS (system -> Cloudflare DoH fallback), TCP, user-space
//! ClientHello fragmentation (TCP split + TLS record split), optional no-SNI, then the WS upgrade.
//!
//! Every socket opened here is bound first and its local port registered in the NAT table's
//! bypass set, so Engine A does not reflect our own gateway connections back into the bridge.

use crate::nat_table::{BypassGuard, NatTable};
use crate::prober::profile::{Shared, SplitAt, WsMethod};
use crate::windivert_engine::tls;
use anyhow::{anyhow, Result};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{sleep, timeout, Sleep};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};
use tokio_tungstenite::WebSocketStream;

pub struct Plan {
    pub split: SplitAt,
    pub record_split: bool,
    pub delay: Duration,
}

/// Turns the first write (the ClientHello) into several separate TCP segments.
pub struct FragIo<S> {
    inner: S,
    plan: Option<Plan>,
    chunks: VecDeque<Vec<u8>>,
    cur: Vec<u8>,
    cur_off: usize,
    owed: usize,
    delay: Option<Pin<Box<Sleep>>>,
    started: bool,
    _bypass: Option<BypassGuard>,
}

impl<S> FragIo<S> {
    pub fn new(inner: S, plan: Option<Plan>, bypass: Option<BypassGuard>) -> Self {
        Self {
            inner,
            plan,
            chunks: VecDeque::new(),
            cur: Vec::new(),
            cur_off: 0,
            owed: 0,
            delay: None,
            started: false,
            _bypass: bypass,
        }
    }
}

/// `connect()` from a pre-bound socket whose port is exempt from the transparent redirect.
pub async fn connect_bypassed(nat: &Arc<NatTable>, addr: SocketAddr) -> io::Result<(TcpStream, BypassGuard)> {
    let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    let any: SocketAddr = if addr.is_ipv4() { ([0u8; 4], 0).into() } else { ([0u16; 8], 0).into() };
    sock.bind(any)?;
    let guard = nat.bypass(sock.local_addr()?.port());
    let s = sock.connect(addr).await?;
    s.set_nodelay(true)?;
    Ok((s, guard))
}

fn plan_chunks(plan: &Plan, buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    let h = tls::parse_client_hello(buf)?;
    if buf.len() < 3 {
        return None;
    }
    let k = plan.split.resolve(h.sni_off, h.sni.len(), buf.len());
    if plan.record_split {
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if 5 + rec_len == buf.len() && rec_len > 2 {
            let hs = &buf[5..];
            let hk = k.saturating_sub(5).clamp(1, hs.len() - 1);
            let mk = |body: &[u8]| {
                let mut r = vec![buf[0], buf[1], buf[2]];
                r.extend_from_slice(&(body.len() as u16).to_be_bytes());
                r.extend_from_slice(body);
                r
            };
            return Some(vec![mk(&hs[..hk]), mk(&hs[hk..])]);
        }
    }
    Some(vec![buf[..k].to_vec(), buf[k..].to_vec()])
}

impl<S: AsyncRead + Unpin> AsyncRead for FragIo<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.started {
            this.started = true;
            if let Some(plan) = &this.plan {
                if let Some(c) = plan_chunks(plan, buf) {
                    this.chunks = c.into();
                    this.owed = buf.len();
                }
            }
        }
        if this.owed > 0 {
            loop {
                if let Some(d) = this.delay.as_mut() {
                    ready!(d.as_mut().poll(cx));
                    this.delay = None;
                }
                if this.cur_off >= this.cur.len() {
                    match this.chunks.pop_front() {
                        Some(c) => {
                            this.cur = c;
                            this.cur_off = 0;
                        }
                        None => break,
                    }
                }
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.cur[this.cur_off..]))?;
                this.cur_off += n;
                if this.cur_off >= this.cur.len() && !this.chunks.is_empty() {
                    if let Some(p) = &this.plan {
                        if !p.delay.is_zero() {
                            this.delay = Some(Box::pin(sleep(p.delay)));
                        }
                    }
                }
            }
            let n = this.owed;
            this.owed = 0;
            return Poll::Ready(Ok(n));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

const STAGE_TIMEOUT: Duration = Duration::from_secs(4);

pub type Tls = tokio_rustls::client::TlsStream<FragIo<TcpStream>>;
pub type Ws = WebSocketStream<Tls>;

pub struct WsDialer {
    profile: Shared,
    nat: Arc<NatTable>,
    /// cleared by the prober when Cloudflare DoH is unreachable (skips a 4 s timeout per dial)
    pub doh_ok: AtomicBool,
    cfg_sni: Arc<ClientConfig>,
    cfg_nosni: Arc<ClientConfig>,
    cache: Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
    /// static fallback gateway IPs, used when DNS is poisoned / null-routed
    pub overrides: Vec<IpAddr>,
}

pub fn mk_cfg(enable_sni: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut c = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.enable_sni = enable_sni;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}

impl WsDialer {
    pub fn new(profile: Shared, nat: Arc<NatTable>, overrides: Vec<IpAddr>) -> Self {
        Self {
            profile,
            nat,
            doh_ok: AtomicBool::new(true),
            cfg_sni: mk_cfg(true),
            cfg_nosni: mk_cfg(false),
            cache: Mutex::new(HashMap::new()),
            overrides,
        }
    }

    pub fn nat(&self) -> &Arc<NatTable> {
        &self.nat
    }

    pub async fn connect(&self, host: &str) -> Result<Ws> {
        let mut last = anyhow!("no addresses for {host}");
        for doh in [false, true] {
            if doh && !self.doh_ok.load(Ordering::Relaxed) && self.overrides.is_empty() {
                continue;
            }
            let ips = self.resolve(host, doh).await;
            for ip in ips.iter().take(4) {
                match self.connect_ip(host, *ip).await {
                    Ok(ws) => return Ok(ws),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// TCP, TLS and the WebSocket upgrade each get their own timeout, so a failure says which
    /// layer is blocked: TCP = the address is blackholed, TLS = SNI/handshake filtering.
    async fn connect_ip(&self, host: &str, ip: IpAddr) -> Result<Ws> {
        let p = self.profile.load_full();
        let (tcp, guard) = timeout(STAGE_TIMEOUT, connect_bypassed(&self.nat, SocketAddr::new(ip, 443)))
            .await
            .map_err(|_| anyhow!("{ip}: TCP connect timed out (address blocked?)"))?
            .map_err(|e| anyhow!("{ip}: TCP connect failed: {e}"))?;
        let plan = (p.ws_method == WsMethod::Fragment).then(|| Plan {
            split: p.ws_split,
            record_split: p.ws_record_split,
            delay: Duration::from_millis(p.ws_delay_ms),
        });
        let cfg = if p.ws_method == WsMethod::NoSni { &self.cfg_nosni } else { &self.cfg_sni };
        let hs = TlsConnector::from(cfg.clone())
            .connect(ServerName::try_from(host.to_string())?, FragIo::new(tcp, plan, Some(guard)));
        let tls = timeout(STAGE_TIMEOUT, hs)
            .await
            .map_err(|_| anyhow!("{ip}: TLS handshake timed out (ws_method={:?})", p.ws_method))?
            .map_err(|e| anyhow!("{ip}: TLS handshake failed: {e}"))?;
        let mut req = format!("wss://{host}/apiws").into_client_request()?;
        req.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
        req.headers_mut().insert("Origin", HeaderValue::from_static("https://web.telegram.org"));
        let (ws, _) = timeout(STAGE_TIMEOUT, tokio_tungstenite::client_async(req, tls))
            .await
            .map_err(|_| anyhow!("{ip}: WebSocket upgrade timed out"))?
            .map_err(|e| anyhow!("{ip}: WebSocket upgrade failed: {e}"))?;
        Ok(ws)
    }

    async fn resolve(&self, host: &str, use_doh: bool) -> Vec<IpAddr> {
        let key = format!("{host}|{use_doh}");
        if let Some((t, v)) = self.cache.lock().unwrap().get(&key) {
            if t.elapsed() < Duration::from_secs(120) {
                return v.clone();
            }
        }
        let mut v: Vec<IpAddr> = if use_doh {
            self.doh(host).await.unwrap_or_default()
        } else {
            match timeout(Duration::from_secs(3), tokio::net::lookup_host((host, 443))).await {
                Ok(Ok(it)) => it.map(|a| a.ip()).collect(),
                _ => vec![],
            }
        };
        // DNS poisoning / null-route detection
        v.retain(|ip| !ip.is_unspecified() && !ip.is_loopback());
        if use_doh {
            for ip in &self.overrides {
                if !v.contains(ip) {
                    v.push(*ip);
                }
            }
        }
        if !v.is_empty() {
            self.cache.lock().unwrap().insert(key, (Instant::now(), v.clone()));
        }
        v
    }

    /// DNS-over-HTTPS against Cloudflare's anycast 1.1.1.1 (IP-SAN certificate, no SNI sent).
    pub async fn doh(&self, host: &str) -> Result<Vec<IpAddr>> {
        let run = async {
            let tcp = TcpStream::connect(("1.1.1.1", 443)).await?;
            let sn = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)).into());
            let mut tls = TlsConnector::from(self.cfg_sni.clone()).connect(sn, FragIo::new(tcp, None, None)).await?;
            let req = format!(
                "GET /dns-query?name={host}&type=A HTTP/1.0\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-json\r\n\r\n"
            );
            tls.write_all(req.as_bytes()).await?;
            let mut body = Vec::new();
            let _ = tls.read_to_end(&mut body).await; // missing close_notify is fine
            let s = String::from_utf8_lossy(&body).to_string();
            let json = s.split("\r\n\r\n").nth(1).ok_or_else(|| anyhow!("bad DoH reply"))?;
            let v: serde_json::Value = serde_json::from_str(json)?;
            let mut out = vec![];
            if let Some(a) = v["Answer"].as_array() {
                for r in a {
                    if r["type"] == 1 {
                        if let Some(ip) = r["data"].as_str().and_then(|d| d.parse::<IpAddr>().ok()) {
                            out.push(ip);
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(out)
        };
        timeout(Duration::from_secs(4), run).await?
    }
}
