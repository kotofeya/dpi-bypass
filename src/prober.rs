//! Engine C — autonomous strategy prober (self-healing loop).
//!
//! Besides the strategy search below it keeps two health signals fresh for Engine B:
//! Cloudflare DoH reachability (lets the dialer skip a dead DoH fallback) and the latency /
//! failure state of every kws{1..5} WebSocket gateway (orders gateway candidates per DC).
//!
//! Two stages, each probing with the candidate profile swapped in live:
//!   1. (only when Engine A is running) grid over [split offset x fake TTL x BadSum] against
//!      real TLS endpoints. The prober's own ClientHellos are captured and desynchronized by
//!      Engine A exactly like normal traffic, so a successful handshake + HTTP reply proves
//!      the strategy works on this ISP. Best = most targets reachable, then lowest latency.
//!   2. grid over [WS method x split x record-split] against kws2.web.telegram.org with the
//!      stage-1 winner already locked; best = lowest WebSocket handshake latency.
//!
//! The winner is stored into the shared ArcSwap profile. The loop re-checks health every
//! 5 minutes and immediately when Engine B reports repeated gateway failures.

pub mod profile;

use crate::tg_bridge::dialer::{mk_cfg, WsDialer};
use crate::tg_bridge::Ctx;
use profile::{Profile, Shared, SplitAt, WsMethod};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

/// youtube front page, a real googlevideo.com host, Discord. (rr1---sn-*.googlevideo.com names
/// are per-user; redirector.googlevideo.com sits behind the same SNI rules.)
const HTTPS_TARGETS: &[&str] = &["www.youtube.com", "redirector.googlevideo.com", "discord.com"];
const WS_TARGET: &str = "kws2.web.telegram.org";
const HTTPS_TIMEOUT: Duration = Duration::from_millis(2500);
const WS_TIMEOUT: Duration = Duration::from_secs(5);
const RECHECK: Duration = Duration::from_secs(300);
const RETRY_AFTER_FAIL: Duration = Duration::from_secs(60);

/// TLS handshake + first bytes of an HTTP response. Returns total latency on success.
async fn probe_https(host: &str, cfg: &Arc<ClientConfig>) -> Option<Duration> {
    let t0 = Instant::now();
    let run = async {
        let addr = tokio::net::lookup_host((host, 443)).await.ok()?.find(|a| a.is_ipv4())?;
        let tcp = TcpStream::connect(addr).await.ok()?;
        tcp.set_nodelay(true).ok()?;
        let sn = ServerName::try_from(host.to_string()).ok()?;
        let mut tls = TlsConnector::from(cfg.clone()).connect(sn, tcp).await.ok()?;
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.ok()?;
        let mut b = [0u8; 8];
        let mut got = 0usize;
        while got < 5 {
            let n = tls.read(&mut b[got..]).await.ok()?;
            if n == 0 {
                break;
            }
            got += n;
        }
        (got >= 5 && &b[..5] == b"HTTP/").then_some(())
    };
    match timeout(HTTPS_TIMEOUT, run).await {
        Ok(Some(())) => Some(t0.elapsed()),
        _ => None,
    }
}

/// Probe all HTTPS targets concurrently -> (how many succeeded, summed latency of the successes).
async fn probe_all(cfg: &Arc<ClientConfig>) -> (usize, Duration) {
    let rs = futures_util::future::join_all(HTTPS_TARGETS.iter().map(|h| probe_https(h, cfg))).await;
    let ok = rs.iter().flatten().count();
    let total: Duration = rs.iter().flatten().sum();
    (ok, total)
}

async fn probe_ws(d: &WsDialer) -> Option<Duration> {
    let t0 = Instant::now();
    match timeout(WS_TIMEOUT, d.connect(WS_TARGET)).await {
        Ok(Ok(_ws)) => Some(t0.elapsed()),
        _ => None,
    }
}

/// [Split Offset x Fake TTL (3..12, plus "none") x BadSum]; cheapest / most common first.
fn stage1(base: &Profile) -> Vec<Profile> {
    let splits = [SplitAt::SniMid, SplitAt::SniStart(1), SplitAt::Fixed(1)];
    let ttls: [u8; 11] = [0, 6, 4, 8, 5, 7, 3, 9, 10, 11, 12];
    let mut out = Vec::new();
    for &ttl in &ttls {
        for &bad in &[false, true] {
            for &split in &splits {
                let mut p = base.clone();
                p.split = split;
                p.disorder = true;
                p.fake_ttl = ttl;
                p.bad_sum = bad;
                p.fake_count = if ttl == 0 && !bad { 0 } else { 1 };
                out.push(p);
            }
        }
    }
    out
}

/// [WSMethod x split x TLS-record-split] for Engine B's dialer.
fn stage2(base: &Profile) -> Vec<Profile> {
    let mut out = Vec::new();
    for m in [WsMethod::Plain, WsMethod::NoSni] {
        let mut p = base.clone();
        p.ws_method = m;
        out.push(p);
    }
    for &rec in &[true, false] {
        for &sp in &[SplitAt::SniMid, SplitAt::SniStart(1), SplitAt::Fixed(1)] {
            let mut p = base.clone();
            p.ws_method = WsMethod::Fragment;
            p.ws_split = sp;
            p.ws_record_split = rec;
            out.push(p);
        }
    }
    out
}

async fn healthy(cfg: &Arc<ClientConfig>, dialer: &WsDialer, engine_a: bool) -> bool {
    if engine_a {
        let (ok, _) = probe_all(cfg).await;
        if ok < HTTPS_TARGETS.len() {
            return false;
        }
    }
    probe_ws(dialer).await.is_some()
}

/// Full search. Returns true when every available engine ended up with a working strategy.
async fn search(shared: &Shared, cfg: &Arc<ClientConfig>, dialer: &WsDialer, engine_a: bool) -> bool {
    let mut base: Profile = (*shared.load_full()).clone();
    let mut a_ok = !engine_a;

    if engine_a {
        let need = HTTPS_TARGETS.len();
        let mut best: Option<(usize, Duration, Profile)> = None;
        let mut full = 0usize;
        for cand in stage1(&base) {
            shared.store(Arc::new(cand.clone()));
            let (ok, total) = probe_all(cfg).await;
            if ok == 0 {
                continue;
            }
            let better = match &best {
                None => true,
                Some((bo, bt, _)) => ok > *bo || (ok == *bo && total < *bt),
            };
            if better {
                best = Some((ok, total, cand));
            }
            if ok == need {
                full += 1;
                if full >= 4 {
                    break; // enough full-success candidates; the best of them wins
                }
            }
        }
        match best {
            Some((ok, total, p)) => {
                info!("stage 1: {ok}/{need} targets, {total:?} total -> split={:?} ttl={} badsum={}", p.split, p.fake_ttl, p.bad_sum);
                a_ok = ok == need;
                base = p;
            }
            None => warn!("stage 1: no packet-level strategy reached any target"),
        }
        shared.store(Arc::new(base.clone()));
    }

    let _ = probe_ws(dialer).await; // warm DNS cache so the first candidate isn't penalised
    let mut best_ws: Option<(Duration, Profile)> = None;
    for cand in stage2(&base) {
        shared.store(Arc::new(cand.clone()));
        if let Some(t) = probe_ws(dialer).await {
            if best_ws.as_ref().map_or(true, |(b, _)| t < *b) {
                best_ws = Some((t, cand));
            }
        }
    }
    let ws_ok = best_ws.is_some();
    match best_ws {
        Some((t, p)) => {
            info!("stage 2: {WS_TARGET} in {t:?} -> ws_method={:?} split={:?} record_split={}", p.ws_method, p.ws_split, p.ws_record_split);
            base = p;
        }
        None => warn!("stage 2: no WebSocket strategy reached {WS_TARGET}"),
    }
    shared.store(Arc::new(base.clone()));
    info!("locked profile: {base:?}");
    a_ok && ws_ok
}

/// Cloudflare DoH (1.1.1.1) answers for a Telegram gateway name.
async fn probe_cloudflare(d: &WsDialer) -> bool {
    matches!(timeout(Duration::from_secs(5), d.doh(WS_TARGET)).await, Ok(Ok(v)) if !v.is_empty())
}

/// Handshake latency of every DC's primary gateway, recorded into the bridge's health table.
async fn probe_gateways(ctx: &Ctx) {
    let hosts: Vec<String> = (1..=5).map(|dc| format!("kws{dc}.web.telegram.org")).collect();
    let rs = futures_util::future::join_all(hosts.iter().map(|h| async move {
        let t0 = Instant::now();
        let ok = matches!(timeout(WS_TIMEOUT, ctx.dialer.connect(h)).await, Ok(Ok(_)));
        (h, ok, t0.elapsed())
    }))
    .await;
    for (h, ok, t) in rs {
        if ok {
            ctx.gateways.record_ok(h, t);
        } else {
            ctx.gateways.record_fail(h);
        }
    }
    info!("gateways: {}", ctx.gateways.summary());
}

pub async fn run(shared: Shared, ctx: Arc<Ctx>, engine_a: bool) {
    let cfg = mk_cfg(true);
    let dialer = ctx.dialer.clone();
    let trigger = ctx.probe.clone();
    let mut need = true; // always search on startup
    loop {
        let cf = probe_cloudflare(&dialer).await;
        if cf != dialer.doh_ok.swap(cf, Ordering::Relaxed) {
            info!("Cloudflare DoH {}", if cf { "reachable" } else { "unreachable, DoH fallback disabled" });
        }
        if !need {
            need = !healthy(&cfg, &dialer, engine_a).await;
            if need {
                warn!("health check failed, re-probing");
            }
        }
        let mut wait = RECHECK;
        if need {
            info!("engine C: probing strategies");
            if search(&shared, &cfg, &dialer, engine_a).await {
                need = false;
            } else {
                warn!("engine C: no fully working profile, retrying in {RETRY_AFTER_FAIL:?}");
                wait = RETRY_AFTER_FAIL;
            }
        }
        probe_gateways(&ctx).await;
        tokio::select! {
            _ = trigger.notified() => {}
            _ = sleep(wait) => {}
        }
    }
}
