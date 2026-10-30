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
//! The winner is stored into the shared ArcSwap profile. The two stages are re-checked
//! independently every 5 minutes: stage 1 re-runs only after two failed YouTube/Discord checks
//! in a row, stage 2 re-runs when Engine B reports repeated gateway failures and backs off
//! (up to 15 minutes) while the gateways stay unreachable, so a blocked Telegram never makes
//! the prober churn the packet strategy under live traffic.

pub mod profile;

use crate::tg_bridge::dialer::{mk_cfg, WsDialer};
use crate::tg_bridge::Ctx;
use profile::{Profile, Shared, SplitAt, WsMethod};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
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
const WS_BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

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

/// Stage 1: packet-level strategy for Engine A. Returns false only when nothing reached any
/// target (a partial result is kept and re-checked on the normal schedule).
async fn search_packet(shared: &Shared, cfg: &Arc<ClientConfig>) -> bool {
    let mut base: Profile = (*shared.load_full()).clone();
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
    let found = best.is_some();
    match best {
        Some((ok, total, p)) => {
            info!("stage 1: {ok}/{need} targets, {total:?} total -> split={:?} ttl={} badsum={}", p.split, p.fake_ttl, p.bad_sum);
            base = p;
        }
        None => warn!("stage 1: no packet-level strategy reached any target"),
    }
    shared.store(Arc::new(base.clone()));
    info!("locked profile: {base:?}");
    found
}

/// Stage 2: WebSocket dialer strategy for Engine B. Only touches the ws_* fields, so it never
/// disturbs YouTube / Discord traffic while it runs.
async fn search_ws(shared: &Shared, dialer: &WsDialer) -> bool {
    let base: Profile = (*shared.load_full()).clone();
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
    // keep whatever stage 1 may have stored meanwhile; only the ws_* fields are ours
    let mut cur: Profile = (*shared.load_full()).clone();
    let src = best_ws.as_ref().map(|(_, p)| p).unwrap_or(&base);
    cur.ws_method = src.ws_method;
    cur.ws_split = src.ws_split;
    cur.ws_record_split = src.ws_record_split;
    shared.store(Arc::new(cur));
    match best_ws {
        Some((t, p)) => {
            info!("stage 2: {WS_TARGET} in {t:?} -> ws_method={:?} split={:?} record_split={}", p.ws_method, p.ws_split, p.ws_record_split);
            true
        }
        None => {
            warn!("stage 2: no WebSocket strategy reached {WS_TARGET}");
            false
        }
    }
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
    // always search on startup
    let mut need_packet = engine_a;
    let mut need_ws = true;
    let mut packet_fails = 0u32;
    let mut ws_backoff = RETRY_AFTER_FAIL;
    loop {
        let cf = probe_cloudflare(&dialer).await;
        if cf != dialer.doh_ok.swap(cf, Ordering::Relaxed) {
            info!("Cloudflare DoH {}", if cf { "reachable" } else { "unreachable, DoH fallback disabled" });
        }

        // Engine A: a single flaky probe must not trigger a full re-search (it swaps live
        // strategies under the user's traffic), so require two failed checks in a row.
        if engine_a && !need_packet {
            let (ok, _) = probe_all(&cfg).await;
            packet_fails = if ok < HTTPS_TARGETS.len() { packet_fails + 1 } else { 0 };
            if packet_fails >= 2 {
                warn!("YouTube/Discord health check failed twice ({ok}/{}), re-probing", HTTPS_TARGETS.len());
                need_packet = true;
                packet_fails = 0;
            }
        }
        if need_packet {
            info!("engine C: probing packet strategies");
            need_packet = !search_packet(&shared, &cfg).await;
        }

        // Engine B: independent of Engine A; backs off while the gateways stay unreachable.
        if !need_ws && probe_ws(&dialer).await.is_none() {
            warn!("Telegram gateway health check failed, re-probing WebSocket strategies");
            need_ws = true;
        }
        if need_ws {
            if search_ws(&shared, &dialer).await {
                need_ws = false;
                ws_backoff = RETRY_AFTER_FAIL;
            } else {
                warn!(
                    "Telegram gateways unreachable with every strategy (address-level block?); next try in {ws_backoff:?}"
                );
            }
        }
        probe_gateways(&ctx).await;

        let wait = if need_packet {
            RETRY_AFTER_FAIL
        } else if need_ws {
            let w = ws_backoff;
            ws_backoff = (ws_backoff * 2).min(WS_BACKOFF_MAX);
            w
        } else {
            RECHECK
        };
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            tokio::select! {
                _ = trigger.notified() => {
                    // Engine B reports failing gateways: worth an early look only if we
                    // currently believe they work (otherwise we are already backing off).
                    if !need_ws {
                        need_ws = true;
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
    }
}
