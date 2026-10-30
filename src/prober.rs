//! Engine C — autonomous strategy prober (self-healing loop).
//!
//! Grid over [split offset x fake TTL x BadSum] against real TLS endpoints, each candidate
//! swapped into the shared profile live. The prober's own ClientHellos are captured and
//! desynchronized by the packet engine exactly like normal traffic, so a successful handshake +
//! HTTP reply proves the strategy works on this ISP.
//!
//! Every swap also applies to the user's own connections, so the search is kept short: the
//! current profile is tried first and the first candidate that reaches every target wins. The
//! loop re-checks every 5 minutes and only searches again after two failed checks in a row.

pub mod profile;

use profile::{Profile, Shared, SplitAt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

/// YouTube front page and video redirector, plus the hosts the Discord app needs to get past
/// its splash screen (updater, API, gateway).
const HTTPS_TARGETS: &[&str] = &[
    "www.youtube.com",
    "redirector.googlevideo.com",
    "discord.com",
    "updates.discord.com",
    "gateway.discord.gg",
];
const HTTPS_TIMEOUT: Duration = Duration::from_millis(2500);
const RECHECK: Duration = Duration::from_secs(300);
const RETRY_AFTER_FAIL: Duration = Duration::from_secs(60);

fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut c = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}

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

/// Probe all targets concurrently -> (which succeeded, summed latency of the successes).
async fn probe_all(cfg: &Arc<ClientConfig>) -> (Vec<bool>, Duration) {
    let rs = futures_util::future::join_all(HTTPS_TARGETS.iter().map(|h| probe_https(h, cfg))).await;
    let total: Duration = rs.iter().flatten().sum();
    (rs.iter().map(Option::is_some).collect(), total)
}

fn failed_hosts(ok: &[bool]) -> String {
    HTTPS_TARGETS.iter().zip(ok).filter(|(_, ok)| !**ok).map(|(h, _)| *h).collect::<Vec<_>>().join(", ")
}

/// The current profile first, then [Split Offset x Fake TTL (3..12, plus "none") x BadSum],
/// cheapest / most common first.
fn candidates(base: &Profile) -> Vec<Profile> {
    let splits = [SplitAt::SniMid, SplitAt::SniStart(1), SplitAt::Fixed(1)];
    let ttls: [u8; 11] = [0, 6, 4, 8, 5, 7, 3, 9, 10, 11, 12];
    let mut out = vec![base.clone()];
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

/// Returns false only when nothing reached any target (a partial result is kept and re-checked
/// on the normal schedule).
async fn search(shared: &Shared, cfg: &Arc<ClientConfig>) -> bool {
    let need = HTTPS_TARGETS.len();
    let mut best: Option<(usize, Duration, Vec<bool>, Profile)> = None;
    for cand in candidates(&shared.load_full()) {
        shared.store(Arc::new(cand.clone()));
        let (oks, total) = probe_all(cfg).await;
        let ok = oks.iter().filter(|o| **o).count();
        if ok == 0 {
            continue;
        }
        let better = match &best {
            None => true,
            Some((bo, bt, _, _)) => ok > *bo || (ok == *bo && total < *bt),
        };
        if better {
            best = Some((ok, total, oks, cand));
        }
        if ok == need {
            break; // first fully working strategy wins: fewer live swaps under user traffic
        }
    }
    match best {
        Some((ok, total, oks, p)) => {
            info!("strategy: {ok}/{need} targets, {total:?} -> split={:?} ttl={} badsum={}", p.split, p.fake_ttl, p.bad_sum);
            if ok < need {
                warn!("still unreachable with the best strategy: {}", failed_hosts(&oks));
            }
            info!("locked profile: {p:?}");
            shared.store(Arc::new(p));
            true
        }
        None => {
            warn!("no strategy reached any target, keeping the current profile");
            false
        }
    }
}

pub async fn run(shared: Shared) {
    let cfg = tls_config();
    let mut need = true; // always search on startup
    let mut fails = 0u32;
    loop {
        if !need {
            let (oks, _) = probe_all(&cfg).await;
            fails = if oks.iter().all(|o| *o) { 0 } else { fails + 1 };
            // a single flaky probe must not trigger a search (it swaps live strategies)
            if fails >= 2 {
                warn!("health check failed twice ({}), re-probing", failed_hosts(&oks));
                need = true;
                fails = 0;
            }
        }
        if need {
            info!("probing strategies");
            need = !search(&shared, &cfg).await;
        }
        sleep(if need { RETRY_AFTER_FAIL } else { RECHECK }).await;
    }
}
