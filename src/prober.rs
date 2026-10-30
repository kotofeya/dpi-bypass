//! Engine C — autonomous strategy prober (self-healing loop).
//!
//! Each candidate strategy is swapped into the shared profile live, then every target gets a
//! raw TLS ClientHello the size of a modern Chromium one (post-quantum key share, ~1.8 KB, so
//! it spans two TCP segments exactly like the Discord app's and the browser's), with the SNI in
//! the second segment, the worst case Chromium's extension shuffling produces. The prober's
//! own packets go through the packet engine like normal traffic; a ServerHello coming back
//! proves the DPI let the handshake through.
//!
//! Every swap also applies to the user's own connections, so the search is kept short: the
//! current profile is tried first and the first candidate that reaches every target wins. The
//! loop re-checks every 5 minutes and only searches again after two failed checks in a row.

pub mod profile;

use crate::windivert_engine::tls;
use profile::{Fooling, Method, Profile, Shared, SplitAt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

/// YouTube front page and video redirector, plus the hosts the Discord app needs to get past
/// its splash screen (updater, API, gateway).
const HTTPS_TARGETS: &[&str] = &[
    "www.youtube.com",
    "redirector.googlevideo.com",
    "discord.com",
    "updates.discord.com",
    "gateway.discord.gg",
];
/// Chromium's ClientHello with X25519MLKEM768 is ~1.7-1.9 KB: larger than one segment.
const PROBE_HELLO_LEN: usize = 1780;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const RECHECK: Duration = Duration::from_secs(300);
const RETRY_AFTER_FAIL: Duration = Duration::from_secs(60);

/// Sends a Chromium-sized ClientHello and waits for the ServerHello (or HelloRetryRequest).
/// Returns the latency on success.
async fn probe_tls(host: &str) -> Option<Duration> {
    let t0 = Instant::now();
    let run = async {
        let addr = tokio::net::lookup_host((host, 443)).await.ok()?.find(|a| a.is_ipv4())?;
        let mut tcp = TcpStream::connect(addr).await.ok()?;
        tcp.set_nodelay(true).ok()?;
        tcp.write_all(&tls::build_probe_client_hello(host, PROBE_HELLO_LEN)).await.ok()?;
        // record header (5) + handshake type (1)
        let mut b = [0u8; 6];
        tcp.read_exact(&mut b).await.ok()?;
        (b[0] == 0x16 && b[5] == 0x02).then_some(())
    };
    match timeout(PROBE_TIMEOUT, run).await {
        Ok(Some(())) => Some(t0.elapsed()),
        _ => None,
    }
}

/// Probe all targets concurrently -> (which succeeded, summed latency of the successes).
async fn probe_all() -> (Vec<bool>, Duration) {
    let rs = futures_util::future::join_all(HTTPS_TARGETS.iter().map(|h| probe_tls(h))).await;
    let total: Duration = rs.iter().flatten().sum();
    (rs.iter().map(Option::is_some).collect(), total)
}

fn failed_hosts(ok: &[bool]) -> String {
    HTTPS_TARGETS.iter().zip(ok).filter(|(_, ok)| !**ok).map(|(h, _)| *h).collect::<Vec<_>>().join(", ")
}

fn describe(p: &Profile) -> String {
    match p.method {
        Method::SeqOvl => "seqovl".into(),
        Method::Fake => format!("fake x{} {:?}", p.fake_count, p.fooling),
        Method::FakeSplit => format!(
            "fake x{} {:?} + split {:?}{}",
            p.fake_count,
            p.fooling,
            p.split,
            if p.disorder { " disorder" } else { "" }
        ),
    }
}

/// The current profile first, then the strategies zapret-discord-youtube ships, most commonly
/// working first: seqovl, plain fakes, fakes + disorder split; fakes fooled by bad sequence
/// numbers, TTL (4..8) or bad checksum.
fn candidates(base: &Profile) -> Vec<Profile> {
    let foolings = [
        Fooling::BadSeq,
        Fooling::Ttl(6),
        Fooling::Ttl(4),
        Fooling::Ttl(8),
        Fooling::Ttl(5),
        Fooling::Ttl(7),
        Fooling::BadSum,
    ];
    let mut out = vec![base.clone()];
    let mut seqovl = base.clone();
    seqovl.method = Method::SeqOvl;
    out.push(seqovl);
    for (method, split) in [(Method::Fake, SplitAt::SniMid), (Method::FakeSplit, SplitAt::SniMid), (Method::FakeSplit, SplitAt::Fixed(1))] {
        for &fooling in &foolings {
            let mut p = base.clone();
            p.method = method;
            p.split = split;
            p.disorder = true;
            p.fooling = fooling;
            p.fake_count = if fooling == Fooling::BadSeq { 11 } else { 6 };
            out.push(p);
        }
    }
    out
}

/// Returns false only when nothing reached any target (a partial result is kept and re-checked
/// on the normal schedule).
async fn search(shared: &Shared) -> bool {
    let need = HTTPS_TARGETS.len();
    let mut best: Option<(usize, Duration, Vec<bool>, Profile)> = None;
    for cand in candidates(&shared.load_full()) {
        shared.store(Arc::new(cand.clone()));
        let (oks, total) = probe_all().await;
        let ok = oks.iter().filter(|o| **o).count();
        debug!("candidate {}: {ok}/{need}", describe(&cand));
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
            info!("strategy: {ok}/{need} targets, {total:?} -> {}", describe(&p));
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
    let mut need = true; // always search on startup
    let mut fails = 0u32;
    loop {
        if !need {
            let (oks, _) = probe_all().await;
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
            need = !search(&shared).await;
        }
        sleep(if need { RETRY_AFTER_FAIL } else { RECHECK }).await;
    }
}
