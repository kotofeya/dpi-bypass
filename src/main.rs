mod dialer;
mod divert;
mod engine_a;
mod engine_c;
mod profile;
mod quic;
mod telegram;
mod tls;

use anyhow::Result;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    ).init();

    let shared = profile::shared_default();

    // Engine A (needs Administrator; Engine B still works without it)
    let dv = match divert::Divert::open(engine_a::FILTER, 0) {
        Ok(d) => Some(Arc::new(d)),
        Err(e) => {
            tracing::error!("Engine A disabled: {e:#}");
            None
        }
    };
    let a_thread = dv.as_ref().map(|d| {
        let (d, p) = (d.clone(), shared.clone());
        std::thread::spawn(move || engine_a::run(d, p))
    });

    // Engine B
    let secret = telegram::load_secret();
    let dialer = Arc::new(dialer::WsDialer::new(shared.clone(), vec![]));
    let ctx = Arc::new(telegram::Ctx::new(dialer, secret));
    tokio::spawn(telegram::serve_socks(ctx.clone()));
    tokio::spawn(telegram::serve_mtproxy(ctx.clone()));
    tracing::info!("Telegram: use SOCKS5 127.0.0.1:1080  or open  {}", telegram::proxy_link(&secret));

    // Engine C: probes strategies on startup, then re-probes on health-check failure or when
    // Engine B signals repeated gateway failures.
    tokio::spawn(engine_c::run(shared.clone(), ctx.dialer.clone(), ctx.probe.clone(), dv.is_some()));

    tokio::signal::ctrl_c().await?;
    if let Some(d) = &dv {
        d.close();
    }
    if let Some(t) = a_thread {
        let _ = t.join();
    }
    Ok(())
}
