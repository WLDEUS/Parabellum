//! First-run baselines: on the very first run, persistence items and devices that already exist are
//! recorded silently (`baseline`), so the user is not flooded with alerts about their own Mac.
//!
//! The window opens at startup when the kv flag is absent and closes after [`QUIET`] without events
//! (or [`MAX`] after startup); the flag is then written so later runs alert normally.

use crate::ctx::Ctx;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Window closes after this much quiet…
pub const QUIET: Duration = Duration::from_secs(120);
/// …or this long after startup.
pub const MAX: Duration = Duration::from_secs(600);

/// Which baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Persistence,
    Devices,
}

impl Kind {
    /// kv flag set once the baseline is complete.
    pub fn kv_key(self) -> &'static str {
        match self {
            Kind::Persistence => "persistence_baseline_done",
            Kind::Devices => "devices_baseline_done",
        }
    }

    fn slot(self, st: &mut crate::ctx::RuntimeState) -> &mut Option<Instant> {
        match self {
            Kind::Persistence => &mut st.persistence_baseline_until,
            Kind::Devices => &mut st.devices_baseline_until,
        }
    }
}

/// Open the window if this baseline was never completed.
pub async fn init(ctx: &Arc<Ctx>, kind: Kind) {
    let done = ctx
        .store
        .run(move |s| s.kv_get(kind.kv_key()))
        .await
        .ok()
        .flatten()
        .is_some();
    if done {
        return;
    }
    tracing::info!(?kind, "first run: existing items become the baseline");
    *kind.slot(&mut ctx.state()) = Some(Instant::now() + MAX);
    let ctx = ctx.clone();
    tokio::spawn(async move { close_when_due(ctx, kind).await });
}

async fn close_when_due(ctx: Arc<Ctx>, kind: Kind) {
    loop {
        let until = *kind.slot(&mut ctx.state());
        let Some(until) = until else { return };
        if Instant::now() >= until {
            *kind.slot(&mut ctx.state()) = None;
            let now = pb_core::now_ts().to_string();
            if let Err(e) = ctx.store.run(move |s| s.kv_set(kind.kv_key(), &now)).await {
                tracing::warn!(error = %e, "cannot store baseline flag");
            }
            tracing::info!(?kind, "baseline complete");
            return;
        }
        let wake = until.min(Instant::now() + Duration::from_secs(15));
        tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
    }
}

/// In the window: extend it by the quiet period (capped) and return true.
pub fn in_window(ctx: &Ctx, kind: Kind) -> bool {
    let mut st = ctx.state();
    let slot = kind.slot(&mut st);
    match *slot {
        Some(until) if Instant::now() < until => {
            // The first event shrinks the initial window to the quiet period; later ones extend it.
            *slot = Some((Instant::now() + QUIET).min(ctx.started + MAX));
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::Backends;
    use crate::store::Store;
    use pb_core::config::Config;
    use pb_core::paths::Paths;

    #[tokio::test]
    async fn window_opens_only_on_first_run() {
        let ctx = Arc::new(Ctx::new(
            Paths::with_root("/tmp/pbb"),
            true,
            Store::open_in_memory().unwrap(),
            Backends::unavailable(),
            Config::default(),
        ));
        init(&ctx, Kind::Devices).await;
        assert!(in_window(&ctx, Kind::Devices));
        assert!(!in_window(&ctx, Kind::Persistence));
        ctx.store.kv_set(Kind::Persistence.kv_key(), "1").unwrap();
        init(&ctx, Kind::Persistence).await;
        assert!(!in_window(&ctx, Kind::Persistence));
        // Force-close: past deadline.
        ctx.state().devices_baseline_until = Some(Instant::now());
        assert!(!in_window(&ctx, Kind::Devices));
    }
}
