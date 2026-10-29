//! Glue between the daemon and [`pb_privacy::PrivacyService`]: alert hook and service access.

use crate::actions;
use crate::ctx::Ctx;
use crate::store::AlertKey;
use async_trait::async_trait;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use pb_privacy::{PrivacyAlert, PrivacyError, PrivacyHooks, PrivacyService};
use std::sync::{Arc, Weak};

/// Map a privacy error onto an IPC error.
pub fn err(e: PrivacyError) -> IpcError {
    {
        match e {
            PrivacyError::Invalid(m) => IpcError::new(ErrorCode::BadRequest, m),
            PrivacyError::Unavailable(m) => IpcError::new(ErrorCode::Unavailable, m),
            PrivacyError::NotFound(m) => IpcError::new(ErrorCode::NotFound, m),
            PrivacyError::Failed(m) => IpcError::new(ErrorCode::Internal, m),
        }
    }
}

pub struct DaemonPrivacyHooks {
    ctx: Weak<Ctx>,
}

impl DaemonPrivacyHooks {
    pub fn new(ctx: &Arc<Ctx>) -> Arc<Self> {
        Arc::new(Self {
            ctx: Arc::downgrade(ctx),
        })
    }
}

async fn raise(ctx: &Arc<Ctx>, a: PrivacyAlert) {
    let key = format!("privacy:{}", a.key);
    let since = pb_core::now_ts() - 86_400;
    let k2 = key.clone();
    let recent = ctx
        .store
        .run(move |s| s.find_recent_alert_by(AlertKind::Privacy, AlertKey::Title(&k2), since))
        .await
        .ok()
        .flatten();
    if recent.is_some() {
        return;
    }
    let alert = actions::alert(AlertKind::Privacy, a.severity, a.title, a.message);
    actions::raise_alert(ctx, alert, Some(key)).await;
}

#[async_trait]
impl PrivacyHooks for DaemonPrivacyHooks {
    fn alert(&self, alert: PrivacyAlert) {
        if let Some(ctx) = self.ctx.upgrade() {
            tokio::spawn(async move { raise(&ctx, alert).await });
        }
    }
}

pub fn service(ctx: &Ctx) -> Result<Arc<PrivacyService>, IpcError> {
    ctx.privacy
        .get()
        .cloned()
        .ok_or_else(|| IpcError::new(ErrorCode::Unavailable, "service vie privée non démarré"))
}

pub fn start(ctx: &Arc<Ctx>) -> tokio::task::JoinHandle<()> {
    let svc = PrivacyService::new(ctx.paths.clone(), DaemonPrivacyHooks::new(ctx));
    let _ = ctx.privacy.set(svc.clone());
    tokio::spawn(svc.run(ctx.config_rx(), ctx.shutdown_rx()))
}
