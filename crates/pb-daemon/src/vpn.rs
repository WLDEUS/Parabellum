//! Glue between the daemon and [`pb_vpn::VpnService`]: hooks (status push, alerts, sing-box install,
//! trusted-network persistence) and the IPC handlers.

use crate::actions;
use crate::ctx::Ctx;
use crate::store::AlertKey;
use async_trait::async_trait;
use pb_core::ipc::{DaemonEvent, ErrorCode, IpcError};
use pb_core::model::*;
use pb_vpn::{NetAlert, VpnError, VpnHooks, VpnService};
use std::path::PathBuf;
use std::sync::{Arc, Weak};

/// Component name of sing-box in the component manager.
pub const SINGBOX_COMPONENT: &str = "sing-box";

/// Map a VPN error onto an IPC error.
pub fn err(e: VpnError) -> IpcError {
    {
        match e {
            VpnError::Invalid(m) => IpcError::new(ErrorCode::BadRequest, m),
            VpnError::Unavailable(m) => IpcError::new(ErrorCode::Unavailable, m),
            VpnError::NotFound(m) => IpcError::new(ErrorCode::NotFound, m),
            VpnError::Failed(m) => IpcError::new(ErrorCode::Internal, m),
        }
    }
}

/// Hooks given to the VPN service (weak reference: the context owns the service).
pub struct DaemonVpnHooks {
    ctx: Weak<Ctx>,
}

impl DaemonVpnHooks {
    pub fn new(ctx: &Arc<Ctx>) -> Arc<Self> {
        Arc::new(Self {
            ctx: Arc::downgrade(ctx),
        })
    }
}

/// Store a network alert (kind `network`), deduplicated on its key for 24 h.
pub async fn raise_net_alert(ctx: &Arc<Ctx>, a: NetAlert) {
    let key = format!("vpn:{}", a.key);
    let since = pb_core::now_ts() - 86_400;
    let k2 = key.clone();
    let recent = ctx
        .store
        .run(move |s| s.find_recent_alert_by(AlertKind::Network, AlertKey::Title(&k2), since))
        .await
        .ok()
        .flatten();
    if recent.is_some() {
        return;
    }
    let mut alert = actions::alert(AlertKind::Network, a.severity, a.title, a.message);
    alert.network_id = a.network_id.clone();
    if a.offer_trust && a.network_id.is_some() {
        alert.actions = vec![AlertAction::TrustNetwork, AlertAction::Acknowledge];
    }
    actions::raise_alert(ctx, alert, Some(key)).await;
}

#[async_trait]
impl VpnHooks for DaemonVpnHooks {
    fn status_changed(&self, status: &VpnStatus) {
        if let Some(ctx) = self.ctx.upgrade() {
            ctx.bus.publish(DaemonEvent::Vpn(status.clone()));
            ctx.status_dirty.notify_one();
        }
    }

    fn alert(&self, alert: NetAlert) {
        if let Some(ctx) = self.ctx.upgrade() {
            tokio::spawn(async move { raise_net_alert(&ctx, alert).await });
        }
    }

    async fn ensure_singbox(&self) -> Result<PathBuf, VpnError> {
        let ctx = self
            .ctx
            .upgrade()
            .ok_or_else(|| VpnError::Unavailable("arrêt en cours".into()))?;
        let bin = pb_updater::singbox_binary(&ctx.paths);
        if bin.is_file() {
            return Ok(bin);
        }
        let cfg = ctx.config();
        let st = ctx
            .backends
            .updater
            .install_component(SINGBOX_COMPONENT, &cfg)
            .await
            .map_err(|e| {
                VpnError::Unavailable(format!("installation de sing-box impossible : {e}"))
            })?;
        ctx.bus.publish(DaemonEvent::Component(st));
        if bin.is_file() {
            Ok(bin)
        } else {
            Err(VpnError::Unavailable(
                "sing-box absent : il arrive avec la prochaine base de menaces signée".into(),
            ))
        }
    }

    async fn save_trusted_networks(&self, ids: Vec<String>) -> Result<(), VpnError> {
        let ctx = self
            .ctx
            .upgrade()
            .ok_or_else(|| VpnError::Unavailable("arrêt en cours".into()))?;
        let mut cfg = (*ctx.config()).clone();
        cfg.vpn.trusted_networks = ids;
        cfg.validate()
            .map_err(|e| VpnError::Invalid(e.to_string()))?;
        crate::setup::save_config(&ctx.paths, &cfg).map_err(|e| VpnError::Failed(e.to_string()))?;
        ctx.publish_config(cfg);
        Ok(())
    }
}

/// The running service (`Unavailable` before startup completed / in tests without it).
pub fn service(ctx: &Ctx) -> Result<Arc<VpnService>, IpcError> {
    ctx.vpn
        .get()
        .cloned()
        .ok_or_else(|| IpcError::new(ErrorCode::Unavailable, "service VPN non démarré"))
}

/// Start the service: crash recovery then the main loop. Returns its task.
pub async fn start(ctx: &Arc<Ctx>) -> tokio::task::JoinHandle<()> {
    let svc = VpnService::new(ctx.paths.clone(), DaemonVpnHooks::new(ctx));
    let _ = ctx.vpn.set(svc.clone());
    svc.recover_on_startup().await;
    tokio::spawn(svc.run(ctx.config_rx(), ctx.shutdown_rx()))
}

/// `set_network_trust` and the alert action.
pub async fn set_network_trust(
    ctx: &Arc<Ctx>,
    id: &str,
    trusted: bool,
) -> Result<NetworkInfo, IpcError> {
    if !pb_core::config::is_network_id(id) {
        return Err(IpcError::new(
            ErrorCode::BadRequest,
            format!("identifiant de réseau invalide : {id}"),
        ));
    }
    service(ctx)?
        .set_network_trust(id, trusted)
        .await
        .map_err(err)
}
