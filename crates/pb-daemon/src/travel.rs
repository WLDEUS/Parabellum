//! Travel mode ("Mode Voyage"): one-click hardening for public Wi-Fi, and one click back.
//!
//! Enabling records the current state of every setting it touches ([`Settings`]) in
//! `state/travel.json` (root-only, written before anything changes, so a crash or a reboot never loses it),
//! then sets: VPN mode `always` + kill switch (only when a VPN is configured, otherwise the kill switch would
//! cut the Mac off), DNS blocking, macOS application firewall on + stealth mode (+ block all incoming when
//! `travel.block_all_incoming`). Disabling puts back only what travel mode changed: a setting you modified
//! meanwhile keeps your value ([`plan_restore`]).
//!
//! AirDrop and Bluetooth are per-user / hardware settings: the app applies them as the user when it sees
//! `StatusInfo::travel_active` change (see `TravelStore.swift`).
//!
//! The state machine ([`Travel`]) only talks to a [`TravelBackend`]: the daemon's ([`DaemonBackend`]: config,
//! DNS supervisor, pb-vpn, `socketfilterfw`) or fakes in tests.

use crate::ctx::Ctx;
use async_trait::async_trait;
use pb_core::config::{Config, TravelConfig, VpnBackend, VpnMode};
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

/// Snapshot file in the state directory.
pub const STATE_FILE: &str = "travel.json";
/// `socketfilterfw` (application firewall control, root).
pub const SOCKETFILTERFW: &str = crate::posture::SOCKETFILTERFW;
const FW_TIMEOUT: Duration = Duration::from_secs(10);
/// A suggestion alert is raised at most once per network in this window.
pub const SUGGEST_DEDUPE_SECS: i64 = 86_400;

// ---------------------------------------------------------------------------------------------
// Settings & pure planning
// ---------------------------------------------------------------------------------------------

/// The settings travel mode touches. Firewall values are `None` when they could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub vpn_mode: VpnMode,
    pub kill_switch: bool,
    pub dns: bool,
    pub firewall: Option<bool>,
    pub stealth: Option<bool>,
    pub block_all: Option<bool>,
}

/// One setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    VpnMode,
    KillSwitch,
    Dns,
    Firewall,
    Stealth,
    BlockAll,
}

/// Value of one setting (for generic comparisons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Mode(VpnMode),
    Flag(Option<bool>),
}

impl Field {
    pub const ALL: [Field; 6] = [
        Field::VpnMode,
        Field::KillSwitch,
        Field::Dns,
        Field::Firewall,
        Field::Stealth,
        Field::BlockAll,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Field::VpnMode => "vpn_mode",
            Field::KillSwitch => "kill_switch",
            Field::Dns => "dns",
            Field::Firewall => "firewall",
            Field::Stealth => "stealth",
            Field::BlockAll => "block_all",
        }
    }

    /// French label of the travel value.
    pub fn label(self) -> &'static str {
        match self {
            Field::VpnMode => "VPN toujours actif",
            Field::KillSwitch => "Coupe-circuit VPN",
            Field::Dns => "Blocage DNS (pubs, pistage, sites malveillants)",
            Field::Firewall => "Coupe-feu de macOS activé",
            Field::Stealth => "Mode furtif du coupe-feu",
            Field::BlockAll => "Toutes les connexions entrantes bloquées",
        }
    }
}

impl Settings {
    pub fn get(&self, f: Field) -> Value {
        match f {
            Field::VpnMode => Value::Mode(self.vpn_mode),
            Field::KillSwitch => Value::Flag(Some(self.kill_switch)),
            Field::Dns => Value::Flag(Some(self.dns)),
            Field::Firewall => Value::Flag(self.firewall),
            Field::Stealth => Value::Flag(self.stealth),
            Field::BlockAll => Value::Flag(self.block_all),
        }
    }

    /// Copy one setting from `other`.
    pub fn take(&mut self, f: Field, other: &Settings) {
        match f {
            Field::VpnMode => self.vpn_mode = other.vpn_mode,
            Field::KillSwitch => self.kill_switch = other.kill_switch,
            Field::Dns => self.dns = other.dns,
            Field::Firewall => self.firewall = other.firewall,
            Field::Stealth => self.stealth = other.stealth,
            Field::BlockAll => self.block_all = other.block_all,
        }
    }

    /// Settings that differ from `other`.
    pub fn diff(&self, other: &Settings) -> Vec<Field> {
        Field::ALL
            .into_iter()
            .filter(|f| self.get(*f) != other.get(*f))
            .collect()
    }
}

/// Inputs of [`plan_enable`] that do not come from the current settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnableOptions {
    /// A VPN is configured (profile imported, or a macOS VPN chosen for the external backend).
    pub vpn_usable: bool,
    /// `travel.block_all_incoming`.
    pub block_all: bool,
}

pub const WARN_NO_VPN: &str = "VPN non configuré : importez un profil (ou choisissez un VPN de macOS) pour chiffrer le trafic. Le coupe-circuit n'a pas été activé pour ne pas couper Internet.";
pub const WARN_FIREWALL_UNKNOWN: &str =
    "État du coupe-feu de macOS illisible : il n'a pas été modifié.";

/// Target settings of travel mode, with French warnings for what is left out.
pub fn plan_enable(current: &Settings, opts: &EnableOptions) -> (Settings, Vec<String>) {
    let mut t = *current;
    let mut warnings = Vec::new();
    if opts.vpn_usable {
        t.vpn_mode = VpnMode::Always;
        t.kill_switch = true;
    } else {
        warnings.push(WARN_NO_VPN.to_string());
    }
    t.dns = true;
    if current.firewall.is_some() {
        t.firewall = Some(true);
        if current.stealth.is_some() {
            t.stealth = Some(true);
        }
        if opts.block_all && current.block_all.is_some() {
            t.block_all = Some(true);
        }
    } else {
        warnings.push(WARN_FIREWALL_UNKNOWN.to_string());
    }
    (t, warnings)
}

/// What disabling must set: for every setting travel mode changed, the value from before, unless it was
/// changed by hand since (then it is kept and listed). An unreadable current value counts as unchanged.
pub fn plan_restore(
    before: &Settings,
    applied: &Settings,
    current: &Settings,
) -> (Settings, Vec<Field>) {
    let mut target = *current;
    let mut kept = Vec::new();
    for f in Field::ALL {
        let (b, a, c) = (before.get(f), applied.get(f), current.get(f));
        if b == a || c == b {
            // Not changed by travel mode, or already back to its previous value.
            continue;
        }
        if c == a || c == Value::Flag(None) {
            target.take(f, before);
        } else {
            kept.push(f);
        }
    }
    (target, kept)
}

/// What to do when the current network changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetAction {
    None,
    /// Raise an alert offering travel mode.
    Suggest,
    AutoEnable,
    /// Travel mode was enabled automatically and the Mac is back on a trusted network.
    AutoDisable,
}

/// Decision for a new current network (`trusted` = in `vpn.trusted_networks`).
pub fn network_action(
    cfg: &TravelConfig,
    active: bool,
    automatic: bool,
    trusted: Option<bool>,
) -> NetAction {
    match trusted {
        None => NetAction::None,
        Some(false) if active => NetAction::None,
        Some(false) if cfg.auto_enable => NetAction::AutoEnable,
        Some(false) if cfg.suggest_on_untrusted => NetAction::Suggest,
        Some(false) => NetAction::None,
        Some(true) if active && automatic => NetAction::AutoDisable,
        Some(true) => NetAction::None,
    }
}

// ---------------------------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------------------------

/// Saved while travel mode is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub since: i64,
    #[serde(default)]
    pub automatic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub before: Settings,
    /// What travel mode actually set (updated once applied).
    pub applied: Settings,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// A network as seen in the VPN status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenNetwork {
    pub id: String,
    pub name: String,
    pub trusted: bool,
}

/// Side effects of travel mode.
#[async_trait]
pub trait TravelBackend: Send + Sync {
    /// Current settings (configuration + firewall).
    async fn read(&self) -> Settings;
    /// A VPN is configured.
    async fn vpn_usable(&self) -> bool;
    /// Change the settings that differ between `current` and `target`; returns warnings (French).
    async fn apply(&self, current: &Settings, target: &Settings) -> Vec<String>;
    /// Bring the tunnel up (after enabling).
    async fn connect_vpn(&self);
}

/// Travel mode state, owned by [`Ctx`].
pub struct Travel {
    file: PathBuf,
    /// Serializes enable / disable.
    op: tokio::sync::Mutex<()>,
    snapshot: Mutex<Option<Snapshot>>,
    network: Mutex<Option<SeenNetwork>>,
    message: Mutex<Option<String>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Travel {
    /// Load `state_dir/travel.json` (a snapshot left by a previous run means travel mode is still on).
    pub fn new(state_dir: &Path) -> Self {
        let file = state_dir.join(STATE_FILE);
        let snapshot = match pb_vpn::fsutil::read_json::<Snapshot>(&file) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "travel snapshot unreadable, travel mode considered off");
                None
            }
        };
        Self {
            file,
            op: tokio::sync::Mutex::new(()),
            snapshot: Mutex::new(snapshot),
            network: Mutex::new(None),
            message: Mutex::new(None),
        }
    }

    pub fn is_active(&self) -> bool {
        lock(&self.snapshot).is_some()
    }

    pub fn is_automatic(&self) -> bool {
        lock(&self.snapshot).as_ref().is_some_and(|s| s.automatic)
    }

    pub fn status(&self) -> TravelStatus {
        let untrusted_network = lock(&self.network).as_ref().is_some_and(|n| !n.trusted);
        let message = lock(&self.message).clone();
        match lock(&self.snapshot).as_ref() {
            Some(s) => TravelStatus {
                active: true,
                since: Some(s.since),
                automatic: s.automatic,
                network: s.network.clone(),
                changes: s
                    .before
                    .diff(&s.applied)
                    .into_iter()
                    .map(|f| TravelItem {
                        id: f.id().into(),
                        label: f.label().into(),
                    })
                    .collect(),
                warnings: s.warnings.clone(),
                message,
                untrusted_network,
            },
            None => TravelStatus {
                message,
                untrusted_network,
                ..Default::default()
            },
        }
    }

    /// Record the current network; true when it changed (id or trust).
    pub fn note_network(&self, n: Option<SeenNetwork>) -> bool {
        let mut g = lock(&self.network);
        if *g == n {
            return false;
        }
        *g = n;
        true
    }

    pub fn current_network(&self) -> Option<SeenNetwork> {
        lock(&self.network).clone()
    }

    fn save(&self, s: Option<&Snapshot>) -> std::io::Result<()> {
        match s {
            Some(s) => pb_vpn::fsutil::write_json(&self.file, s),
            None => pb_vpn::fsutil::remove(&self.file),
        }
    }

    /// Enable (no-op when already on).
    pub async fn enable(
        &self,
        b: &dyn TravelBackend,
        automatic: bool,
        network: Option<SeenNetwork>,
        now: i64,
    ) -> Result<TravelStatus, String> {
        let _op = self.op.lock().await;
        if self.is_active() {
            return Ok(self.status());
        }
        let current = b.read().await;
        let opts = EnableOptions {
            vpn_usable: b.vpn_usable().await,
            block_all: false,
        };
        self.enable_with(b, current, opts, automatic, network, now)
            .await
    }

    /// Same as [`Travel::enable`] with explicit options (`block_all`).
    pub async fn enable_opts(
        &self,
        b: &dyn TravelBackend,
        block_all: bool,
        automatic: bool,
        network: Option<SeenNetwork>,
        now: i64,
    ) -> Result<TravelStatus, String> {
        let _op = self.op.lock().await;
        if self.is_active() {
            return Ok(self.status());
        }
        let current = b.read().await;
        let opts = EnableOptions {
            vpn_usable: b.vpn_usable().await,
            block_all,
        };
        self.enable_with(b, current, opts, automatic, network, now)
            .await
    }

    async fn enable_with(
        &self,
        b: &dyn TravelBackend,
        current: Settings,
        opts: EnableOptions,
        automatic: bool,
        network: Option<SeenNetwork>,
        now: i64,
    ) -> Result<TravelStatus, String> {
        let (target, mut warnings) = plan_enable(&current, &opts);
        // Saved first: whatever happens next, disabling knows what to put back.
        let mut snap = Snapshot {
            since: now,
            automatic,
            network_id: network.as_ref().map(|n| n.id.clone()),
            network: network.as_ref().map(|n| n.name.clone()),
            before: current,
            applied: target,
            warnings: warnings.clone(),
        };
        self.save(Some(&snap))
            .map_err(|e| format!("enregistrement de l'état du mode Voyage impossible : {e}"))?;
        *lock(&self.snapshot) = Some(snap.clone());
        warnings.extend(b.apply(&current, &target).await);
        // Record what really changed (a failed step must not be "restored" later).
        let achieved = b.read().await;
        for f in current.diff(&target) {
            if achieved.get(f) != target.get(f) {
                snap.applied.take(f, &achieved);
            }
        }
        snap.warnings = warnings;
        if let Err(e) = self.save(Some(&snap)) {
            tracing::warn!(error = %e, "travel snapshot not updated");
        }
        *lock(&self.snapshot) = Some(snap.clone());
        *lock(&self.message) = None;
        if snap.applied.vpn_mode == VpnMode::Always && opts.vpn_usable {
            b.connect_vpn().await;
        }
        tracing::info!(automatic, changes = ?snap.before.diff(&snap.applied), "travel mode enabled");
        Ok(self.status())
    }

    /// Disable: put back what travel mode changed (no-op when off).
    pub async fn disable(&self, b: &dyn TravelBackend) -> Result<TravelStatus, String> {
        let _op = self.op.lock().await;
        let Some(snap) = lock(&self.snapshot).clone() else {
            return Ok(self.status());
        };
        let current = b.read().await;
        let (target, kept) = plan_restore(&snap.before, &snap.applied, &current);
        let mut warnings = b.apply(&current, &target).await;
        let after = b.read().await;
        for f in current.diff(&target) {
            if after.get(f) != target.get(f) {
                warnings.push(format!("« {} » n'a pas pu être rétabli", f.label()));
            }
        }
        self.save(None)
            .map_err(|e| format!("suppression de l'état du mode Voyage impossible : {e}"))?;
        *lock(&self.snapshot) = None;
        let mut parts = Vec::new();
        if !kept.is_empty() {
            let names: Vec<&str> = kept.iter().map(|f| f.label()).collect();
            parts.push(format!(
                "Modifiés entre-temps, conservés tels quels : {}.",
                names.join(", ")
            ));
        }
        if !warnings.is_empty() {
            parts.push(warnings.join(" ; "));
        }
        *lock(&self.message) = (!parts.is_empty()).then(|| parts.join(" "));
        tracing::info!(kept = ?kept, "travel mode disabled");
        Ok(self.status())
    }
}

// ---------------------------------------------------------------------------------------------
// Firewall (`socketfilterfw`)
// ---------------------------------------------------------------------------------------------

/// `--getstealthmode` / `--getblockall` output → on/off. Seen: `Firewall stealth mode is on`,
/// `Stealth mode enabled`, `Firewall has block all state set to disabled.`, `Block all DISABLED!`.
/// Errors (`… cannot be modified …`) → `None`.
pub fn parse_fw_flag(out: &str) -> Option<bool> {
    let l = out.to_ascii_lowercase();
    if l.contains("cannot") || l.contains("error") || l.contains("usage") {
        return None;
    }
    let words: Vec<&str> = l
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    if words.iter().any(|w| matches!(*w, "disabled" | "off")) {
        Some(false)
    } else if words.iter().any(|w| matches!(*w, "enabled" | "on")) {
        Some(true)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FwSetting {
    Global,
    Stealth,
    BlockAll,
}

impl FwSetting {
    fn get_arg(self) -> &'static str {
        match self {
            FwSetting::Global => "--getglobalstate",
            FwSetting::Stealth => "--getstealthmode",
            FwSetting::BlockAll => "--getblockall",
        }
    }
    fn set_arg(self) -> &'static str {
        match self {
            FwSetting::Global => "--setglobalstate",
            FwSetting::Stealth => "--setstealthmode",
            FwSetting::BlockAll => "--setblockall",
        }
    }
    fn parse(self, out: &str) -> Option<bool> {
        match self {
            FwSetting::Global => crate::posture::parse_firewall(out),
            _ => parse_fw_flag(out),
        }
    }
}

async fn fw_get(s: FwSetting) -> Option<bool> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    match crate::system::run_command(SOCKETFILTERFW, &[s.get_arg()], FW_TIMEOUT).await {
        Ok(o) => s.parse(&o.stdout),
        Err(e) => {
            tracing::debug!(error = %e, "socketfilterfw read failed");
            None
        }
    }
}

async fn fw_set(s: FwSetting, on: bool) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("coupe-feu de macOS indisponible".into());
    }
    let v = if on { "on" } else { "off" };
    let o = crate::system::run_command(SOCKETFILTERFW, &[s.set_arg(), v], FW_TIMEOUT).await?;
    match fw_get(s).await {
        Some(x) if x == on => Ok(()),
        _ => Err(format!(
            "socketfilterfw {} {v} sans effet : {}",
            s.set_arg(),
            o.stdout.trim().chars().take(200).collect::<String>()
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Daemon backend
// ---------------------------------------------------------------------------------------------

/// Read-modify-save of the configuration fields travel mode owns, under `ctx.config_write` so a
/// concurrent settings save never loses (or overwrites) these changes.
async fn update_config(ctx: &Arc<Ctx>, f: impl FnOnce(&mut Config)) -> Result<Config, String> {
    let _write = ctx.config_write.lock().await;
    let mut cfg = (*ctx.config()).clone();
    f(&mut cfg);
    cfg.validate().map_err(|e| e.to_string())?;
    crate::setup::save_config(&ctx.paths, &cfg).map_err(|e| e.to_string())?;
    ctx.publish_config(cfg.clone());
    Ok(cfg)
}

/// Production backend.
pub struct DaemonBackend {
    ctx: Weak<Ctx>,
}

impl DaemonBackend {
    pub fn new(ctx: &Arc<Ctx>) -> Self {
        Self {
            ctx: Arc::downgrade(ctx),
        }
    }
}

#[async_trait]
impl TravelBackend for DaemonBackend {
    async fn read(&self) -> Settings {
        let Some(ctx) = self.ctx.upgrade() else {
            return Settings {
                vpn_mode: VpnMode::Off,
                kill_switch: false,
                dns: false,
                firewall: None,
                stealth: None,
                block_all: None,
            };
        };
        let cfg = ctx.config();
        let (firewall, stealth, block_all) = tokio::join!(
            fw_get(FwSetting::Global),
            fw_get(FwSetting::Stealth),
            fw_get(FwSetting::BlockAll)
        );
        Settings {
            vpn_mode: cfg.vpn.mode,
            kill_switch: cfg.vpn.kill_switch,
            dns: cfg.dns.enabled,
            firewall,
            stealth,
            block_all,
        }
    }

    async fn vpn_usable(&self) -> bool {
        let Some(ctx) = self.ctx.upgrade() else {
            return false;
        };
        let cfg = ctx.config();
        match cfg.vpn.backend {
            VpnBackend::External => cfg.vpn.external_service.is_some(),
            VpnBackend::SingBox => match crate::vpn::service(&ctx) {
                Ok(v) => v.status().await.profile.is_some(),
                Err(_) => false,
            },
        }
    }

    async fn apply(&self, current: &Settings, target: &Settings) -> Vec<String> {
        let Some(ctx) = self.ctx.upgrade() else {
            return vec!["arrêt en cours".into()];
        };
        let mut warnings = Vec::new();
        let mut dns = current.dns;
        if target.dns != current.dns {
            let mut cfg = (*ctx.config()).clone();
            cfg.dns.enabled = target.dns;
            let r = if target.dns {
                ctx.backends.dns.enable(&cfg).await.map(|_| ())
            } else {
                ctx.backends.dns.disable().await.map(|_| ())
            };
            match r {
                Ok(()) => dns = target.dns,
                Err(e) => warnings.push(format!("Blocage DNS non modifié : {e}")),
            }
        }
        if (target.vpn_mode, target.kill_switch, dns)
            != (current.vpn_mode, current.kill_switch, current.dns)
        {
            let (mode, ks) = (target.vpn_mode, target.kill_switch);
            if let Err(e) = update_config(&ctx, |c| {
                c.vpn.mode = mode;
                c.vpn.kill_switch = ks;
                c.dns.enabled = dns;
            })
            .await
            {
                warnings.push(format!("Configuration non enregistrée : {e}"));
            }
        }
        // Firewall: switched on first / off last, so the Mac is never more exposed than before.
        let order = if target.firewall == Some(true) {
            [FwSetting::Global, FwSetting::Stealth, FwSetting::BlockAll]
        } else {
            [FwSetting::BlockAll, FwSetting::Stealth, FwSetting::Global]
        };
        for s in order {
            let (cur, want) = match s {
                FwSetting::Global => (current.firewall, target.firewall),
                FwSetting::Stealth => (current.stealth, target.stealth),
                FwSetting::BlockAll => (current.block_all, target.block_all),
            };
            if let Some(on) = want {
                if cur != want {
                    if let Err(e) = fw_set(s, on).await {
                        tracing::warn!(error = %e, "firewall setting not applied");
                        warnings.push(format!("Coupe-feu : {e}"));
                    }
                }
            }
        }
        ctx.status_dirty.notify_one();
        warnings
    }

    async fn connect_vpn(&self) {
        let Some(ctx) = self.ctx.upgrade() else {
            return;
        };
        if let Ok(v) = crate::vpn::service(&ctx) {
            // In the background: the tunnel may take up to 25 s; its progress is pushed as `vpn` events.
            tokio::spawn(async move {
                if let Err(e) = v.connect().await {
                    tracing::warn!(error = %e, "travel mode: VPN connection failed");
                }
            });
        }
    }
}

fn internal(e: String) -> IpcError {
    IpcError::new(ErrorCode::Internal, e)
}

/// `travel_status`.
pub fn status(ctx: &Ctx) -> TravelStatus {
    ctx.travel.status()
}

/// `travel_enable` (and the alert action).
pub async fn enable(ctx: &Arc<Ctx>, automatic: bool) -> Result<TravelStatus, IpcError> {
    let b = DaemonBackend::new(ctx);
    let block_all = ctx.config().travel.block_all_incoming;
    let net = ctx.travel.current_network();
    let r = ctx
        .travel
        .enable_opts(&b, block_all, automatic, net, pb_core::now_ts())
        .await
        .map_err(internal);
    ctx.status_dirty.notify_one();
    r
}

/// `travel_disable`.
pub async fn disable(ctx: &Arc<Ctx>) -> Result<TravelStatus, IpcError> {
    let b = DaemonBackend::new(ctx);
    let r = ctx.travel.disable(&b).await.map_err(internal);
    ctx.status_dirty.notify_one();
    r
}

/// Called on every VPN status push: on a network change, suggest / enable / restore travel mode.
pub fn on_vpn_status(ctx: &Arc<Ctx>, status: &VpnStatus) {
    let seen = status.network.as_ref().map(|n| SeenNetwork {
        id: n.id.clone(),
        name: n.name.clone(),
        trusted: n.trusted,
    });
    if !ctx.travel.note_network(seen.clone()) {
        return;
    }
    ctx.status_dirty.notify_one();
    let action = network_action(
        &ctx.config().travel,
        ctx.travel.is_active(),
        ctx.travel.is_automatic(),
        seen.as_ref().map(|n| n.trusted),
    );
    let Some(net) = seen else { return };
    let ctx = ctx.clone();
    match action {
        NetAction::None => {}
        NetAction::Suggest => {
            tokio::spawn(async move { suggest(&ctx, &net).await });
        }
        NetAction::AutoEnable => {
            tokio::spawn(async move {
                match enable(&ctx, true).await {
                    Ok(_) => {
                        let a = crate::actions::alert(
                            AlertKind::Network,
                            Severity::Low,
                            "Mode Voyage activé automatiquement",
                            format!(
                                "Le réseau « {} » n'est pas approuvé : VPN, coupe-circuit, blocage DNS et coupe-feu furtif \
                                 sont actifs. Ils seront rétablis à votre retour sur un réseau approuvé.",
                                net.name
                            ),
                        );
                        crate::actions::raise_alert(
                            &ctx,
                            a,
                            Some(format!("travel-auto:{}", net.id)),
                        )
                        .await;
                    }
                    Err(e) => tracing::warn!(error = %e.message, "automatic travel mode failed"),
                }
            });
        }
        NetAction::AutoDisable => {
            tokio::spawn(async move {
                if let Err(e) = disable(&ctx).await {
                    tracing::warn!(error = %e.message, "automatic travel mode restore failed");
                }
            });
        }
    }
}

/// Alert offering travel mode on an untrusted network (once per network per day).
async fn suggest(ctx: &Arc<Ctx>, net: &SeenNetwork) {
    let key = format!("travel-suggest:{}", net.id);
    let since = pb_core::now_ts() - SUGGEST_DEDUPE_SECS;
    let k2 = key.clone();
    let recent = ctx
        .store
        .run(move |s| {
            s.find_recent_alert_by(
                AlertKind::Network,
                crate::store::AlertKey::Title(&k2),
                since,
            )
        })
        .await
        .ok()
        .flatten();
    if recent.is_some() {
        return;
    }
    let mut a = crate::actions::alert(
        AlertKind::Network,
        Severity::Medium,
        format!("Réseau non approuvé : « {} »", net.name),
        "Sur un Wi-Fi public (gare, hôtel, café), activez le mode Voyage : VPN permanent avec coupe-circuit, \
         blocage DNS et coupe-feu furtif. Un clic le désactive et rétablit vos réglages.",
    );
    a.network_id = Some(net.id.clone());
    a.actions = vec![
        AlertAction::EnableTravelMode,
        AlertAction::TrustNetwork,
        AlertAction::Acknowledge,
    ];
    crate::actions::raise_alert(ctx, a, Some(key)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn home() -> Settings {
        Settings {
            vpn_mode: VpnMode::Off,
            kill_switch: false,
            dns: false,
            firewall: Some(false),
            stealth: Some(false),
            block_all: Some(false),
        }
    }

    /// Fake system: settings in memory, optional failures, call counters.
    struct Fake {
        s: Mutex<Settings>,
        vpn: bool,
        fail_dns: bool,
        connects: AtomicU32,
    }

    impl Fake {
        fn new(s: Settings, vpn: bool) -> Self {
            Self {
                s: Mutex::new(s),
                vpn,
                fail_dns: false,
                connects: AtomicU32::new(0),
            }
        }
        fn get(&self) -> Settings {
            *lock(&self.s)
        }
        fn set(&self, f: impl FnOnce(&mut Settings)) {
            f(&mut lock(&self.s));
        }
    }

    #[async_trait]
    impl TravelBackend for Fake {
        async fn read(&self) -> Settings {
            self.get()
        }
        async fn vpn_usable(&self) -> bool {
            self.vpn
        }
        async fn apply(&self, current: &Settings, target: &Settings) -> Vec<String> {
            let mut w = vec![];
            let mut s = lock(&self.s);
            for f in current.diff(target) {
                if f == Field::Dns && self.fail_dns {
                    w.push("dns indisponible".into());
                    continue;
                }
                s.take(f, target);
            }
            w
        }
        async fn connect_vpn(&self) {
            self.connects.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn net() -> Option<SeenNetwork> {
        Some(SeenNetwork {
            id: "gw:00:11:22:33:44:55".into(),
            name: "Gare-WiFi".into(),
            trusted: false,
        })
    }

    #[test]
    fn plan_enable_with_and_without_vpn() {
        let (t, w) = plan_enable(
            &home(),
            &EnableOptions {
                vpn_usable: true,
                block_all: false,
            },
        );
        assert_eq!(t.vpn_mode, VpnMode::Always);
        assert!(t.kill_switch && t.dns);
        assert_eq!(
            (t.firewall, t.stealth, t.block_all),
            (Some(true), Some(true), Some(false))
        );
        assert!(w.is_empty());
        let (t, w) = plan_enable(
            &home(),
            &EnableOptions {
                vpn_usable: false,
                block_all: true,
            },
        );
        assert_eq!(t.vpn_mode, VpnMode::Off);
        assert!(!t.kill_switch && t.dns);
        assert_eq!(t.block_all, Some(true));
        assert_eq!(w, vec![WARN_NO_VPN.to_string()]);
        // Unreadable firewall: left alone.
        let mut cur = home();
        cur.firewall = None;
        let (t, w) = plan_enable(&cur, &EnableOptions::default());
        assert_eq!((t.firewall, t.stealth), (None, Some(false)));
        assert!(w.contains(&WARN_FIREWALL_UNKNOWN.to_string()));
    }

    #[test]
    fn plan_restore_keeps_manual_changes() {
        let before = home();
        let (applied, _) = plan_enable(
            &before,
            &EnableOptions {
                vpn_usable: true,
                block_all: false,
            },
        );
        // Nothing touched since: everything goes back.
        let (t, kept) = plan_restore(&before, &applied, &applied);
        assert_eq!(t, before);
        assert!(kept.is_empty());
        // The user switched the VPN mode to "untrusted networks" and DNS off meanwhile.
        let mut cur = applied;
        cur.vpn_mode = VpnMode::UntrustedNetworks;
        cur.dns = false;
        let (t, kept) = plan_restore(&before, &applied, &cur);
        assert_eq!(kept, vec![Field::VpnMode]);
        assert_eq!(t.vpn_mode, VpnMode::UntrustedNetworks);
        assert!(!t.kill_switch && !t.dns);
        assert_eq!(t.firewall, Some(false));
        // Settings travel mode did not change are never touched.
        let mut b2 = home();
        b2.dns = true;
        let (a2, _) = plan_enable(&b2, &EnableOptions::default());
        let mut cur = a2;
        cur.dns = false;
        let (t, kept) = plan_restore(&b2, &a2, &cur);
        assert!(!t.dns && kept.is_empty());
        // Unreadable now: restored.
        let mut cur = applied;
        cur.stealth = None;
        let (t, _) = plan_restore(&before, &applied, &cur);
        assert_eq!(t.stealth, Some(false));
    }

    #[test]
    fn network_decisions() {
        let mut c = TravelConfig::default();
        assert_eq!(network_action(&c, false, false, None), NetAction::None);
        assert_eq!(
            network_action(&c, false, false, Some(false)),
            NetAction::Suggest
        );
        assert_eq!(
            network_action(&c, true, false, Some(false)),
            NetAction::None
        );
        assert_eq!(network_action(&c, true, false, Some(true)), NetAction::None);
        assert_eq!(
            network_action(&c, true, true, Some(true)),
            NetAction::AutoDisable
        );
        c.auto_enable = true;
        assert_eq!(
            network_action(&c, false, false, Some(false)),
            NetAction::AutoEnable
        );
        c.auto_enable = false;
        c.suggest_on_untrusted = false;
        assert_eq!(
            network_action(&c, false, false, Some(false)),
            NetAction::None
        );
    }

    #[tokio::test]
    async fn enable_then_disable_restores_exactly() {
        let d = tempfile::tempdir().unwrap();
        let t = Travel::new(d.path());
        let fake = Fake::new(home(), true);
        assert!(!t.is_active());
        t.note_network(net());
        let st = t.enable(&fake, false, net(), 100).await.unwrap();
        assert!(st.active && st.untrusted_network);
        assert_eq!(st.network.as_deref(), Some("Gare-WiFi"));
        assert_eq!(st.changes.len(), 5);
        assert_eq!(fake.connects.load(Ordering::SeqCst), 1);
        assert_eq!(fake.get().vpn_mode, VpnMode::Always);
        assert!(d.path().join(STATE_FILE).is_file());
        // Idempotent.
        let again = t.enable(&fake, false, net(), 200).await.unwrap();
        assert_eq!(again.since, Some(100));
        assert_eq!(fake.connects.load(Ordering::SeqCst), 1);
        // The user turns stealth mode off by hand: it stays off, the rest goes back.
        fake.set(|s| s.stealth = Some(false));
        fake.set(|s| s.kill_switch = false);
        let st = t.disable(&fake).await.unwrap();
        assert!(!st.active);
        assert_eq!(fake.get(), home());
        assert!(st.message.is_none(), "{:?}", st.message);
        assert!(!d.path().join(STATE_FILE).exists());
        // Disabling twice is harmless.
        assert!(!t.disable(&fake).await.unwrap().active);
    }

    #[tokio::test]
    async fn manual_change_is_kept_and_reported() {
        let d = tempfile::tempdir().unwrap();
        let t = Travel::new(d.path());
        let fake = Fake::new(home(), true);
        t.enable(&fake, false, None, 1).await.unwrap();
        fake.set(|s| s.vpn_mode = VpnMode::UntrustedNetworks);
        let st = t.disable(&fake).await.unwrap();
        assert_eq!(fake.get().vpn_mode, VpnMode::UntrustedNetworks);
        assert!(!fake.get().kill_switch && !fake.get().dns);
        let msg = st.message.unwrap();
        assert!(msg.contains("VPN toujours actif"), "{msg}");
    }

    #[tokio::test]
    async fn failed_step_is_not_restored_and_snapshot_survives_restart() {
        let d = tempfile::tempdir().unwrap();
        let mut b = home();
        b.vpn_mode = VpnMode::UntrustedNetworks;
        let mut fake = Fake::new(b, false);
        fake.fail_dns = true;
        {
            let t = Travel::new(d.path());
            let st = t.enable(&fake, true, net(), 5).await.unwrap();
            assert!(st.automatic);
            // No VPN configured: VPN mode / kill switch untouched, no connection attempt.
            assert_eq!(fake.get().vpn_mode, VpnMode::UntrustedNetworks);
            assert_eq!(fake.connects.load(Ordering::SeqCst), 0);
            assert!(!st.changes.iter().any(|c| c.id == "dns"));
            assert!(st.warnings.iter().any(|w| w.contains("dns indisponible")));
            assert!(st.warnings.contains(&WARN_NO_VPN.to_string()));
        }
        // "Reboot": the snapshot is reloaded, travel mode is still on.
        let t = Travel::new(d.path());
        assert!(t.is_active() && t.is_automatic());
        fake.fail_dns = false;
        // DNS turned on by hand meanwhile: travel mode did not change it, so it stays on.
        fake.set(|s| s.dns = true);
        t.disable(&fake).await.unwrap();
        let after = fake.get();
        assert!(after.dns);
        assert_eq!(after.firewall, Some(false));
        assert_eq!(after.vpn_mode, VpnMode::UntrustedNetworks);
    }

    #[test]
    fn corrupt_snapshot_means_off() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(STATE_FILE), b"{not json").unwrap();
        assert!(!Travel::new(d.path()).is_active());
    }

    #[test]
    fn network_changes_are_detected_once() {
        let d = tempfile::tempdir().unwrap();
        let t = Travel::new(d.path());
        assert!(t.note_network(net()));
        assert!(!t.note_network(net()));
        let mut n = net().unwrap();
        n.trusted = true;
        assert!(t.note_network(Some(n)));
        assert!(!t.status().untrusted_network);
        assert!(t.note_network(None));
    }

    #[test]
    fn firewall_outputs() {
        assert_eq!(parse_fw_flag("Firewall stealth mode is on\n"), Some(true));
        assert_eq!(parse_fw_flag("Firewall stealth mode is off\n"), Some(false));
        assert_eq!(parse_fw_flag("Stealth mode enabled \n"), Some(true));
        assert_eq!(parse_fw_flag("Stealth mode disabled \n"), Some(false));
        assert_eq!(
            parse_fw_flag("Firewall has block all state set to disabled.\n"),
            Some(false)
        );
        assert_eq!(
            parse_fw_flag("Firewall has block all state set to enabled.\n"),
            Some(true)
        );
        assert_eq!(parse_fw_flag("Block all DISABLED! \n"), Some(false));
        assert_eq!(parse_fw_flag("Block all ENABLED! \n"), Some(true));
        assert_eq!(
            parse_fw_flag(
                "Firewall settings cannot be modified from command line on managed Mac computers.\n"
            ),
            None
        );
        assert_eq!(parse_fw_flag(""), None);
        assert_eq!(
            FwSetting::Global.parse("Firewall is enabled. (State = 1)\n"),
            Some(true)
        );
        assert_eq!(
            FwSetting::Global.parse("Firewall is disabled. (State = 0)\n"),
            Some(false)
        );
    }
}
