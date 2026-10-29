//! IPC protocol between `parabellumd` (server) and the SwiftUI app / `parabellum` CLI (clients).
//!
//! Transport: Unix domain socket ([`crate::paths::Paths::socket`]), **one JSON object per line**
//! (UTF-8, `\n`-terminated, max [`MAX_FRAME`] bytes per line).
//!
//! Client -> daemon: a [`RequestEnvelope`]:
//! ```json
//! {"id": 7, "cmd": "scan", "paths": ["/Users/q/Downloads"], "recursive": true}
//! ```
//! Daemon -> client: either a [`ResponseEnvelope`] (has `"id"`) …
//! ```json
//! {"id": 7, "ok": true, "data": {"job_id": "…"}}
//! {"id": 8, "ok": false, "error": {"code": "not_found", "message": "no such alert"}}
//! ```
//! … or, after a `subscribe` request on that connection, pushed [`EventEnvelope`]s (have `"event"`):
//! ```json
//! {"event": "alert", "data": { …Alert… }}
//! ```
//! Clients must tell them apart by the presence of the `"event"` key.
//!
//! Security: the daemon checks the peer (uid of the console user or root, and the executable path of the
//! peer process must be the installed app or CLI) before accepting *mutating* commands — see
//! [`Request::is_mutating`].

use crate::config::Config;
use crate::model::*;
use serde::{Deserialize, Serialize};

/// Max size of a single JSON line.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;
/// Bumped when the protocol changes incompatibly; returned by `ping`.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: u64,
    /// Proof that a human administrator approved this request: base64 of the 32-byte
    /// `AuthorizationExternalForm` of an `AuthorizationRef` that holds [`ADMIN_RIGHT`] (the app obtains
    /// it with `AuthorizationCopyRights(.interactionAllowed | .extendRights)`, i.e. a password / Touch ID
    /// prompt drawn by SecurityAgent, which synthetic input cannot drive). Required for
    /// [`Request::requires_admin`] commands unless the peer is root (`sudo parabellum …`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(flatten)]
    pub request: Request,
}

/// Authorization right registered by the daemon at startup (`AuthorizationRightSet`, rule
/// `authenticate-admin`, not shared) and required for protection-weakening commands.
pub const ADMIN_RIGHT: &str = "com.wldeus.parabellum.admin";

/// All commands. The doc comment of each variant names the type of `data` in the success response.
// `SetConfig` carries the whole config inline; requests are short-lived, boxing would only obscure the API.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// -> [`PingResponse`]
    Ping,
    /// -> [`StatusInfo`]
    Status,
    /// Start an on-demand scan. -> [`JobStarted`]
    Scan {
        paths: Vec<String>,
        #[serde(default = "default_true")]
        recursive: bool,
        /// Override `scan.clamav_on_demand` for this job.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        use_clamav: Option<bool>,
    },
    /// -> `null`
    CancelScan { job_id: String },
    /// Recent jobs, newest first. -> `Vec<ScanJobSummary>`
    ListJobs {
        #[serde(default = "default_limit")]
        limit: u32,
    },
    /// -> [`ScanJobDetail`]
    GetJob { job_id: String },
    /// Newest first. -> `Vec<Alert>`
    ListAlerts {
        #[serde(default = "default_limit")]
        limit: u32,
        #[serde(default)]
        include_resolved: bool,
    },
    /// Apply one of the alert's `actions`. -> [`Alert`] (updated)
    ResolveAlert { alert_id: i64, action: AlertAction },
    /// -> `Vec<QuarantineEntry>`
    ListQuarantine,
    /// Manually quarantine a file. -> [`QuarantineEntry`]
    QuarantinePath { path: String },
    /// Put a quarantined file back. `allow = true` also adds its hash to the local allowlist.
    /// -> `{"restored_path": String}`
    Restore {
        entry_id: String,
        #[serde(default)]
        allow: bool,
    },
    /// Permanently delete a quarantined file (explicit user action only). -> `null`
    DeleteQuarantined { entry_id: String },
    /// Record a false positive: hash goes to the local allowlist + FP log (weekly report). -> `null`
    ReportFalsePositive {
        sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// -> `Vec<PersistenceItem>`
    ListPersistence {
        #[serde(default)]
        only_new: bool,
    },
    /// Approve (keep) or remove (unload + quarantine) a persistence item. -> [`PersistenceItem`]
    SetPersistenceStatus {
        item_id: String,
        status: PersistenceStatus,
    },
    /// -> `Vec<DeviceInfo>`
    ListDevices {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<DeviceKind>,
    },
    /// -> [`DeviceInfo`]
    SetDeviceTrust {
        device_id: String,
        trust: DeviceTrust,
    },
    /// Runs in the background; completion is pushed as `update_finished`. -> [`JobStarted`]
    UpdateNow { target: UpdateTarget },
    /// -> `Vec<ComponentStatus>`
    ListComponents,
    /// Install (or reinstall) a managed component by name. -> [`JobStarted`]
    InstallComponent { name: String },
    /// -> `Vec<ComponentStatus>`
    SetComponentAutoUpdate { name: String, auto_update: bool },
    /// -> [`DnsStatus`]
    GetDns,
    /// -> [`DnsStatus`]
    SetDns { enabled: bool },
    /// -> [`AdblockStatus`]
    AdblockStatus,
    /// -> [`Config`]
    GetConfig,
    /// Replace the whole config (validated). -> [`Config`]
    SetConfig { config: Config },
    /// Pause real-time protection for `minutes` (0 = resume now). -> [`StatusInfo`]
    SetProtection { paused_minutes: u32 },
    /// `week_offset` 0 = current week, 1 = last week… -> [`WeeklyReport`]
    WeeklyReport {
        #[serde(default)]
        week_offset: u32,
    },
    /// Re-scan files seen in the last `days` days with the current DB. -> [`JobStarted`]
    RetroHunt {
        #[serde(default = "default_retro_days")]
        days: u32,
    },
    /// Check this Mac for traces of mercenary spyware (Zero Breach Toolkit from the threat DB, run as the
    /// console user, read-only). Progress / end are pushed as `scan_progress` / `scan_finished` with
    /// origin `spyware`; matches become alerts. -> [`JobStarted`]
    SpywareScan,
    /// macOS security settings (SIP, Gatekeeper, FileVault, firewall…). `refresh` re-runs the checks
    /// (at most every 30 s) instead of returning the last results. -> `Vec<PostureCheck>`
    Posture {
        #[serde(default)]
        refresh: bool,
    },
    // ----- VPN & networks -----
    /// -> [`VpnStatus`]
    VpnStatus,
    /// Bring the tunnel up now (manual override until `vpn_disconnect`). -> [`VpnStatus`]
    VpnConnect,
    /// Take the tunnel down (manual override until the next network change). Weakens protection when the
    /// mode wants it up: admin. -> [`VpnStatus`]
    VpnDisconnect,
    /// Import the VPN profile used by the sing-box backend: a share link (`ss://`, `vless://`, `vmess://`,
    /// `trojan://`, `hysteria2://` / `hy2://`, `tuic://`, `wireguard://`) or a WireGuard `.conf` text.
    /// Replaces the previous one. Admin (it decides where all traffic goes). -> [`VpnProfileInfo`]
    VpnImportProfile { profile: String },
    /// Forget the imported profile (disconnects). Admin. -> `null`
    VpnRemoveProfile,
    /// Run a leak test now (public IPv4/IPv6, DNS servers, kill switch). -> [`LeakTestResult`]
    VpnLeakTest,
    /// VPNs configured in macOS, for the external backend. -> `Vec<ExternalVpnService>`
    VpnListServices,
    /// Networks seen, current first. -> `Vec<NetworkInfo>`
    ListNetworks,
    /// Trust (admin) or stop trusting a network (`gw:<router MAC>`). -> [`NetworkInfo`]
    SetNetworkTrust { network_id: String, trusted: bool },

    // ----- Behaviour guard & snapshots -----
    /// -> [`GuardStatus`]
    GuardStatus,
    /// APFS local snapshots of the data volume, newest first. -> `Vec<SnapshotInfo>`
    ListSnapshots,
    /// -> [`SnapshotInfo`]
    CreateSnapshot,
    /// Copy `path` (inside the console user's home) as it was in `snapshot` to
    /// `~/Parabellum-Restauration/<snapshot>/<path relative to home>`; nothing is overwritten. Admin.
    /// -> `{"restored_to": String}`
    RestoreFromSnapshot { snapshot: String, path: String },

    // ----- Privacy -----
    /// The identity used for GDPR requests, masked unless `reveal` (admin). -> [`IdentityProfile`]
    PrivacyGetProfile {
        #[serde(default)]
        reveal: bool,
    },
    /// Admin. -> [`IdentityProfile`] (masked)
    PrivacySetProfile { profile: IdentityProfile },
    /// Brokers of the configured regions (signed list from the threat DB). -> `Vec<BrokerInfo>`
    PrivacyListBrokers,
    /// -> `Vec<RemovalRequest>`
    PrivacyListRequests,
    /// -> [`RemovalSummary`]
    PrivacySummary,
    /// Queue erasure requests to every broker of the configured regions (or only `broker_ids`) that has no
    /// open request. Sends in your name: admin. -> [`RemovalSummary`]
    PrivacyStartRemoval {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        broker_ids: Option<Vec<String>>,
    },
    /// Record what happened (draft sent, broker answered, web form done…). -> [`RemovalRequest`]
    PrivacyUpdateRequest {
        request_id: String,
        status: RemovalStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// The email to send for a request (first letter, or the reminder once overdue). Contains your identity:
    /// admin. -> [`MailDraft`]
    PrivacyDraft { request_id: String },
    /// Complaint text for the supervisory authority (CNIL) about an unanswered request. Contains your
    /// identity: admin. -> [`ComplaintDraft`]
    PrivacyComplaint { request_id: String },
    /// -> `Vec<BreachFinding>`
    BreachList,
    /// Check `breach.emails` now. -> `Vec<BreachFinding>`
    BreachCheckNow,
    /// -> `Vec<EmailAlias>`
    AliasList,
    /// Create a new alias (provider from `aliases`) labelled with what it is for. -> [`EmailAlias`]
    AliasCreate { label: String },

    /// Start receiving [`EventEnvelope`]s on this connection. -> `null`
    Subscribe,
}

fn default_true() -> bool {
    true
}
fn default_limit() -> u32 {
    100
}
fn default_retro_days() -> u32 {
    30
}

impl Request {
    /// Commands that weaken protection or destroy data. They need **administrator approval**: either the
    /// peer runs as root (`sudo parabellum …`) or the envelope carries a valid `auth` for [`ADMIN_RIGHT`].
    /// Without it the daemon answers [`ErrorCode::AuthRequired`]. Rationale: the console user's own
    /// processes (malware included) can run the installed CLI, so "same uid + installed binary" is not
    /// enough to allow-list malware, pause protection, trust a BadUSB device, or change the config.
    pub fn requires_admin(&self) -> bool {
        match self {
            Request::Restore { .. }
            | Request::DeleteQuarantined { .. }
            | Request::ReportFalsePositive { .. }
            | Request::SetConfig { .. }
            | Request::QuarantinePath { .. }
            | Request::SetPersistenceStatus { .. } => true,
            Request::VpnDisconnect
            | Request::VpnImportProfile { .. }
            | Request::VpnRemoveProfile
            | Request::RestoreFromSnapshot { .. }
            | Request::PrivacySetProfile { .. }
            | Request::PrivacyDraft { .. }
            | Request::PrivacyComplaint { .. }
            | Request::PrivacyStartRemoval { .. } => true,
            Request::SetNetworkTrust { trusted, .. } => *trusted,
            Request::PrivacyGetProfile { reveal } => *reveal,
            Request::SetDns { enabled } => !enabled,
            Request::SetProtection { paused_minutes } => *paused_minutes > 0,
            Request::SetDeviceTrust { trust, .. } => *trust != DeviceTrust::Blocked,
            Request::SetComponentAutoUpdate { auto_update, .. } => !auto_update,
            Request::ResolveAlert { action, .. } => matches!(
                action,
                AlertAction::Allow
                    | AlertAction::Restore
                    | AlertAction::TrustDevice
                    | AlertAction::ApprovePersistence
                    | AlertAction::RemovePersistence
                    | AlertAction::ReportFalsePositive
                    | AlertAction::ResumeProcess
                    | AlertAction::TrustNetwork
            ),
            _ => false,
        }
    }

    /// Commands that change state (need the peer to be the installed app/CLI of the console user or root).
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Request::Ping
                | Request::Status
                | Request::ListJobs { .. }
                | Request::GetJob { .. }
                | Request::ListAlerts { .. }
                | Request::ListQuarantine
                | Request::ListPersistence { .. }
                | Request::ListDevices { .. }
                | Request::ListComponents
                | Request::GetDns
                | Request::AdblockStatus
                | Request::GetConfig
                | Request::WeeklyReport { .. }
                | Request::Posture { .. }
                | Request::Subscribe
                | Request::VpnStatus
                | Request::VpnListServices
                | Request::ListNetworks
                | Request::GuardStatus
                | Request::ListSnapshots
                | Request::PrivacyGetProfile { reveal: false }
                | Request::PrivacyListBrokers
                | Request::PrivacyListRequests
                | Request::PrivacySummary
                | Request::BreachList
                | Request::AliasList
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingResponse {
    pub version: String,
    pub protocol: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobStarted {
    pub job_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    NotFound,
    PermissionDenied,
    /// The command needs administrator approval (see [`Request::requires_admin`]): retry with `auth`
    /// (app) or with `sudo` (CLI).
    AuthRequired,
    Busy,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
}

impl IpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

impl ResponseEnvelope {
    pub fn ok<T: Serialize>(id: u64, data: &T) -> Self {
        match serde_json::to_value(data) {
            Ok(v) => Self {
                id,
                ok: true,
                data: if v.is_null() { None } else { Some(v) },
                error: None,
            },
            Err(e) => Self::err(id, IpcError::new(ErrorCode::Internal, e.to_string())),
        }
    }
    pub fn ok_empty(id: u64) -> Self {
        Self {
            id,
            ok: true,
            data: None,
            error: None,
        }
    }
    pub fn err(id: u64, error: IpcError) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            error: Some(error),
        }
    }
    /// Decode `data` into the type documented for the request.
    pub fn into_result<T: serde::de::DeserializeOwned>(self) -> Result<T, IpcError> {
        if !self.ok {
            return Err(self
                .error
                .unwrap_or(IpcError::new(ErrorCode::Internal, "unknown error")));
        }
        serde_json::from_value(self.data.unwrap_or(serde_json::Value::Null))
            .map_err(|e| IpcError::new(ErrorCode::Internal, format!("bad response payload: {e}")))
    }
}

/// Events pushed to subscribed clients.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum DaemonEvent {
    Alert(Alert),
    /// Sent at most every 500 ms per running job.
    ScanProgress(ScanJobSummary),
    ScanFinished(ScanJobSummary),
    StatusChanged(StatusInfo),
    Device(DeviceEvent),
    UpdateFinished(UpdateResult),
    Component(ComponentStatus),
    Quarantined(QuarantineEntry),
    /// VPN state, kill switch, current network or leak test changed.
    Vpn(VpnStatus),
}

/// Alias kept for documentation symmetry with the module docs.
pub type EventEnvelope = DaemonEvent;

/// A line received by a client: response or event.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    Event(DaemonEvent),
    Response(ResponseEnvelope),
}

/// Serialize a message as one `\n`-terminated JSON line.
pub fn encode_line<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut v = serde_json::to_vec(msg)?;
    v.push(b'\n');
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format() {
        let r = RequestEnvelope {
            id: 7,
            auth: None,
            request: Request::Scan {
                paths: vec!["/tmp".into()],
                recursive: true,
                use_clamav: None,
            },
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(
            s,
            r#"{"id":7,"cmd":"scan","paths":["/tmp"],"recursive":true}"#
        );
        let back: RequestEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn unit_request_and_defaults() {
        let r: RequestEnvelope = serde_json::from_str(r#"{"id":1,"cmd":"status"}"#).unwrap();
        assert_eq!(r.request, Request::Status);
        let r: RequestEnvelope = serde_json::from_str(r#"{"id":2,"cmd":"list_alerts"}"#).unwrap();
        assert_eq!(
            r.request,
            Request::ListAlerts {
                limit: 100,
                include_resolved: false
            }
        );
        let r: RequestEnvelope =
            serde_json::from_str(r#"{"id":3,"cmd":"scan","paths":["/a"]}"#).unwrap();
        assert!(matches!(
            r.request,
            Request::Scan {
                recursive: true,
                ..
            }
        ));
    }

    #[test]
    fn admin_classification() {
        assert!(Request::Restore {
            entry_id: "x".into(),
            allow: false
        }
        .requires_admin());
        assert!(Request::SetDns { enabled: false }.requires_admin());
        assert!(!Request::SetDns { enabled: true }.requires_admin());
        assert!(!Request::SetProtection { paused_minutes: 0 }.requires_admin());
        assert!(Request::SetProtection { paused_minutes: 10 }.requires_admin());
        assert!(!Request::SetDeviceTrust {
            device_id: "d".into(),
            trust: DeviceTrust::Blocked
        }
        .requires_admin());
        assert!(Request::SetDeviceTrust {
            device_id: "d".into(),
            trust: DeviceTrust::Trusted
        }
        .requires_admin());
        assert!(!Request::ResolveAlert {
            alert_id: 1,
            action: AlertAction::Quarantine
        }
        .requires_admin());
        assert!(Request::ResolveAlert {
            alert_id: 1,
            action: AlertAction::Allow
        }
        .requires_admin());
        assert!(!Request::Scan {
            paths: vec![],
            recursive: true,
            use_clamav: None
        }
        .requires_admin());
        // auth travels next to id/cmd and is omitted when absent
        let e = RequestEnvelope {
            id: 1,
            auth: Some("QUJD".into()),
            request: Request::GetConfig,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"id":1,"auth":"QUJD","cmd":"get_config"}"#);
        assert_eq!(serde_json::from_str::<RequestEnvelope>(&s).unwrap(), e);
    }

    #[test]
    fn spyware_and_posture_requests() {
        let r: RequestEnvelope = serde_json::from_str(r#"{"id":1,"cmd":"spyware_scan"}"#).unwrap();
        assert_eq!(r.request, Request::SpywareScan);
        assert!(!Request::SpywareScan.requires_admin());
        assert!(Request::SpywareScan.is_mutating());
        let r: RequestEnvelope = serde_json::from_str(r#"{"id":2,"cmd":"posture"}"#).unwrap();
        assert_eq!(r.request, Request::Posture { refresh: false });
        assert!(!r.request.is_mutating());
        assert!(!r.request.requires_admin());
    }

    #[test]
    fn protection_requests() {
        let r: RequestEnvelope =
            serde_json::from_str(r#"{"id":1,"cmd":"vpn_import_profile","profile":"ss://x"}"#)
                .unwrap();
        assert!(r.request.requires_admin() && r.request.is_mutating());
        let r: RequestEnvelope =
            serde_json::from_str(r#"{"id":2,"cmd":"privacy_get_profile"}"#).unwrap();
        assert_eq!(r.request, Request::PrivacyGetProfile { reveal: false });
        assert!(!r.request.requires_admin() && !r.request.is_mutating());
        let reveal = Request::PrivacyGetProfile { reveal: true };
        assert!(reveal.requires_admin() && reveal.is_mutating());
        assert!(Request::SetNetworkTrust {
            network_id: "gw:00:11:22:33:44:55".into(),
            trusted: true
        }
        .requires_admin());
        assert!(!Request::SetNetworkTrust {
            network_id: "gw:00:11:22:33:44:55".into(),
            trusted: false
        }
        .requires_admin());
        assert!(!Request::VpnConnect.requires_admin() && Request::VpnConnect.is_mutating());
        assert!(Request::VpnDisconnect.requires_admin());
        assert!(!Request::VpnStatus.is_mutating());
        assert!(Request::ResolveAlert {
            alert_id: 1,
            action: AlertAction::ResumeProcess
        }
        .requires_admin());
        assert!(!Request::ResolveAlert {
            alert_id: 1,
            action: AlertAction::KillProcess
        }
        .requires_admin());
        let r: RequestEnvelope = serde_json::from_str(
            r#"{"id":3,"cmd":"privacy_update_request","request_id":"r","status":"completed"}"#,
        )
        .unwrap();
        assert!(matches!(
            r.request,
            Request::PrivacyUpdateRequest {
                status: RemovalStatus::Completed,
                note: None,
                ..
            }
        ));
        let line = String::from_utf8(encode_line(&DaemonEvent::Vpn(VpnStatus::default())).unwrap())
            .unwrap();
        assert!(line.starts_with(r#"{"event":"vpn","data":{"#));
    }

    #[test]
    fn mutating_classification() {
        assert!(!Request::Status.is_mutating());
        assert!(Request::SetDns { enabled: true }.is_mutating());
        assert!(Request::Restore {
            entry_id: "x".into(),
            allow: false
        }
        .is_mutating());
    }

    #[test]
    fn server_messages_disambiguate() {
        let ev = DaemonEvent::ScanFinished(ScanJobSummary {
            job_id: "j".into(),
            origin: ScanOrigin::Manual,
            paths: vec![],
            state: JobState::Finished,
            started_at: 1,
            finished_at: Some(2),
            files_scanned: 3,
            bytes_scanned: 4,
            threats: 0,
            errors: 0,
            current_path: None,
        });
        let line = String::from_utf8(encode_line(&ev).unwrap()).unwrap();
        assert!(line.starts_with(r#"{"event":"scan_finished","data":{"#));
        match serde_json::from_str::<ServerMessage>(line.trim_end()).unwrap() {
            ServerMessage::Event(e) => assert_eq!(e, ev),
            _ => panic!("expected event"),
        }
        let resp = ResponseEnvelope::ok(
            9,
            &PingResponse {
                version: "0.1.0".into(),
                protocol: 1,
            },
        );
        let line = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<ServerMessage>(&line).unwrap() {
            ServerMessage::Response(r) => {
                let p: PingResponse = r.into_result().unwrap();
                assert_eq!(p.protocol, 1);
            }
            _ => panic!("expected response"),
        }
    }
}
