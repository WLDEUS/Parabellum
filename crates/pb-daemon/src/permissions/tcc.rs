//! TCC databases: service catalogue (French labels, impact, System Settings pane), reading the `access`
//! table from a private copy, and risk scoring of each grant.
//!
//! `access` (macOS 11+): `service, client, client_type (0 bundle id / 1 path), auth_value (0 denied,
//! 1 unknown, 2 allowed, 3 limited), auth_reason, …, indirect_object_identifier (Automation target,
//! `UNUSED` otherwise), …, last_modified`. Only these columns are read, so older and newer layouts work.

use pb_core::model::{Severity, SigningInfo, TccAuthValue};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// System-wide database (root-owned, needs Full Disk Access).
pub const SYSTEM_DB: &str = "/Library/Application Support/com.apple.TCC/TCC.db";
/// Per-user database, relative to the home folder.
pub const USER_DB: &str = "Library/Application Support/com.apple.TCC/TCC.db";
/// Copies larger than this are refused.
pub const MAX_DB: u64 = 64 * 1024 * 1024;
const SETTINGS: &str = "x-apple.systempreferences:com.apple.preference.security?";

/// One known TCC service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceInfo {
    pub id: &'static str,
    pub label: &'static str,
    /// 3 = can read everything / control the Mac, 2 = sensitive, 1 = personal data, 0 = minor.
    pub impact: u8,
    /// `Privacy_*` anchor of the System Settings pane.
    pub anchor: &'static str,
}

const fn s(id: &'static str, label: &'static str, impact: u8, anchor: &'static str) -> ServiceInfo {
    ServiceInfo {
        id,
        label,
        impact,
        anchor,
    }
}

pub const SERVICES: &[ServiceInfo] = &[
    s(
        "kTCCServiceAccessibility",
        "Accessibilité",
        3,
        "Privacy_Accessibility",
    ),
    s(
        "kTCCServiceScreenCapture",
        "Enregistrement de l'écran",
        3,
        "Privacy_ScreenCapture",
    ),
    s(
        "kTCCServiceSystemPolicyAllFiles",
        "Accès complet au disque",
        3,
        "Privacy_AllFiles",
    ),
    s(
        "kTCCServiceListenEvent",
        "Surveillance de l'entrée (clavier)",
        3,
        "Privacy_ListenEvent",
    ),
    s(
        "kTCCServicePostEvent",
        "Contrôle du clavier et de la souris",
        2,
        "Privacy_Accessibility",
    ),
    s(
        "kTCCServiceEndpointSecurityClient",
        "Client Endpoint Security",
        3,
        "Privacy_AllFiles",
    ),
    s(
        "kTCCServiceDeveloperTool",
        "Outils de développement",
        2,
        "Privacy_DevTools",
    ),
    s(
        "kTCCServiceAppleEvents",
        "Automatisation",
        2,
        "Privacy_Automation",
    ),
    s(
        "kTCCServiceSystemPolicyAppBundles",
        "Gestion des apps",
        2,
        "Privacy_AppBundles",
    ),
    s("kTCCServiceCamera", "Caméra", 2, "Privacy_Camera"),
    s("kTCCServiceMicrophone", "Micro", 2, "Privacy_Microphone"),
    s(
        "kTCCServiceSystemPolicySysAdminFiles",
        "Fichiers d'administration",
        2,
        "Privacy_AllFiles",
    ),
    s("kTCCServicePhotos", "Photos", 1, "Privacy_Photos"),
    s("kTCCServiceAddressBook", "Contacts", 1, "Privacy_Contacts"),
    s("kTCCServiceCalendar", "Calendrier", 1, "Privacy_Calendars"),
    s("kTCCServiceReminders", "Rappels", 1, "Privacy_Reminders"),
    s(
        "kTCCServiceSystemPolicyDesktopFolder",
        "Dossier Bureau",
        1,
        "Privacy_FilesAndFolders",
    ),
    s(
        "kTCCServiceSystemPolicyDocumentsFolder",
        "Dossier Documents",
        1,
        "Privacy_FilesAndFolders",
    ),
    s(
        "kTCCServiceSystemPolicyDownloadsFolder",
        "Dossier Téléchargements",
        1,
        "Privacy_FilesAndFolders",
    ),
    s(
        "kTCCServiceSystemPolicyNetworkVolumes",
        "Volumes réseau",
        1,
        "Privacy_FilesAndFolders",
    ),
    s(
        "kTCCServiceSystemPolicyRemovableVolumes",
        "Volumes amovibles",
        1,
        "Privacy_FilesAndFolders",
    ),
    s(
        "kTCCServiceSystemPolicyAppData",
        "Données d'autres apps",
        1,
        "Privacy_AppData",
    ),
    s(
        "kTCCServiceLocation",
        "Localisation",
        1,
        "Privacy_LocationServices",
    ),
    s(
        "kTCCServicePhotosAdd",
        "Ajout à Photos",
        0,
        "Privacy_Photos",
    ),
    s(
        "kTCCServiceBluetoothAlways",
        "Bluetooth",
        0,
        "Privacy_Bluetooth",
    ),
    s(
        "kTCCServiceMediaLibrary",
        "Médias et Apple Music",
        0,
        "Privacy_Media",
    ),
    s(
        "kTCCServiceSpeechRecognition",
        "Reconnaissance vocale",
        0,
        "Privacy_SpeechRecognition",
    ),
    s(
        "kTCCServiceFileProviderDomain",
        "Fournisseurs de fichiers",
        0,
        "Privacy_FilesAndFolders",
    ),
    s("kTCCServiceUbiquity", "iCloud", 0, "Privacy"),
];

/// Catalogue entry (unknown services: raw name without the prefix, impact 0).
pub fn service_info(id: &str) -> ServiceInfo {
    SERVICES
        .iter()
        .copied()
        .find(|s| s.id == id)
        .unwrap_or(ServiceInfo {
            id: "",
            label: "",
            impact: 0,
            anchor: "Privacy",
        })
}

pub fn service_label(id: &str) -> String {
    let i = service_info(id);
    if i.label.is_empty() {
        id.trim_start_matches("kTCCService").to_string()
    } else {
        i.label.to_string()
    }
}

pub fn settings_url(id: &str) -> String {
    format!("{SETTINGS}{}", service_info(id).anchor)
}

/// One row of `access`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TccRow {
    pub service: String,
    pub client: String,
    pub client_is_path: bool,
    pub auth: TccAuthValue,
    pub target: Option<String>,
    pub last_modified: Option<i64>,
}

pub fn auth_value(v: i64) -> TccAuthValue {
    match v {
        0 => TccAuthValue::Denied,
        2 => TccAuthValue::Allowed,
        3 => TccAuthValue::Limited,
        _ => TccAuthValue::Unknown,
    }
}

/// Max rows read from one database.
pub const MAX_ROWS: usize = 5_000;

/// Rows of the `access` table of a database file (our private copy).
pub fn read_rows(db: &Path) -> Result<Vec<TccRow>, String> {
    let c = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    let _ = c.execute_batch("PRAGMA trusted_schema = OFF;");
    let mut st = c
        .prepare(
            "SELECT service, client, client_type, auth_value, indirect_object_identifier, last_modified \
             FROM access LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([MAX_ROWS as i64], |r| {
            let target: Option<String> = r.get(4).ok();
            Ok(TccRow {
                service: r.get::<_, String>(0)?,
                client: r.get::<_, String>(1)?,
                client_is_path: r.get::<_, i64>(2).unwrap_or(0) == 1,
                auth: auth_value(r.get::<_, i64>(3).unwrap_or(1)),
                target: target.filter(|t| !t.is_empty() && t != "UNUSED"),
                last_modified: r.get::<_, i64>(5).ok().filter(|t| *t > 0),
            })
        })
        .map_err(|e| e.to_string())?;
    let mut v = Vec::new();
    for r in rows {
        match r {
            Ok(row) if row.client.len() <= 1024 && row.service.len() <= 128 => v.push(row),
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(v)
}

/// Copy the database (and its `-wal`, so recent grants are seen) into `work` and read it. The source files
/// are read with [`super::safefile::read_no_follow`] (owner `owner` or root).
pub fn read_db(src: &Path, owner: u32, work: &Path) -> Result<Option<Vec<TccRow>>, String> {
    let Some(main) =
        super::safefile::read_no_follow(src, owner, MAX_DB).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Scratch(work.join(format!("tcc-{}", uuid::Uuid::new_v4().simple())));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir.0)
            .map_err(|e| e.to_string())?;
    }
    let copy = dir.0.join("TCC.db");
    std::fs::write(&copy, &main).map_err(|e| e.to_string())?;
    let mut wal_name = src.as_os_str().to_os_string();
    wal_name.push("-wal");
    if let Ok(Some(wal)) = super::safefile::read_no_follow(Path::new(&wal_name), owner, MAX_DB) {
        std::fs::write(dir.0.join("TCC.db-wal"), wal).map_err(|e| e.to_string())?;
    }
    read_rows(&copy).map(Some)
}

/// Facts used to score a grant.
#[derive(Debug, Clone, Default)]
pub struct RiskInput<'a> {
    pub service: &'a str,
    pub auth: TccAuthValue,
    pub client: &'a str,
    pub client_is_path: bool,
    pub installed: Option<bool>,
    pub signing: Option<&'a SigningInfo>,
}

/// Risk of a grant and why (French).
pub fn score(i: &RiskInput<'_>) -> (Severity, Vec<String>) {
    let info = service_info(i.service);
    let label = service_label(i.service);
    let mut reasons = Vec::new();
    if i.auth == TccAuthValue::Denied {
        return (Severity::Info, vec!["Accès refusé".into()]);
    }
    if i.installed == Some(false) {
        reasons.push("App introuvable sur ce Mac : autorisation orpheline à réinitialiser".into());
        return (Severity::Low, reasons);
    }
    let apple = i.signing.map(|s| s.apple).unwrap_or(false)
        || (i.signing.is_none() && !i.client_is_path && i.client.starts_with("com.apple."));
    if apple {
        return (Severity::Info, vec!["Composant d'Apple".into()]);
    }
    let untrusted = match i.signing {
        Some(s) if !s.signed => {
            reasons.push("App non signée".into());
            true
        }
        Some(s) if s.adhoc => {
            reasons.push("App signée « ad hoc » (sans identité de développeur)".into());
            true
        }
        Some(s) if !s.valid => {
            reasons.push("Signature invalide (app modifiée ?)".into());
            true
        }
        Some(s) if s.notarized == Some(false) => {
            reasons.push("App non notarisée par Apple".into());
            true
        }
        Some(s) => {
            if let Some(t) = &s.team_id {
                reasons.push(format!("Développeur identifié ({t})"));
            }
            false
        }
        None => {
            reasons.push("Signature non vérifiée".into());
            false
        }
    };
    if i.client_is_path {
        reasons.push("Exécutable isolé (hors app)".into());
    }
    let sev = match (info.impact, untrusted) {
        (3, true) => Severity::High,
        (2, true) => Severity::Medium,
        (_, true) => Severity::Low,
        (3, false) => Severity::Medium,
        (2, false) => Severity::Low,
        _ => Severity::Info,
    };
    if info.impact >= 2 {
        reasons.push(format!(
            "{label} : accès puissant, à n'accorder qu'aux apps indispensables"
        ));
    }
    (sev, reasons)
}

/// Stable grant id.
pub fn grant_id(system: bool, service: &str, client: &str, target: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let scope = if system { "system" } else { "user" };
    let h =
        Sha256::digest(format!("{scope}|{service}|{client}|{}", target.unwrap_or("")).as_bytes());
    hex::encode(h)[..16].to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Synthetic database with the macOS 14 `access` schema.
    pub fn make_db(path: &Path, rows: &[(&str, &str, i64, i64, &str, i64)]) {
        let c = Connection::open(path).unwrap();
        c.execute_batch(
            "CREATE TABLE admin (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);
             INSERT INTO admin VALUES ('version', 30);
             CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL,
               auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL,
               csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER,
               indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB,
               flags INTEGER, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
               pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminded INTEGER NOT NULL DEFAULT 0,
               PRIMARY KEY (service, client, client_type, indirect_object_identifier));",
        )
        .unwrap();
        for (service, client, ctype, auth, target, ts) in rows {
            c.execute(
                "INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, \
                 indirect_object_identifier, last_modified) VALUES (?1, ?2, ?3, ?4, 2, 1, ?5, ?6)",
                rusqlite::params![service, client, ctype, auth, target, ts],
            )
            .unwrap();
        }
    }

    #[test]
    fn reads_access_rows() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("TCC.db");
        make_db(
            &p,
            &[
                (
                    "kTCCServiceCamera",
                    "us.zoom.xos",
                    0,
                    2,
                    "UNUSED",
                    1_760_000_000,
                ),
                (
                    "kTCCServiceAppleEvents",
                    "com.example.Script",
                    0,
                    2,
                    "com.apple.finder",
                    1_760_000_100,
                ),
                (
                    "kTCCServiceMicrophone",
                    "/usr/local/bin/rec",
                    1,
                    0,
                    "UNUSED",
                    0,
                ),
            ],
        );
        let rows = read_rows(&p).unwrap();
        assert_eq!(rows.len(), 3);
        let ae = rows
            .iter()
            .find(|r| r.service == "kTCCServiceAppleEvents")
            .unwrap();
        assert_eq!(ae.target.as_deref(), Some("com.apple.finder"));
        assert_eq!(ae.auth, TccAuthValue::Allowed);
        let mic = rows.iter().find(|r| r.client_is_path).unwrap();
        assert_eq!(mic.auth, TccAuthValue::Denied);
        assert_eq!(mic.last_modified, None);
        // Through a private copy.
        let work = tempfile::tempdir().unwrap();
        let src = d.path().canonicalize().unwrap().join("TCC.db");
        let rows2 = read_db(&src, crate::system::euid(), work.path())
            .unwrap()
            .unwrap();
        assert_eq!(rows2, rows);
        assert!(read_db(&src.with_file_name("none.db"), 0, work.path())
            .unwrap()
            .is_none());
        assert!(
            std::fs::read_dir(work.path()).unwrap().next().is_none(),
            "copy removed"
        );
        assert!(read_rows(&d.path().join("missing-table.db")).is_err());
    }

    fn signing(signed: bool, adhoc: bool, apple: bool, notarized: Option<bool>) -> SigningInfo {
        SigningInfo {
            signed,
            valid: signed,
            adhoc,
            team_id: (!adhoc && signed && !apple).then(|| "ABCDE12345".to_string()),
            identifier: None,
            authority: None,
            notarized,
            apple,
        }
    }

    #[test]
    fn risk_scoring() {
        let base = |svc, sig| RiskInput {
            service: svc,
            auth: TccAuthValue::Allowed,
            client: "com.example.app",
            client_is_path: false,
            installed: Some(true),
            signing: sig,
        };
        let adhoc = signing(true, true, false, None);
        let devid = signing(true, false, false, Some(true));
        let apple = signing(true, false, true, None);
        let unsigned = signing(false, false, false, None);
        assert_eq!(
            score(&base("kTCCServiceAccessibility", Some(&adhoc))).0,
            Severity::High
        );
        assert_eq!(
            score(&base("kTCCServiceScreenCapture", Some(&unsigned))).0,
            Severity::High
        );
        assert_eq!(
            score(&base("kTCCServiceSystemPolicyAllFiles", Some(&devid))).0,
            Severity::Medium
        );
        assert_eq!(
            score(&base("kTCCServiceCamera", Some(&devid))).0,
            Severity::Low
        );
        assert_eq!(
            score(&base("kTCCServiceCamera", Some(&adhoc))).0,
            Severity::Medium
        );
        assert_eq!(
            score(&base("kTCCServiceAddressBook", Some(&devid))).0,
            Severity::Info
        );
        assert_eq!(
            score(&base("kTCCServiceAccessibility", Some(&apple))).0,
            Severity::Info
        );
        let mut i = base("kTCCServiceAccessibility", Some(&adhoc));
        i.auth = TccAuthValue::Denied;
        assert_eq!(score(&i).0, Severity::Info);
        let mut i = base("kTCCServiceAccessibility", None);
        i.installed = Some(false);
        let (sev, why) = score(&i);
        assert_eq!(sev, Severity::Low);
        assert!(why[0].contains("orpheline"));
        let mut i = base("kTCCServiceListenEvent", None);
        i.client = "com.apple.Terminal";
        assert_eq!(score(&i).0, Severity::Info);
        let (sev, why) = score(&base("kTCCServiceAccessibility", Some(&adhoc)));
        assert_eq!(sev, Severity::High);
        assert!(why.iter().any(|w| w.contains("ad hoc")));
    }

    #[test]
    fn catalogue() {
        assert_eq!(service_label("kTCCServiceCamera"), "Caméra");
        assert_eq!(service_label("kTCCServiceFocusStatus"), "FocusStatus");
        assert!(settings_url("kTCCServiceListenEvent").ends_with("?Privacy_ListenEvent"));
        assert_eq!(grant_id(true, "a", "b", None).len(), 16);
        assert_ne!(
            grant_id(true, "a", "b", None),
            grant_id(false, "a", "b", None)
        );
    }
}
