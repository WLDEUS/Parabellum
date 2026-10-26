//! osquery hunting packs, run one-shot with `osqueryi --json` at background priority.
//!
//! The official macOS package installs `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`
//! and a symlink `/usr/local/bin/osqueryi` to it; the same binary runs the shell when started as
//! `osqueryi` or with `-S`. Pack format (also used by the DB bundle's `osquery/hunting.json`):
//! `{"queries": {"<name>": {"query": "<sql>", "interval": <secs>, "description": "<text>"}}}`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::{run_prepared, tool_command};
use crate::MonitorError;

/// Canonical binary of the official macOS package (run with `-S`).
pub const OSQUERYD_APP: &str = "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd";
/// Candidates, in order of preference.
const CANDIDATES: &[&str] = &[
    OSQUERYD_APP,
    "/usr/local/bin/osqueryi",
    "/opt/osquery/bin/osqueryi",
    "/usr/bin/osqueryi",
];
const TASKPOLICY: &str = "/usr/sbin/taskpolicy";
/// Max rows kept per query and max stdout per query.
const MAX_ROWS: usize = 5000;
const MAX_OUTPUT: usize = 16 * 1024 * 1024;

/// Result of one pack query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntResult {
    /// Query name (key in the pack).
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rows (all values as strings; `null` -> empty string).
    #[serde(default)]
    pub rows: Vec<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One query of a pack.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PackQuery {
    pub query: String,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Pack {
    queries: BTreeMap<String, PackQuery>,
}

/// Parses a pack; queries are returned sorted by name.
pub fn parse_pack(pack_json: &str) -> Result<Vec<(String, PackQuery)>, MonitorError> {
    let p: Pack = serde_json::from_str(pack_json)
        .map_err(|e| MonitorError::Parse(format!("osquery pack: {e}")))?;
    Ok(p.queries.into_iter().take(256).collect())
}

/// Parses `osqueryi --json` output (array of objects); scalars are stringified, `null` -> "".
pub fn parse_osquery_json(stdout: &[u8]) -> Result<Vec<BTreeMap<String, String>>, MonitorError> {
    let text = String::from_utf8_lossy(stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| MonitorError::Parse(format!("osqueryi output: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| MonitorError::Parse("osqueryi output is not an array".into()))?;
    Ok(arr
        .iter()
        .take(MAX_ROWS)
        .filter_map(|row| row.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    let s = match v {
                        serde_json::Value::Null => String::new(),
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), s)
                })
                .collect()
        })
        .collect())
}

/// A candidate binary is used only if it (after symlink resolution) is a regular file owned by
/// root and not writable by group / others (it runs as root).
fn trusted_binary(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(path).ok()?;
    let meta = std::fs::metadata(&real).ok()?;
    (meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.mode() & 0o111 != 0)
        .then_some(real)
}

/// Locates an osquery shell binary (see module docs). Returns the path to execute.
pub fn find_osqueryi() -> Option<PathBuf> {
    CANDIDATES.iter().map(Path::new).find_map(trusted_binary)
}

/// Program and arguments to run one SQL statement (`-S` when the binary is `osqueryd`; wrapped
/// in `taskpolicy -b` on macOS for background QoS).
pub(crate) fn command_line(osqueryi: &Path, sql: &str, taskpolicy: bool) -> (String, Vec<String>) {
    let mut args: Vec<String> = Vec::new();
    let bin = osqueryi.to_string_lossy().into_owned();
    if osqueryi
        .file_name()
        .map(|n| n == "osqueryd")
        .unwrap_or(false)
    {
        args.push("-S".into());
    }
    args.push("--json".into());
    args.push(sql.to_string());
    if taskpolicy {
        let mut wrapped = vec!["-b".to_string(), bin];
        wrapped.extend(args);
        (TASKPOLICY.to_string(), wrapped)
    } else {
        (bin, args)
    }
}

/// Runs every query of `pack_json` sequentially (each with `timeout`). Never fails as a whole:
/// pack or query errors are reported in [`HuntResult::error`]. Blocking: call from
/// `spawn_blocking`.
pub fn run_pack(osqueryi: &Path, pack_json: &str, timeout: Duration) -> Vec<HuntResult> {
    let queries = match parse_pack(pack_json) {
        Ok(q) => q,
        Err(e) => {
            return vec![HuntResult {
                query: "_pack".into(),
                description: None,
                rows: Vec::new(),
                error: Some(e.to_string()),
            }]
        }
    };
    let use_taskpolicy = cfg!(target_os = "macos") && Path::new(TASKPOLICY).is_file();
    queries
        .into_iter()
        .map(|(name, q)| {
            let (program, args) = command_line(osqueryi, &q.query, use_taskpolicy);
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut cmd = tool_command(&program, &arg_refs);
            // osqueryi keeps its shell history / ephemeral DB under $HOME.
            cmd.env("HOME", std::env::temp_dir());
            let result = run_prepared(cmd, "osqueryi", timeout, MAX_OUTPUT);
            let (rows, error) = match result {
                Ok(out) if out.success => match parse_osquery_json(&out.stdout) {
                    Ok(rows) => (rows, out.truncated.then(|| "sortie tronquée".to_string())),
                    Err(e) => (Vec::new(), Some(e.to_string())),
                },
                Ok(out) => (
                    Vec::new(),
                    Some(format!(
                        "osqueryi exit {:?}: {}",
                        out.code,
                        crate::util::clip(out.stderr.trim(), 2000)
                    )),
                ),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };
            HuntResult {
                query: name,
                description: q.description,
                rows,
                error,
            }
        })
        .collect()
}

/// Default macOS hunting pack (osquery 5 schema). Each query returns only suspicious / notable
/// rows; the daemon diffs results between runs (e.g. sudoers or extensions changes).
pub const DEFAULT_HUNTING_PACK: &str = r#"{
  "queries": {
    "launchd_unsigned_programs": {
      "query": "WITH items AS (SELECT label, path, COALESCE(NULLIF(program, ''), split(program_arguments, ' ', 0)) AS prog FROM launchd WHERE path NOT LIKE '/System/%') SELECT items.label, items.path, items.prog AS program, signature.signed, signature.identifier, signature.team_identifier, signature.authority FROM items JOIN signature ON signature.path = items.prog WHERE signature.signed = 0;",
      "interval": 86400,
      "description": "Agents/daemons launchd dont le programme n'est pas signé"
    },
    "processes_binary_deleted": {
      "query": "SELECT pid, name, path, cmdline, uid, parent FROM processes WHERE on_disk = 0;",
      "interval": 86400,
      "description": "Processus dont le binaire a été supprimé du disque"
    },
    "listening_ports_unsigned": {
      "query": "SELECT DISTINCT lp.pid, lp.port, lp.protocol, lp.address, p.name, p.path, s.signed, s.authority FROM listening_ports AS lp JOIN processes AS p USING (pid) JOIN signature AS s ON s.path = p.path WHERE lp.port != 0 AND s.signed = 0;",
      "interval": 86400,
      "description": "Ports en écoute ouverts par des processus non signés"
    },
    "chrome_extensions": {
      "query": "SELECT u.username, ce.browser_type, ce.name, ce.identifier, ce.version, ce.from_webstore, ce.state, ce.permissions, ce.path FROM users AS u CROSS JOIN chrome_extensions AS ce USING (uid);",
      "interval": 86400,
      "description": "Extensions des navigateurs Chromium"
    },
    "safari_extensions": {
      "query": "SELECT u.username, se.name, se.identifier, se.version, se.sdk, se.path FROM users AS u CROSS JOIN safari_extensions AS se USING (uid);",
      "interval": 86400,
      "description": "Extensions Safari"
    },
    "managed_policies": {
      "query": "SELECT domain, uuid, name, value, username, manual FROM managed_policies;",
      "interval": 86400,
      "description": "Préférences imposées par des profils de configuration"
    },
    "third_party_kernel_extensions": {
      "query": "SELECT name, version, path, linked_against FROM kernel_extensions WHERE name NOT LIKE 'com.apple.%';",
      "interval": 86400,
      "description": "Extensions noyau tierces chargées"
    },
    "system_extensions": {
      "query": "SELECT identifier, version, state, category, team, path, mdm_managed FROM system_extensions;",
      "interval": 86400,
      "description": "Extensions système installées"
    },
    "recent_startup_items": {
      "query": "SELECT si.name, si.path, si.type, si.source, si.status, si.username, f.btime FROM startup_items AS si JOIN file AS f ON f.path = si.path WHERE f.btime > (strftime('%s', 'now') - 7 * 86400);",
      "interval": 86400,
      "description": "Éléments de démarrage / ouverture ajoutés ces 7 derniers jours"
    },
    "sip_status": {
      "query": "SELECT config_flag, enabled, enabled_nvram FROM sip_config WHERE config_flag = 'sip';",
      "interval": 86400,
      "description": "État de la protection de l'intégrité du système (SIP)"
    },
    "gatekeeper_status": {
      "query": "SELECT assessments_enabled, dev_id_enabled, version, opaque_version FROM gatekeeper;",
      "interval": 86400,
      "description": "État de Gatekeeper"
    },
    "sudoers_rules": {
      "query": "SELECT source, header, rule_details FROM sudoers WHERE rule_details LIKE '%NOPASSWD%' OR source != '/etc/sudoers';",
      "interval": 86400,
      "description": "Règles sudo sans mot de passe ou hors /etc/sudoers"
    },
    "sudoers_files": {
      "query": "SELECT path, uid, mode, mtime FROM file WHERE path = '/etc/sudoers' OR path LIKE '/etc/sudoers.d/%';",
      "interval": 86400,
      "description": "Fichiers sudoers (date de modification)"
    }
  }
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pack_is_valid() {
        let q = parse_pack(DEFAULT_HUNTING_PACK).unwrap();
        assert!(q.len() >= 10);
        assert!(q.iter().all(|(_, q)| q.query.trim_end().ends_with(';')
            && q.description.is_some()
            && q.interval == Some(86400)));
        assert!(parse_pack("{}").is_err());
    }

    #[test]
    fn parses_output() {
        let rows =
            parse_osquery_json(br#"[{"pid":"12","name":"evil","on_disk":0,"x":null}]"#).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["pid"], "12");
        assert_eq!(rows[0]["on_disk"], "0");
        assert_eq!(rows[0]["x"], "");
        assert!(parse_osquery_json(b"").unwrap().is_empty());
        assert!(parse_osquery_json(b"Error: no such table").is_err());
    }

    #[test]
    fn builds_command_lines() {
        let (p, a) = command_line(Path::new(OSQUERYD_APP), "SELECT 1;", true);
        assert_eq!(p, TASKPOLICY);
        assert_eq!(a, vec!["-b", OSQUERYD_APP, "-S", "--json", "SELECT 1;"]);
        let (p, a) = command_line(Path::new("/usr/local/bin/osqueryi"), "SELECT 1;", false);
        assert_eq!(p, "/usr/local/bin/osqueryi");
        assert_eq!(a, vec!["--json", "SELECT 1;"]);
    }

    #[test]
    fn run_pack_with_fake_shell() {
        // A stand-in "osqueryi" (a shell script) prints a fixed JSON array; checks plumbing.
        let d = tempfile::tempdir().unwrap();
        let fake = d.path().join("osqueryi");
        std::fs::write(&fake, "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\ncase \"$last\" in\n  *fail*) echo 'Error: no such table: nope' >&2; exit 1;;\n  *) echo '[{\"a\":\"1\"},{\"a\":2}]';;\nesac\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pack = r#"{"queries":{"ok":{"query":"SELECT a FROM t;","description":"d"},"ko":{"query":"SELECT fail FROM nope;"}}}"#;
        let res = run_pack(&fake, pack, Duration::from_secs(10));
        assert_eq!(res.len(), 2);
        let ok = res.iter().find(|r| r.query == "ok").unwrap();
        assert_eq!(ok.rows.len(), 2);
        assert_eq!(ok.rows[1]["a"], "2");
        assert_eq!(ok.description.as_deref(), Some("d"));
        let ko = res.iter().find(|r| r.query == "ko").unwrap();
        assert!(ko.error.as_deref().unwrap().contains("no such table"));
        let bad = run_pack(&fake, "not json", Duration::from_secs(1));
        assert!(bad[0].error.is_some());
        // an untrusted (non-root-owned or world-writable) binary is never selected
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_binary(&fake).is_none());
    }
}
