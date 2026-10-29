//! Kill switch: pf rules in the `com.apple/250.Parabellum` anchor.
//!
//! The stock `/etc/pf.conf` evaluates `anchor "com.apple/*"`, so rules loaded into a child anchor apply
//! without editing any system file. pf itself is enabled with a reference token (`pfctl -E`, released with
//! `pfctl -X <token>`), so other users of pf (e.g. Internet Sharing) are not disturbed. The token and the
//! anchor name are saved in `killswitch.json` for crash recovery.
//!
//! Policy (outbound only; replies to allowed traffic are stateful): loopback, the tunnel interfaces, DHCP
//! v4/v6, ICMPv6 neighbour discovery, the VPN server IPs (any protocol / port) and — with `allow_lan` — the
//! private, link-local and multicast ranges; everything else is refused (`block return`: applications fail
//! fast instead of hanging).

use crate::fsutil;
use crate::sys::{System, CMD_TIMEOUT, PFCTL};
use crate::VpnError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// pf anchor holding the rules.
pub const ANCHOR: &str = "com.apple/250.Parabellum";
/// Stock pf configuration (loaded only if the main ruleset lacks the `com.apple/*` anchor hook).
pub const PF_CONF: &str = "/etc/pf.conf";
const RULES_FILE: &str = "killswitch.pf";
const STATE_FILE: &str = "killswitch.json";

/// What the rules must let through.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KillSwitchRules {
    /// Tunnel interfaces (`utunN`): the VPN's own plus the system's existing ones.
    pub tunnel_interfaces: Vec<String>,
    /// VPN server addresses.
    pub server_ips: Vec<IpAddr>,
    pub allow_lan: bool,
}

fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes().all(|b| b.is_ascii_alphanumeric())
        && s.as_bytes()[0].is_ascii_alphabetic()
}

/// Render the anchor rules (pure).
pub fn render_rules(r: &KillSwitchRules) -> String {
    let mut out = String::from(
        "# Parabellum kill switch (generated; removed when the VPN is not wanted)\n\
         pass quick on lo0 all\n",
    );
    let mut ifs: Vec<&String> = r
        .tunnel_interfaces
        .iter()
        .filter(|i| valid_ifname(i))
        .collect();
    ifs.sort();
    ifs.dedup();
    for i in ifs {
        out.push_str(&format!("pass quick on {i} all\n"));
    }
    out.push_str(
        "pass out quick inet proto udp from any port 68 to any port 67\n\
         pass in quick inet proto udp from any port 67 to any port 68\n\
         pass out quick inet6 proto udp from any port 546 to any port 547\n\
         pass in quick inet6 proto udp from any port 547 to any port 546\n\
         pass quick inet6 proto icmp6 all icmp6-type { routersol, routeradv, neighbrsol, neighbradv, redir }\n",
    );
    let mut ips = r.server_ips.clone();
    ips.sort();
    ips.dedup();
    for ip in ips {
        let fam = if ip.is_ipv4() { "inet" } else { "inet6" };
        out.push_str(&format!("pass out quick {fam} from any to {ip}\n"));
    }
    if r.allow_lan {
        out.push_str(
            "pass out quick inet from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }\n\
             pass out quick inet6 from any to { fe80::/10, fc00::/7, ff00::/8 }\n",
        );
    }
    out.push_str("block return out quick all\n");
    out
}

/// Crash-recovery record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KillSwitchRecord {
    pub anchor: String,
    /// `pfctl -E` reference token, if we enabled pf.
    #[serde(default)]
    pub token: Option<String>,
    pub applied_at: i64,
}

/// `Token : 1234567890` in `pfctl -E` output.
pub fn parse_token(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case("token"))
            .then(|| v.trim().to_string())
            .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// The main ruleset hooks the `com.apple/*` anchors (`pfctl -s rules`).
pub fn main_has_apple_anchor(out: &str) -> bool {
    out.lines()
        .any(|l| l.trim_start().starts_with("anchor \"com.apple/*\""))
}

/// Applies / removes the anchor rules.
pub struct KillSwitch {
    sys: Arc<dyn System>,
    dir: PathBuf,
    /// Rules currently loaded (to skip identical reloads).
    applied: std::sync::Mutex<Option<String>>,
}

impl KillSwitch {
    pub fn new(sys: Arc<dyn System>, dir: &Path) -> Self {
        Self {
            sys,
            dir: dir.to_path_buf(),
            applied: std::sync::Mutex::new(None),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    /// Rules are loaded.
    pub fn is_applied(&self) -> bool {
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    async fn pfctl(&self, args: &[&str]) -> Result<crate::sys::CmdOutput, VpnError> {
        let out = self
            .sys
            .run(PFCTL, args, CMD_TIMEOUT)
            .await
            .map_err(VpnError::Failed)?;
        Ok(out)
    }

    /// Load `rules` (no-op when identical to the loaded ones) and make sure pf is enabled and evaluates the
    /// anchor.
    pub async fn apply(&self, rules: &str, now: i64) -> Result<(), VpnError> {
        if !self.sys.is_macos() {
            return Err(VpnError::Unavailable(
                "coupe-circuit indisponible (macOS uniquement)".into(),
            ));
        }
        if self
            .applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref()
            == Some(rules)
        {
            return Ok(());
        }
        let path = self.dir.join(RULES_FILE);
        fsutil::write_private(&path, rules.as_bytes())
            .map_err(|e| VpnError::Failed(format!("règles pf : {e}")))?;
        let path_s = path.to_string_lossy().to_string();
        let out = self.pfctl(&["-a", ANCHOR, "-f", &path_s]).await?;
        if !out.success() {
            return Err(VpnError::Failed(format!(
                "pfctl a refusé les règles : {}",
                last_line(&out.combined())
            )));
        }
        // Enable pf once (reference counted) and remember the token.
        let mut record: KillSwitchRecord = fsutil::read_json(&self.state_path())
            .ok()
            .flatten()
            .unwrap_or_default();
        if record.token.is_none() {
            let out = self.pfctl(&["-E"]).await?;
            record.token = parse_token(&out.combined());
            if record.token.is_none() {
                tracing::warn!(output = %out.combined(), "pfctl -E returned no token");
            }
        }
        record.anchor = ANCHOR.into();
        record.applied_at = now;
        fsutil::write_json(&self.state_path(), &record)
            .map_err(|e| VpnError::Failed(format!("état du coupe-circuit : {e}")))?;
        // The anchor is only evaluated if the main ruleset hooks com.apple/*.
        let main = self.pfctl(&["-s", "rules"]).await?;
        if !main_has_apple_anchor(&main.stdout) {
            tracing::warn!("pf main ruleset lacks the com.apple anchor hook: loading /etc/pf.conf");
            let out = self.pfctl(&["-f", PF_CONF]).await?;
            let main = self.pfctl(&["-s", "rules"]).await?;
            if !out.success() || !main_has_apple_anchor(&main.stdout) {
                let _ = self.remove().await;
                return Err(VpnError::Failed(
                    "pf n'évalue pas l'ancre com.apple (configuration /etc/pf.conf modifiée ?)"
                        .into(),
                ));
            }
        }
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = Some(rules.to_string());
        Ok(())
    }

    /// Flush the anchor and release our pf reference (fail open). Idempotent.
    pub async fn remove(&self) -> Result<(), VpnError> {
        let had = self
            .applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .is_some();
        let record: Option<KillSwitchRecord> = fsutil::read_json(&self.state_path()).ok().flatten();
        if !self.sys.is_macos() {
            return Ok(());
        }
        if !had && record.is_none() {
            return Ok(());
        }
        let mut errors = Vec::new();
        match self.pfctl(&["-a", ANCHOR, "-F", "all"]).await {
            Ok(o) if o.success() => {}
            Ok(o) => errors.push(last_line(&o.combined())),
            Err(e) => errors.push(e.to_string()),
        }
        if let Some(token) = record.and_then(|r| r.token) {
            match self.pfctl(&["-X", &token]).await {
                Ok(o) if o.success() => {}
                // An unknown token (reboot) is not an error.
                Ok(o) => tracing::debug!(output = %o.combined(), "pfctl -X"),
                Err(e) => errors.push(e.to_string()),
            }
        }
        let _ = fsutil::remove(&self.state_path());
        let _ = fsutil::remove(&self.dir.join(RULES_FILE));
        if errors.is_empty() {
            Ok(())
        } else {
            Err(VpnError::Failed(format!(
                "retrait du coupe-circuit incomplet : {}",
                errors.join(" ; ")
            )))
        }
    }

    /// Startup: whatever a previous run left is removed (the service re-applies what is wanted). The anchor
    /// is flushed even without a record (crash between load and save).
    pub async fn recover(&self) {
        if !self.sys.is_macos() {
            return;
        }
        let record: Option<KillSwitchRecord> = fsutil::read_json(&self.state_path()).ok().flatten();
        if record.is_some() {
            tracing::warn!("kill switch left by a previous run: removing it");
        }
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = Some(String::new());
        if let Err(e) = self.remove().await {
            tracing::warn!(error = %e, "kill switch recovery");
        }
    }
}

fn last_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && !l.contains("ALTQ"))
        .unwrap_or("erreur inconnue")
        .chars()
        .take(300)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeSystem;

    #[test]
    fn rules_text() {
        let r = KillSwitchRules {
            tunnel_interfaces: vec![
                "utun4".into(),
                "utun0".into(),
                "bad name".into(),
                "utun4".into(),
            ],
            server_ips: vec![
                "203.0.113.7".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
            allow_lan: true,
        };
        let t = render_rules(&r);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[1], "pass quick on lo0 all");
        assert_eq!(lines[2], "pass quick on utun0 all");
        assert_eq!(lines[3], "pass quick on utun4 all");
        assert!(!t.contains("bad name"));
        assert!(t.contains("pass out quick inet from any to 203.0.113.7\n"));
        assert!(t.contains("pass out quick inet6 from any to 2001:db8::1\n"));
        assert!(t.contains("192.168.0.0/16"));
        assert!(t.contains("icmp6-type { routersol"));
        assert_eq!(*lines.last().unwrap(), "block return out quick all");
        let no_lan = render_rules(&KillSwitchRules {
            allow_lan: false,
            ..r
        });
        assert!(!no_lan.contains("192.168.0.0/16"));
        assert!(no_lan.contains("port 67"));
    }

    #[test]
    fn parsers() {
        assert_eq!(
            parse_token("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 6286225592545306079\n"),
            Some("6286225592545306079".into())
        );
        assert_eq!(parse_token("pf already enabled"), None);
        assert!(main_has_apple_anchor(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
        ));
        assert!(!main_has_apple_anchor("pass all\n"));
    }

    #[tokio::test]
    async fn apply_and_remove_with_token() {
        let d = tempfile::tempdir().unwrap();
        let sys = FakeSystem::macos();
        sys.respond(
            PFCTL,
            &["-a", ANCHOR, "-f"],
            0,
            "",
            "No ALTQ support in kernel\n",
        );
        sys.respond(PFCTL, &["-E"], 0, "", "pf enabled\nToken : 42\n");
        sys.respond(
            PFCTL,
            &["-s", "rules"],
            0,
            "anchor \"com.apple/*\" all\n",
            "",
        );
        sys.respond(
            PFCTL,
            &["-a", ANCHOR, "-F", "all"],
            0,
            "",
            "rules cleared\n",
        );
        sys.respond(PFCTL, &["-X", "42"], 0, "", "pf disabled\n");
        let ks = KillSwitch::new(sys.clone(), d.path());
        let rules = render_rules(&KillSwitchRules::default());
        ks.apply(&rules, 10).await.unwrap();
        assert!(ks.is_applied());
        let rec: KillSwitchRecord = fsutil::read_json(&d.path().join(STATE_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(rec.token.as_deref(), Some("42"));
        // Same rules: nothing re-run.
        let n = sys.calls().len();
        ks.apply(&rules, 11).await.unwrap();
        assert_eq!(sys.calls().len(), n);
        // Different rules: reload only, pf not enabled twice.
        ks.apply(&format!("{rules}#x\n"), 12).await.unwrap();
        assert_eq!(sys.count(PFCTL, &["-E"]), 1);
        ks.remove().await.unwrap();
        assert!(!ks.is_applied());
        assert_eq!(sys.count(PFCTL, &["-X", "42"]), 1);
        assert!(!d.path().join(STATE_FILE).exists());
        // Idempotent.
        ks.remove().await.unwrap();
        assert_eq!(sys.count(PFCTL, &["-X", "42"]), 1);
    }

    #[tokio::test]
    async fn loads_pf_conf_when_hook_missing_and_fails_open() {
        let d = tempfile::tempdir().unwrap();
        let sys = FakeSystem::macos();
        sys.respond(PFCTL, &["-a", ANCHOR, "-f"], 0, "", "");
        sys.respond(PFCTL, &["-E"], 0, "", "Token : 7\n");
        sys.respond(PFCTL, &["-s", "rules"], 0, "", "");
        sys.respond(PFCTL, &["-f", PF_CONF], 0, "", "");
        sys.respond(PFCTL, &["-a", ANCHOR, "-F", "all"], 0, "", "");
        sys.respond(PFCTL, &["-X", "7"], 0, "", "");
        let ks = KillSwitch::new(sys.clone(), d.path());
        let err = ks
            .apply("block return out quick all\n", 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("com.apple"));
        assert_eq!(sys.count(PFCTL, &["-f", PF_CONF]), 1);
        assert_eq!(sys.count(PFCTL, &["-a", ANCHOR, "-F", "all"]), 1);
        assert!(!ks.is_applied());
    }

    #[tokio::test]
    async fn recover_flushes_stale_state_and_linux_is_unavailable() {
        let d = tempfile::tempdir().unwrap();
        fsutil::write_json(
            &d.path().join(STATE_FILE),
            &KillSwitchRecord {
                anchor: ANCHOR.into(),
                token: Some("9".into()),
                applied_at: 1,
            },
        )
        .unwrap();
        let sys = FakeSystem::macos();
        sys.respond(PFCTL, &["-a", ANCHOR, "-F", "all"], 0, "", "");
        sys.respond(PFCTL, &["-X", "9"], 1, "", "pfctl: bad token\n");
        let ks = KillSwitch::new(sys.clone(), d.path());
        ks.recover().await;
        assert_eq!(sys.count(PFCTL, &["-X", "9"]), 1);
        assert!(!d.path().join(STATE_FILE).exists());

        let linux = FakeSystem::linux();
        let ks = KillSwitch::new(linux, d.path());
        assert!(matches!(
            ks.apply("x", 1).await,
            Err(VpnError::Unavailable(_))
        ));
        ks.remove().await.unwrap();
    }
}
