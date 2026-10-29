//! VPN services configured in macOS (`scutil --nc`): list, status, start, stop. Used by the `external`
//! backend (Shadowrocket, WireGuard app, sing-box for Apple…).
//!
//! `scutil --nc list` line format:
//! ```text
//! * (Connected)      6F3C…-… VPN (com.wireguard.macos) "Mullvad Paris"     [VPN/com.wireguard.macos]
//! ```
//! `scutil --nc status <name>`: first line is the state; the extended status may carry `InterfaceName`.

use crate::sys::{System, CMD_TIMEOUT, SCUTIL};
use crate::VpnError;
use pb_core::model::{ExternalVpnService, VpnState};

/// Map an scutil state word.
pub fn parse_state(word: &str) -> VpnState {
    match word.trim().to_ascii_lowercase().as_str() {
        "connected" => VpnState::Connected,
        "connecting" => VpnState::Connecting,
        "disconnecting" => VpnState::Disconnecting,
        _ => VpnState::Disconnected,
    }
}

/// Parse `scutil --nc list`.
pub fn parse_list(out: &str) -> Vec<ExternalVpnService> {
    let mut v = Vec::new();
    for line in out.lines() {
        let l = line.trim_start().trim_start_matches('*').trim_start();
        let Some(rest) = l.strip_prefix('(') else {
            continue;
        };
        let Some((state, rest)) = rest.split_once(')') else {
            continue;
        };
        // Name: between the first `"` and the last `"` before the trailing `[type]`.
        let before_bracket = match rest.rfind('[') {
            Some(i) => &rest[..i],
            None => rest,
        };
        let (Some(a), Some(b)) = (before_bracket.find('"'), before_bracket.rfind('"')) else {
            continue;
        };
        if b <= a {
            continue;
        }
        let name = before_bracket[a + 1..b].to_string();
        if name.is_empty() {
            continue;
        }
        let provider = rest
            .rfind('[')
            .and_then(|i| rest[i + 1..].split_once(']'))
            .map(|(t, _)| t.trim())
            .and_then(|t| t.split_once('/').map(|(_, p)| p.trim().to_string()))
            .filter(|p| !p.is_empty())
            .or_else(|| {
                // `VPN (com.provider)` before the name.
                let head = &before_bracket[..a];
                let i = head.find('(')?;
                let j = head[i..].find(')')? + i;
                Some(head[i + 1..j].trim().to_string()).filter(|p| !p.is_empty())
            });
        v.push(ExternalVpnService {
            name,
            provider,
            state: parse_state(state),
        });
    }
    v
}

/// Parsed `scutil --nc status <name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub state: VpnState,
    pub interface: Option<String>,
}

pub fn parse_status(out: &str) -> Option<ServiceStatus> {
    let first = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    if first.to_ascii_lowercase().starts_with("no service") {
        return None;
    }
    let state = parse_state(first);
    let interface = out.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == "InterfaceName")
            .then(|| v.trim().to_string())
            .filter(|i| i.starts_with("utun") || i.starts_with("ipsec") || i.starts_with("ppp"))
    });
    Some(ServiceStatus { state, interface })
}

fn check_name(name: &str) -> Result<(), VpnError> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(VpnError::Invalid("nom de service VPN invalide".into()));
    }
    Ok(())
}

/// `scutil --nc list`.
pub async fn list(sys: &dyn System) -> Vec<ExternalVpnService> {
    if !sys.is_macos() {
        return vec![];
    }
    match sys.run(SCUTIL, &["--nc", "list"], CMD_TIMEOUT).await {
        Ok(out) => parse_list(&out.stdout),
        Err(e) => {
            tracing::warn!(error = %e, "scutil --nc list");
            vec![]
        }
    }
}

/// Status of one service (`NotFound` when macOS does not know it).
pub async fn status(sys: &dyn System, name: &str) -> Result<ServiceStatus, VpnError> {
    check_name(name)?;
    if !sys.is_macos() {
        return Err(VpnError::Unavailable(
            "scutil indisponible (macOS uniquement)".into(),
        ));
    }
    let out = sys
        .run(SCUTIL, &["--nc", "status", name], CMD_TIMEOUT)
        .await
        .map_err(VpnError::Failed)?;
    parse_status(&out.combined())
        .ok_or_else(|| VpnError::NotFound(format!("service VPN « {name} » introuvable dans macOS")))
}

fn looks_failed(out: &crate::sys::CmdOutput) -> bool {
    let t = out.combined().to_ascii_lowercase();
    !out.success() || t.contains("no service") || t.contains("error") || t.contains("not permitted")
}

/// `scutil --nc start|stop <name>`: as root first, then in the console user's session (per-user VPN
/// configurations from App Store apps).
pub async fn control(sys: &dyn System, name: &str, start: bool) -> Result<(), VpnError> {
    check_name(name)?;
    if !sys.is_macos() {
        return Err(VpnError::Unavailable(
            "scutil indisponible (macOS uniquement)".into(),
        ));
    }
    let verb = if start { "start" } else { "stop" };
    let args = ["--nc", verb, name];
    let first = sys.run(SCUTIL, &args, CMD_TIMEOUT).await;
    match &first {
        Ok(out) if !looks_failed(out) => return Ok(()),
        Ok(out) => {
            tracing::debug!(output = %out.combined(), "scutil as root failed, retrying as the user")
        }
        Err(e) => tracing::debug!(error = %e, "scutil as root failed, retrying as the user"),
    }
    let second = sys.run_as_console_user(SCUTIL, &args, CMD_TIMEOUT).await;
    match second {
        Ok(out) if !looks_failed(&out) => Ok(()),
        Ok(out) => Err(VpnError::Failed(format!(
            "scutil --nc {verb} « {name} » : {}",
            out.combined().trim()
        ))),
        Err(e) => Err(VpnError::Failed(format!(
            "scutil --nc {verb} « {name} » : {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeSystem;

    const LIST: &str = "Available network connection services in the current set (*=enabled):\n\
* (Disconnected)   2B5F2F3A-7E5C-4C8F-9E1D-0F7C3D1A2B3C VPN (com.liguangming.Shadowrocket) \"Shadowrocket\"                  [VPN/com.liguangming.Shadowrocket]\n\
* (Connected)      6F3C2A11-1111-2222-3333-444455556666 VPN (com.wireguard.macos) \"Mullvad \\\"Paris\\\"\"   [VPN/com.wireguard.macos]\n\
  (Disconnected)   0A0B0C0D-0000-0000-0000-000000000001 PPP --> L2TP          \"Work L2TP\"            [PPP/L2TP]\n\
garbage line\n";

    #[test]
    fn list_parsing() {
        let l = parse_list(LIST);
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].name, "Shadowrocket");
        assert_eq!(
            l[0].provider.as_deref(),
            Some("com.liguangming.Shadowrocket")
        );
        assert_eq!(l[0].state, VpnState::Disconnected);
        assert_eq!(l[1].state, VpnState::Connected);
        assert_eq!(l[1].name, "Mullvad \\\"Paris\\\"");
        assert_eq!(l[2].provider.as_deref(), Some("L2TP"));
    }

    #[test]
    fn status_parsing() {
        let s = parse_status("Connected\nExtended Status <dictionary> {\n  IPv4 : <dictionary> {\n    InterfaceName : utun5\n  }\n  Status : 2\n}\n").unwrap();
        assert_eq!(s.state, VpnState::Connected);
        assert_eq!(s.interface.as_deref(), Some("utun5"));
        let s = parse_status("Connecting\n").unwrap();
        assert_eq!(s.state, VpnState::Connecting);
        assert!(parse_status("No service\n").is_none());
        assert_eq!(
            parse_status("Invalid\n").unwrap().state,
            VpnState::Disconnected
        );
    }

    #[tokio::test]
    async fn control_falls_back_to_user_session() {
        let sys = FakeSystem::macos();
        sys.respond(SCUTIL, &["--nc", "start"], 0, "", "No service\n");
        sys.respond("asuser:/usr/sbin/scutil", &["--nc", "start"], 0, "", "");
        control(sys.as_ref(), "Shadowrocket", true).await.unwrap();
        assert_eq!(
            sys.count(
                "asuser:/usr/sbin/scutil",
                &["--nc", "start", "Shadowrocket"]
            ),
            1
        );
        sys.respond(SCUTIL, &["--nc", "stop"], 0, "", "");
        control(sys.as_ref(), "Shadowrocket", false).await.unwrap();
        assert_eq!(sys.count("asuser:/usr/sbin/scutil", &["--nc", "stop"]), 0);
        assert!(control(sys.as_ref(), "", true).await.is_err());
        sys.respond(SCUTIL, &["--nc", "status"], 0, "No service\n", "");
        assert!(matches!(
            status(sys.as_ref(), "X").await,
            Err(VpnError::NotFound(_))
        ));
        let linux = FakeSystem::linux();
        assert!(list(linux.as_ref()).await.is_empty());
        assert!(matches!(
            control(linux.as_ref(), "X", true).await,
            Err(VpnError::Unavailable(_))
        ));
    }
}
