//! Email aliases: addy.io (`POST /api/v1/aliases`, `Authorization: Bearer`, <https://app.addy.io/docs/>) and
//! SimpleLogin (`POST /api/alias/random/new`, `Authentication` header,
//! <https://github.com/simple-login/app/blob/master/docs/api.md>). Both are open source and self-hostable.

use pb_core::config::{is_email, AliasConfig, AliasProvider};
use pb_core::model::EmailAlias;
use serde::Deserialize;
use std::time::Duration;

pub const ADDY_DEFAULT: &str = "https://app.addy.io";
pub const SIMPLELOGIN_DEFAULT: &str = "https://app.simplelogin.io";
/// addy.io shared domain used when `aliases.domain` is empty (the API requires a domain).
pub const ADDY_DEFAULT_DOMAIN: &str = "anonaddy.me";

/// Base URL of the configured provider (config value or public instance), without trailing slash.
pub fn base_url(cfg: &AliasConfig) -> Option<String> {
    let base = if cfg.base_url.trim().is_empty() {
        match cfg.provider {
            AliasProvider::None => return None,
            AliasProvider::Addy => ADDY_DEFAULT,
            AliasProvider::SimpleLogin => SIMPLELOGIN_DEFAULT,
        }
    } else {
        cfg.base_url.trim()
    };
    Some(base.trim_end_matches('/').to_string())
}

/// The label as a hostname hint for SimpleLogin (`example.com`), when it looks like one.
pub fn hostname_hint(label: &str) -> Option<String> {
    let l = label.trim().to_ascii_lowercase();
    let l = l
        .strip_prefix("https://")
        .or_else(|| l.strip_prefix("http://"))
        .unwrap_or(&l)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    (l.contains('.') && pb_core::config::is_host_or_ip(&l)).then_some(l)
}

#[derive(Debug, Deserialize)]
struct AddyResponse {
    data: AddyAlias,
}

#[derive(Debug, Deserialize)]
struct AddyAlias {
    id: serde_json::Value,
    email: String,
    #[serde(default = "yes")]
    active: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct SlAlias {
    id: serde_json::Value,
    email: String,
    #[serde(default = "yes")]
    enabled: bool,
    creation_timestamp: Option<i64>,
}

fn id_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Parse an addy.io `201` body.
pub fn parse_addy(body: &[u8], label: &str, now: i64) -> Result<EmailAlias, String> {
    let r: AddyResponse =
        serde_json::from_slice(body).map_err(|e| format!("réponse addy.io illisible : {e}"))?;
    if !is_email(&r.data.email) {
        return Err(format!(
            "addy.io a renvoyé une adresse invalide : {}",
            r.data.email
        ));
    }
    Ok(EmailAlias {
        id: id_string(&r.data.id),
        email: r.data.email,
        label: label.to_string(),
        provider: AliasProvider::Addy,
        created_at: now,
        active: r.data.active,
    })
}

/// Parse a SimpleLogin `201` body.
pub fn parse_simplelogin(body: &[u8], label: &str, now: i64) -> Result<EmailAlias, String> {
    let r: SlAlias =
        serde_json::from_slice(body).map_err(|e| format!("réponse SimpleLogin illisible : {e}"))?;
    if !is_email(&r.email) {
        return Err(format!(
            "SimpleLogin a renvoyé une adresse invalide : {}",
            r.email
        ));
    }
    Ok(EmailAlias {
        id: id_string(&r.id),
        email: r.email,
        label: label.to_string(),
        provider: AliasProvider::SimpleLogin,
        created_at: r.creation_timestamp.unwrap_or(now),
        active: r.enabled,
    })
}

fn api_error(status: u16, body: &[u8]) -> String {
    let detail = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str().map(str::to_string))
        })
        .unwrap_or_default();
    match status {
        401 | 403 => "clé d'API refusée par le service d'alias".into(),
        429 => "trop de requêtes au service d'alias, réessayez plus tard".into(),
        _ if detail.is_empty() => format!("service d'alias : HTTP {status}"),
        _ => format!(
            "service d'alias : HTTP {status} ({})",
            detail.chars().take(200).collect::<String>()
        ),
    }
}

/// Create one alias labelled `label`.
pub async fn create(cfg: &AliasConfig, label: &str, now: i64) -> Result<EmailAlias, String> {
    let label: String = label
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    if label.is_empty() {
        return Err("indiquez à quoi sert l'alias (nom du site)".into());
    }
    let base = base_url(cfg).ok_or("aucun service d'alias configuré (aliases.provider)")?;
    if !base.starts_with("https://") {
        return Err("aliases.base_url doit utiliser https".into());
    }
    let key = cfg
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or("clé d'API du service d'alias absente (aliases.api_key)")?;
    let http = reqwest::Client::builder()
        .user_agent(crate::breach::USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    match cfg.provider {
        AliasProvider::None => Err("aucun service d'alias configuré (aliases.provider)".into()),
        AliasProvider::Addy => {
            let domain = if cfg.domain.trim().is_empty() {
                ADDY_DEFAULT_DOMAIN
            } else {
                cfg.domain.trim()
            };
            let resp = http
                .post(format!("{base}/api/v1/aliases"))
                .bearer_auth(key)
                .header("X-Requested-With", "XMLHttpRequest")
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&serde_json::json!({
                    "domain": domain,
                    "description": label,
                    "format": "random_words",
                }))
                .send()
                .await
                .map_err(|e| format!("addy.io injoignable : {e}"))?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await.map_err(|e| e.to_string())?;
            if !(200..300).contains(&status) {
                return Err(api_error(status, &body));
            }
            parse_addy(&body, &label, now)
        }
        AliasProvider::SimpleLogin => {
            let mut u = reqwest::Url::parse(&format!("{base}/api/alias/random/new"))
                .map_err(|e| e.to_string())?;
            u.query_pairs_mut().append_pair("mode", "word");
            if let Some(h) = hostname_hint(&label) {
                u.query_pairs_mut().append_pair("hostname", &h);
            }
            let resp = http
                .post(u)
                .header("Authentication", key)
                .json(&serde_json::json!({ "note": label }))
                .send()
                .await
                .map_err(|e| format!("SimpleLogin injoignable : {e}"))?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await.map_err(|e| e.to_string())?;
            if !(200..300).contains(&status) {
                return Err(api_error(status, &body));
            }
            parse_simplelogin(&body, &label, now)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers() {
        let mut c = AliasConfig::default();
        assert_eq!(base_url(&c), None);
        c.provider = AliasProvider::Addy;
        assert_eq!(base_url(&c).as_deref(), Some(ADDY_DEFAULT));
        c.base_url = "https://addy.home.lan/".into();
        assert_eq!(base_url(&c).as_deref(), Some("https://addy.home.lan"));
        assert_eq!(
            hostname_hint("https://www.Example.com/login").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(hostname_hint("Ma banque"), None);
    }

    #[test]
    fn parse_bodies() {
        let addy = br#"{"data":{"id":"50c9e585-e7f5-41c4-9016-9014c15454bc","user_id":"x","local_part":"rude.dog",
            "domain":"anonaddy.me","email":"rude.dog@anonaddy.me","active":true,"description":"example.com"}}"#;
        let a = parse_addy(addy, "example.com", 7).unwrap();
        assert_eq!(a.email, "rude.dog@anonaddy.me");
        assert_eq!(a.id, "50c9e585-e7f5-41c4-9016-9014c15454bc");
        assert_eq!(a.created_at, 7);
        let sl = br#"{"id":42,"email":"happy_cat@simplelogin.com","enabled":true,"creation_timestamp":1700000000,"note":"x"}"#;
        let s = parse_simplelogin(sl, "x", 7).unwrap();
        assert_eq!(
            (s.id.as_str(), s.created_at, s.provider),
            ("42", 1_700_000_000, AliasProvider::SimpleLogin)
        );
        assert!(parse_simplelogin(br#"{"id":1,"email":"nope"}"#, "x", 0).is_err());
        assert!(api_error(401, b"").contains("refusée"));
        assert!(api_error(400, br#"{"error":"bad domain"}"#).contains("bad domain"));
    }
}
