//! Read-only IMAP access to the dedicated mailbox: implicit TLS (rustls, Mozilla roots), `EXAMINE` (the
//! folder is opened read-only, so messages stay unread for you) and `BODY.PEEK` partial fetches.

use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::rustls;

/// Bytes fetched per message (headers + the start of the body are enough to classify).
pub const MAX_MESSAGE_BYTES: u32 = 256 * 1024;
/// First run (or UIDVALIDITY change): only messages of the last days.
pub const FIRST_RUN_DAYS: i64 = 120;
const TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone)]
pub struct ImapSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub mailbox: String,
}

impl std::fmt::Debug for ImapSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("mailbox", &self.mailbox)
            .finish_non_exhaustive()
    }
}

impl ImapSettings {
    pub fn from_config(c: &pb_core::config::MailAgentConfig) -> Result<Self, String> {
        let password = c.imap_password.clone().unwrap_or_default();
        if c.imap_host.trim().is_empty() || c.imap_username.trim().is_empty() || password.is_empty()
        {
            return Err(
                "boîte mail incomplète (serveur IMAP, identifiant et mot de passe d'application)"
                    .into(),
            );
        }
        Ok(Self {
            host: c.imap_host.trim().to_string(),
            port: c.imap_port,
            username: c.imap_username.trim().to_string(),
            password,
            mailbox: c.mailbox.trim().to_string(),
        })
    }
}

/// Result of one fetch.
#[derive(Debug, Default)]
pub struct Fetched {
    pub uid_validity: u32,
    /// `(uid, raw bytes)`, ascending uid.
    pub messages: Vec<(u32, Vec<u8>)>,
}

fn imap_date(ts: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format("%d-%b-%Y").to_string())
        .unwrap_or_else(|| "01-Jan-2020".into())
}

/// New messages after `last_uid` (all messages of the last [`FIRST_RUN_DAYS`] days when the mailbox is new
/// to us or its UIDVALIDITY changed). At most `max`, oldest first.
pub async fn fetch_new(
    s: &ImapSettings,
    known_validity: Option<u32>,
    last_uid: u32,
    max: usize,
    now: i64,
) -> Result<Fetched, String> {
    tokio::time::timeout(TIMEOUT, fetch_inner(s, known_validity, last_uid, max, now))
        .await
        .map_err(|_| format!("IMAP {} : délai dépassé", s.host))?
}

async fn fetch_inner(
    s: &ImapSettings,
    known_validity: Option<u32>,
    last_uid: u32,
    max: usize,
    now: i64,
) -> Result<Fetched, String> {
    let err = |what: &str, e: &dyn std::fmt::Display| format!("IMAP {} : {what} : {e}", s.host);
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| err("TLS", &e))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(s.host.clone())
        .map_err(|e| err("nom de serveur", &e))?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(30),
        TcpStream::connect((s.host.as_str(), s.port)),
    )
    .await
    .map_err(|_| err("connexion", &"délai dépassé"))?
    .map_err(|e| err("connexion", &e))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| err("TLS", &e))?;
    let mut client = async_imap::Client::new(tls);
    client
        .read_response()
        .await
        .map_err(|e| err("accueil", &e))?
        .ok_or_else(|| err("accueil", &"connexion fermée"))?;
    let mut session = client
        .login(&s.username, &s.password)
        .await
        .map_err(|(e, _)| err("identification refusée", &e))?;
    let mailbox = session
        .examine(&s.mailbox)
        .await
        .map_err(|e| err(&format!("dossier {}", s.mailbox), &e))?;
    let validity = mailbox.uid_validity.unwrap_or(0);
    let fresh = known_validity != Some(validity) || last_uid == 0;
    let query = if fresh {
        format!("SINCE {}", imap_date(now - FIRST_RUN_DAYS * 86_400))
    } else {
        format!("UID {}:*", last_uid.saturating_add(1))
    };
    let mut uids: Vec<u32> = session
        .uid_search(&query)
        .await
        .map_err(|e| err("recherche", &e))?
        .into_iter()
        .filter(|u| fresh || *u > last_uid)
        .collect();
    uids.sort_unstable();
    uids.truncate(max);
    let mut messages = Vec::with_capacity(uids.len());
    for chunk in uids.chunks(20) {
        let set = chunk
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut stream = session
            .uid_fetch(&set, format!("(UID BODY.PEEK[]<0.{MAX_MESSAGE_BYTES}>)"))
            .await
            .map_err(|e| err("lecture", &e))?;
        while let Some(f) = stream.next().await {
            let f = f.map_err(|e| err("lecture", &e))?;
            if let (Some(uid), Some(body)) = (f.uid, f.body()) {
                let n = body.len().min(MAX_MESSAGE_BYTES as usize);
                messages.push((uid, body[..n].to_vec()));
            }
        }
    }
    let _ = session.logout().await;
    messages.sort_by_key(|(u, _)| *u);
    Ok(Fetched {
        uid_validity: validity,
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_settings() {
        assert_eq!(imap_date(0), "01-Jan-1970");
        let mut c = pb_core::config::MailAgentConfig::default();
        assert!(ImapSettings::from_config(&c).is_err());
        c.imap_host = "imap.example.com".into();
        c.imap_username = "rgpd@example.com".into();
        c.imap_password = Some("secret".into());
        let s = ImapSettings::from_config(&c).unwrap();
        assert!(!format!("{s:?}").contains("secret"));
    }
}
