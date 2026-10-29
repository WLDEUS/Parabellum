//! Outgoing mail: RFC 5322 message (lettre builder, UTF-8 plain text) and SMTP submission (STARTTLS on
//! any port but 465, implicit TLS on 465; rustls with the Mozilla root store).

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use pb_core::config::DataRemovalConfig;
use std::time::Duration;

/// SMTP account (from `DataRemovalConfig`).
#[derive(Clone, PartialEq, Eq)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    /// Display name of the sender (the identity's full name).
    pub from_name: String,
}

impl std::fmt::Debug for SmtpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("from_address", &self.from_address)
            .finish_non_exhaustive()
    }
}

impl SmtpSettings {
    pub fn from_config(cfg: &DataRemovalConfig, from_name: &str) -> Result<Self, String> {
        if cfg.smtp_host.trim().is_empty() || cfg.from_address.trim().is_empty() {
            return Err("compte SMTP incomplet (serveur et adresse d'expédition requis)".into());
        }
        Ok(Self {
            host: cfg.smtp_host.trim().to_string(),
            port: cfg.smtp_port,
            username: cfg.smtp_username.trim().to_string(),
            password: cfg.smtp_password.clone().unwrap_or_default(),
            from_address: cfg.from_address.trim().to_string(),
            from_name: from_name.trim().to_string(),
        })
    }
}

/// One message to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Sends mail (real SMTP in production, a fake in tests).
#[async_trait]
pub trait MailSender: Send + Sync + 'static {
    async fn send(&self, smtp: &SmtpSettings, mail: &OutgoingMail) -> Result<(), String>;
}

fn mailbox(name: &str, addr: &str) -> Result<Mailbox, String> {
    let address = addr
        .trim()
        .parse()
        .map_err(|e| format!("adresse invalide {addr} : {e}"))?;
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    Ok(Mailbox::new(
        if name.trim().is_empty() {
            None
        } else {
            Some(name.trim().to_string())
        },
        address,
    ))
}

/// Build the message: From / Reply-To = the configured sender, To = the broker, Message-ID, UTF-8 text.
pub fn build_message(smtp: &SmtpSettings, mail: &OutgoingMail) -> Result<Message, String> {
    let from = mailbox(&smtp.from_name, &smtp.from_address)?;
    let to = mailbox("", &mail.to)?;
    let subject: String = mail.subject.chars().filter(|c| !c.is_control()).collect();
    Message::builder()
        .from(from.clone())
        .reply_to(from)
        .to(to)
        .subject(subject)
        .message_id(None)
        .header(ContentType::TEXT_PLAIN)
        .body(mail.body.replace("\r\n", "\n").replace('\n', "\r\n"))
        .map_err(|e| format!("message invalide : {e}"))
}

/// lettre over rustls.
#[derive(Debug, Default, Clone, Copy)]
pub struct LettreSender;

#[async_trait]
impl MailSender for LettreSender {
    async fn send(&self, smtp: &SmtpSettings, mail: &OutgoingMail) -> Result<(), String> {
        let msg = build_message(smtp, mail)?;
        let builder = if smtp.port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
        }
        .map_err(|e| format!("serveur SMTP {} : {e}", smtp.host))?;
        let mut builder = builder
            .port(smtp.port)
            .timeout(Some(Duration::from_secs(60)));
        if !smtp.username.is_empty() {
            builder = builder.credentials(Credentials::new(
                smtp.username.clone(),
                smtp.password.clone(),
            ));
        }
        let transport = builder.build();
        transport
            .send(msg)
            .await
            .map(|_| ())
            .map_err(|e| format!("envoi SMTP refusé : {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_headers() {
        let s = SmtpSettings {
            host: "smtp.example.com".into(),
            port: 587,
            username: "u".into(),
            password: "secret".into(),
            from_address: "q@example.fr".into(),
            from_name: "Camille Été".into(),
        };
        assert!(!format!("{s:?}").contains("secret"));
        let m = OutgoingMail {
            to: "dpo@broker.com".into(),
            subject: "Demande d'effacement (article 17 du RGPD)".into(),
            body: "Bonjour,\nété\n".into(),
        };
        let msg = build_message(&s, &m).unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("To: dpo@broker.com"));
        assert!(raw.contains("Reply-To: "));
        assert!(raw.contains("Message-ID: <"));
        assert!(raw.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(raw.contains("q@example.fr"));
        let bad = OutgoingMail {
            to: "not an address".into(),
            ..m
        };
        assert!(build_message(&s, &bad).is_err());
    }
}
