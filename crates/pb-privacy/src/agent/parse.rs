//! Parsing of one raw message (RFC 5322 / MIME) into the few fields the agent needs. Everything here is
//! untrusted input written by a third party: lengths are bounded and control characters dropped.

use mail_parser::MessageParser;

/// Characters of the text body kept for classification.
pub const MAX_BODY_CHARS: usize = 6000;

/// The fields of one answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedMail {
    pub uid: u32,
    pub message_id: Option<String>,
    /// `In-Reply-To` + `References` ids.
    pub refs: Vec<String>,
    /// Lowercase sender address.
    pub from: String,
    pub from_domain: String,
    pub subject: String,
    pub date: Option<i64>,
    /// Plain text (HTML converted by the parser), truncated to [`MAX_BODY_CHARS`].
    pub body: String,
    /// `Auto-Submitted: auto-replied`, `X-Autoreply`, out-of-office subjects.
    pub auto_reply: bool,
    /// Delivery status notification (`multipart/report; report-type=delivery-status`, mailer-daemon).
    pub bounce: bool,
    /// The receiving server reported a failed DKIM / DMARC check and no passing DKIM signature.
    pub auth_failed: bool,
}

fn clean(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
        .collect()
}

fn one_line(s: &str, max: usize) -> String {
    clean(s, max * 2)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default()
}

const AUTO_REPLY_SUBJECTS: &[&str] = &[
    "out of office",
    "out-of-office",
    "automatic reply",
    "auto reply",
    "autoreply",
    "réponse automatique",
    "reponse automatique",
    "absence",
    "abwesenheit",
    "automatische antwort",
];

/// Parse a raw message; `None` when it is not a message at all.
pub fn parse(uid: u32, raw: &[u8]) -> Option<ParsedMail> {
    let m = MessageParser::default().parse(raw)?;
    let from = m
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .map(|a| a.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut refs: Vec<String> = Vec::new();
    for v in [m.in_reply_to(), m.references()] {
        if let Some(list) = v.as_text_list() {
            for r in list.iter().take(50) {
                refs.push(one_line(r, 300));
            }
        }
    }
    let subject = one_line(m.subject().unwrap_or(""), 300);
    let mut body: String = m
        .body_text(0)
        .map(|b| clean(&b, MAX_BODY_CHARS))
        .unwrap_or_default();
    if body.trim().is_empty() {
        body = m
            .body_html(0)
            .map(|b| clean(&strip_tags(&b), MAX_BODY_CHARS))
            .unwrap_or_default();
    }
    let header = |name: &str| m.header_raw(name).map(|v| v.trim().to_ascii_lowercase());
    let auto_submitted = header("Auto-Submitted").unwrap_or_default();
    let lower_subject = subject.to_lowercase();
    let auto_reply = auto_submitted.starts_with("auto-replied")
        || header("X-Autoreply").is_some_and(|v| v.starts_with("yes"))
        || header("X-Autorespond").is_some()
        || AUTO_REPLY_SUBJECTS
            .iter()
            .any(|s| lower_subject.starts_with(s));
    let report = m
        .header("Content-Type")
        .and_then(|h| h.as_content_type())
        .is_some_and(|ct| {
            ct.ctype().eq_ignore_ascii_case("multipart")
                && ct
                    .subtype()
                    .is_some_and(|s| s.eq_ignore_ascii_case("report"))
                && ct
                    .attribute("report-type")
                    .is_some_and(|r| r.eq_ignore_ascii_case("delivery-status"))
        });
    let local = from.split('@').next().unwrap_or("");
    let daemon_sender = matches!(local, "mailer-daemon" | "postmaster");
    let bounce = report
        || (daemon_sender
            && [
                "undeliver",
                "delivery status",
                "delivery failure",
                "failure notice",
                "non remis",
                "échec de la remise",
                "returned mail",
            ]
            .iter()
            .any(|w| lower_subject.contains(w)));
    // Topmost Authentication-Results is the receiving server's verdict.
    let auth = header("Authentication-Results").unwrap_or_default();
    let auth_failed =
        (auth.contains("dmarc=fail") || auth.contains("dkim=fail")) && !auth.contains("dkim=pass");
    Some(ParsedMail {
        uid,
        message_id: m.message_id().map(|i| one_line(i, 300)),
        refs,
        from_domain: domain_of(&from),
        from,
        subject,
        date: m.date().map(|d| d.to_timestamp()),
        body,
        auto_reply,
        bounce,
        auth_failed,
    })
}

/// Crude HTML to text (only used when a message has no text part).
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len().min(64 * 1024));
    let mut in_tag = false;
    for c in html.chars().take(256 * 1024) {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_reply() {
        let raw = b"Message-ID: <abc@broker.example>\r\nIn-Reply-To: <pb.11111111-2222-4333-8444-555555555555.1700000000@me.example>\r\nFrom: DPO <DPO@Broker.example>\r\nSubject: Re: Demande d'effacement [R\xc3\xa9f. PB-11111111]\r\nAuthentication-Results: mx.me.example; dkim=pass header.d=broker.example\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nVos donn\xc3\xa9es ont \xc3\xa9t\xc3\xa9 supprim\xc3\xa9es.\r\n";
        let p = parse(7, raw).unwrap();
        assert_eq!(p.uid, 7);
        assert_eq!(p.from, "dpo@broker.example");
        assert_eq!(p.from_domain, "broker.example");
        assert!(p.subject.contains("PB-11111111"));
        assert!(p.refs[0].contains("pb.11111111-2222"));
        assert!(p.body.contains("supprimées"));
        assert!(!p.auto_reply && !p.bounce && !p.auth_failed);
    }

    #[test]
    fn detects_bounces_auto_replies_and_failed_auth() {
        let dsn = b"From: Mail Delivery System <MAILER-DAEMON@mx.me.example>\r\nSubject: Undelivered Mail Returned to Sender\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nfailed\r\n--x--\r\n";
        assert!(parse(1, dsn).unwrap().bounce);
        let ooo = b"From: a@b.example\r\nSubject: Automatic reply: hello\r\nAuto-Submitted: auto-replied\r\n\r\naway\r\n";
        assert!(parse(2, ooo).unwrap().auto_reply);
        let spoof = b"From: dpo@broker.example\r\nSubject: done\r\nAuthentication-Results: mx; dkim=fail; dmarc=fail\r\n\r\nerased\r\n";
        assert!(parse(3, spoof).unwrap().auth_failed);
    }

    #[test]
    fn html_only_and_control_characters() {
        let raw = b"From: a@b.example\r\nSubject: x\x07y\r\nContent-Type: text/html\r\n\r\n<p>Hello&nbsp;<b>world</b></p>\r\n";
        let p = parse(1, raw).unwrap();
        assert!(p.body.contains("Hello"));
        assert!(p.body.contains("world"));
        assert!(!p.subject.contains('\x07'));
    }
}
