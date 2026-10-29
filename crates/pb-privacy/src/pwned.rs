//! Pwned Passwords (k-anonymity range API, <https://haveibeenpwned.com/API/v3#PwnedPasswords>): only the first
//! 5 hex characters of the password's SHA-1 leave the Mac; responses are padded (`Add-Padding: true`). Used by
//! the CLI / app as the user; nothing is stored and passwords never reach the daemon.

use crate::PrivacyError;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

pub const RANGE_API: &str = "https://api.pwnedpasswords.com/range/";
/// Max size of a password export CSV.
const MAX_CSV: u64 = 64 * 1024 * 1024;

/// Uppercase hex SHA-1.
pub fn sha1_hex(password: &str) -> String {
    hex::encode_upper(Sha1::digest(password.as_bytes()))
}

/// Count for `suffix` (35 uppercase hex chars) in a range response (`SUFFIX:COUNT` lines; padding lines
/// have a count of 0).
pub fn parse_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.trim().eq_ignore_ascii_case(suffix))
        .and_then(|(_, c)| c.trim().parse().ok())
        .unwrap_or(0)
}

fn client() -> Result<reqwest::Client, PrivacyError> {
    reqwest::Client::builder()
        .user_agent(crate::breach::USER_AGENT)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| PrivacyError::Failed(e.to_string()))
}

async fn fetch_range(
    http: &reqwest::Client,
    base: &str,
    prefix: &str,
) -> Result<String, PrivacyError> {
    let resp = http
        .get(format!("{base}{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|e| PrivacyError::Unavailable(format!("Pwned Passwords injoignable : {e}")))?;
    if !resp.status().is_success() {
        return Err(PrivacyError::Failed(format!(
            "Pwned Passwords : HTTP {}",
            resp.status().as_u16()
        )));
    }
    resp.text()
        .await
        .map_err(|e| PrivacyError::Failed(e.to_string()))
}

/// How many times the password appears in known breaches (0 = not found).
pub async fn check_password(password: &str) -> Result<u64, PrivacyError> {
    check_password_at(RANGE_API, password).await
}

/// [`check_password`] against another range endpoint (tests, mirrors).
pub async fn check_password_at(base: &str, password: &str) -> Result<u64, PrivacyError> {
    if password.is_empty() {
        return Err(PrivacyError::Invalid("mot de passe vide".into()));
    }
    let h = sha1_hex(password);
    let (prefix, suffix) = h.split_at(5);
    let body = fetch_range(&client()?, base, prefix).await?;
    Ok(parse_range(&body, suffix))
}

/// One entry of a password export, without its password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CsvResult {
    /// Entry title (`name` / `Title`), when the export has one.
    pub name: String,
    pub url: String,
    pub username: String,
    /// Times the password appears in breaches (0 = not found).
    pub count: u64,
}

/// Minimal RFC 4180 CSV reader (quoted fields, `""` escapes, newlines inside quotes, CRLF).
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                if !(row.len() == 1 && row[0].is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Column indexes of a password export header (Chrome, Safari, Firefox, Bitwarden, 1Password…).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsvColumns {
    pub name: Option<usize>,
    pub url: Option<usize>,
    pub username: Option<usize>,
    pub password: usize,
}

pub fn detect_columns(header: &[String]) -> Option<CsvColumns> {
    let find = |names: &[&str]| {
        header.iter().position(|h| {
            let h = h.trim().to_ascii_lowercase();
            names.contains(&h.as_str())
        })
    };
    Some(CsvColumns {
        name: find(&["name", "title"]),
        url: find(&[
            "url",
            "login_uri",
            "website",
            "origin",
            "origin_url",
            "web site",
        ]),
        username: find(&[
            "username",
            "login_username",
            "user",
            "login",
            "email",
            "user name",
        ]),
        password: find(&["password", "login_password", "pass"])?,
    })
}

/// Check every password of an export file. Each distinct SHA-1 prefix is queried once.
pub async fn check_csv(path: &Path) -> Result<Vec<CsvResult>, PrivacyError> {
    check_csv_at(RANGE_API, path).await
}

pub async fn check_csv_at(base: &str, path: &Path) -> Result<Vec<CsvResult>, PrivacyError> {
    let md = std::fs::metadata(path)
        .map_err(|e| PrivacyError::NotFound(format!("{} : {e}", path.display())))?;
    if !md.is_file() || md.len() > MAX_CSV {
        return Err(PrivacyError::Invalid(
            "fichier CSV absent ou trop volumineux".into(),
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| PrivacyError::Invalid(format!("CSV illisible (UTF-8 attendu) : {e}")))?;
    let rows = parse_csv(&text);
    let (header, rows) = rows
        .split_first()
        .ok_or_else(|| PrivacyError::Invalid("CSV vide".into()))?;
    let cols = detect_columns(header).ok_or_else(|| {
        PrivacyError::Invalid("colonne « password » introuvable dans l'en-tête du CSV".into())
    })?;
    let get =
        |r: &[String], i: Option<usize>| i.and_then(|i| r.get(i)).cloned().unwrap_or_default();
    // (entry, hash) without keeping passwords around longer than needed.
    let mut entries: Vec<(CsvResult, String)> = Vec::new();
    for r in rows {
        let Some(pw) = r.get(cols.password).filter(|p| !p.is_empty()) else {
            continue;
        };
        entries.push((
            CsvResult {
                name: get(r, cols.name),
                url: get(r, cols.url),
                username: get(r, cols.username),
                count: 0,
            },
            sha1_hex(pw),
        ));
    }
    let mut by_prefix: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, (_, h)) in entries.iter().enumerate() {
        by_prefix.entry(h[..5].to_string()).or_default().push(i);
    }
    let http = client()?;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for (prefix, idx) in &by_prefix {
        let body = fetch_range(&http, base, prefix).await?;
        for &i in idx {
            let suffix = &entries[i].1[5..];
            counts.insert(entries[i].1.clone(), parse_range(&body, suffix));
        }
    }
    Ok(entries
        .into_iter()
        .map(|(mut e, h)| {
            e.count = counts.get(&h).copied().unwrap_or(0);
            e
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_and_range() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let h = sha1_hex("password");
        assert_eq!(h, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\n";
        assert_eq!(parse_range(body, &h[5..]), 9_659_365);
        assert_eq!(parse_range(body, "0000000000000000000000000000000000A"), 0);
    }

    #[test]
    fn csv_formats() {
        let chrome = "name,url,username,password,note\r\nex,https://ex.com/,q,\"p,a\"\"ss\",\"multi\nline\"\r\n,,,,\r\n";
        let rows = parse_csv(chrome);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1][3], "p,a\"ss");
        assert_eq!(rows[1][4], "multi\nline");
        let c = detect_columns(&rows[0]).unwrap();
        assert_eq!(
            (c.name, c.url, c.username, c.password),
            (Some(0), Some(1), Some(2), 3)
        );
        let safari = parse_csv("\u{feff}Title,URL,Username,Password,Notes,OTPAuth\n");
        assert_eq!(detect_columns(&safari[0]).unwrap().password, 3);
        let bw = parse_csv("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n");
        let c = detect_columns(&bw[0]).unwrap();
        assert_eq!((c.url, c.username, c.password), (Some(7), Some(8), 9));
        assert!(detect_columns(&parse_csv("a,b\n")[0]).is_none());
    }
}
