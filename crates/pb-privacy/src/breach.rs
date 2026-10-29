//! Data-breach lookups: XposedOrNot (free, no key; <https://xposedornot.com/api_doc>) and Have I Been Pwned v3
//! (API key; <https://haveibeenpwned.com/API/v3>). Only the email address leaves the Mac.

use pb_core::config::BreachProvider;
use serde::Deserialize;
use std::time::Duration;

pub const XON_API: &str = "https://api.xposedornot.com";
pub const HIBP_API: &str = "https://haveibeenpwned.com/api/v3";
pub const USER_AGENT: &str = concat!(
    "Parabellum/",
    env!("CARGO_PKG_VERSION"),
    " (personal macOS antivirus)"
);

/// One breach for one address, as reported by the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub breach: String,
    pub date: Option<String>,
    pub data_classes: Vec<String>,
}

/// Lookup failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// Rate-limited: try again later (seconds, when the provider says).
    RateLimited(Option<u64>),
    Failed(String),
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::RateLimited(Some(s)) => {
                write!(f, "limite de requêtes atteinte, réessayer dans {s} s")
            }
            LookupError::RateLimited(None) => {
                write!(f, "limite de requêtes atteinte, réessayer plus tard")
            }
            LookupError::Failed(m) => f.write_str(m),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// XposedOrNot
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct XonAnalytics {
    #[serde(rename = "ExposedBreaches")]
    exposed: Option<XonExposed>,
}

#[derive(Debug, Deserialize)]
struct XonExposed {
    #[serde(default)]
    breaches_details: Vec<XonBreach>,
}

#[derive(Debug, Deserialize)]
struct XonBreach {
    breach: Option<String>,
    xposed_data: Option<String>,
    xposed_date: Option<serde_json::Value>,
}

/// `GET /v1/breach-analytics?email=` body. Not found: `ExposedBreaches` is `null` (HTTP 200).
pub fn parse_xon_analytics(body: &[u8]) -> Result<Vec<Hit>, String> {
    let doc: XonAnalytics =
        serde_json::from_slice(body).map_err(|e| format!("réponse XposedOrNot illisible : {e}"))?;
    let Some(exp) = doc.exposed else {
        return Ok(vec![]);
    };
    Ok(exp
        .breaches_details
        .into_iter()
        .filter_map(|b| {
            let name = b.breach?.trim().to_string();
            if name.is_empty() {
                return None;
            }
            let date = b.xposed_date.and_then(|v| match v {
                serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
            let data_classes = b
                .xposed_data
                .unwrap_or_default()
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            Some(Hit {
                breach: name,
                date,
                data_classes,
            })
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct XonCheck {
    #[serde(default)]
    breaches: Vec<Vec<String>>,
}

/// `GET /v1/check-email/{email}` body (fallback): `{"breaches": [["A","B"]], …}`.
pub fn parse_xon_check(body: &[u8]) -> Result<Vec<Hit>, String> {
    let doc: XonCheck =
        serde_json::from_slice(body).map_err(|e| format!("réponse XposedOrNot illisible : {e}"))?;
    Ok(doc
        .breaches
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|breach| Hit {
            breach,
            date: None,
            data_classes: vec![],
        })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// Have I Been Pwned
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HibpBreach {
    name: String,
    title: Option<String>,
    breach_date: Option<String>,
    #[serde(default)]
    data_classes: Vec<String>,
}

/// `GET /breachedaccount/{account}?truncateResponse=false` body.
pub fn parse_hibp(body: &[u8]) -> Result<Vec<Hit>, String> {
    let list: Vec<HibpBreach> =
        serde_json::from_slice(body).map_err(|e| format!("réponse HIBP illisible : {e}"))?;
    Ok(list
        .into_iter()
        .map(|b| Hit {
            breach: b.title.filter(|t| !t.trim().is_empty()).unwrap_or(b.name),
            date: b.breach_date,
            data_classes: b.data_classes,
        })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------------------------

/// Base URLs (overridable in tests).
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub xposedornot: String,
    pub hibp: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            xposedornot: XON_API.into(),
            hibp: HIBP_API.into(),
        }
    }
}

fn client() -> Result<reqwest::Client, LookupError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| LookupError::Failed(e.to_string()))
}

fn url_with_segment(base: &str, segments: &[&str]) -> Result<reqwest::Url, LookupError> {
    let mut u = reqwest::Url::parse(base).map_err(|e| LookupError::Failed(e.to_string()))?;
    u.path_segments_mut()
        .map_err(|_| LookupError::Failed("URL de base invalide".into()))?
        .pop_if_empty()
        .extend(segments);
    Ok(u)
}

fn retry_after(resp: &reqwest::Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Breaches of one address with the configured provider.
pub async fn lookup(
    provider: BreachProvider,
    email: &str,
    hibp_key: Option<&str>,
    ep: &Endpoints,
) -> Result<Vec<Hit>, LookupError> {
    let http = client()?;
    match provider {
        BreachProvider::XposedOrNot => {
            let mut u = url_with_segment(&ep.xposedornot, &["v1", "breach-analytics"])?;
            u.query_pairs_mut().append_pair("email", email);
            let resp = http
                .get(u)
                .send()
                .await
                .map_err(|e| LookupError::Failed(format!("XposedOrNot injoignable : {e}")))?;
            match resp.status().as_u16() {
                404 => return Ok(vec![]),
                429 => return Err(LookupError::RateLimited(retry_after(&resp))),
                s if !(200..300).contains(&s) => {
                    return Err(LookupError::Failed(format!("XposedOrNot : HTTP {s}")))
                }
                _ => {}
            }
            let body = resp
                .bytes()
                .await
                .map_err(|e| LookupError::Failed(e.to_string()))?;
            match parse_xon_analytics(&body) {
                Ok(h) => Ok(h),
                Err(_) => {
                    // Unexpected analytics shape: fall back to the simple endpoint (names only).
                    let u = url_with_segment(&ep.xposedornot, &["v1", "check-email", email])?;
                    let resp = http.get(u).send().await.map_err(|e| {
                        LookupError::Failed(format!("XposedOrNot injoignable : {e}"))
                    })?;
                    match resp.status().as_u16() {
                        404 => Ok(vec![]),
                        429 => Err(LookupError::RateLimited(retry_after(&resp))),
                        s if !(200..300).contains(&s) => {
                            Err(LookupError::Failed(format!("XposedOrNot : HTTP {s}")))
                        }
                        _ => {
                            let body = resp
                                .bytes()
                                .await
                                .map_err(|e| LookupError::Failed(e.to_string()))?;
                            parse_xon_check(&body).map_err(LookupError::Failed)
                        }
                    }
                }
            }
        }
        BreachProvider::Hibp => {
            let key = hibp_key
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .ok_or_else(|| {
                    LookupError::Failed(
                        "clé d'API Have I Been Pwned absente (breach.hibp_api_key)".into(),
                    )
                })?;
            let mut u = url_with_segment(&ep.hibp, &["breachedaccount", email])?;
            u.query_pairs_mut().append_pair("truncateResponse", "false");
            let resp = http
                .get(u)
                .header("hibp-api-key", key)
                .send()
                .await
                .map_err(|e| LookupError::Failed(format!("Have I Been Pwned injoignable : {e}")))?;
            match resp.status().as_u16() {
                404 => Ok(vec![]),
                429 => Err(LookupError::RateLimited(retry_after(&resp))),
                401 => Err(LookupError::Failed(
                    "clé d'API Have I Been Pwned refusée".into(),
                )),
                s if !(200..300).contains(&s) => {
                    Err(LookupError::Failed(format!("Have I Been Pwned : HTTP {s}")))
                }
                _ => {
                    let body = resp
                        .bytes()
                        .await
                        .map_err(|e| LookupError::Failed(e.to_string()))?;
                    parse_hibp(&body).map_err(LookupError::Failed)
                }
            }
        }
    }
}

/// Data classes that mean credentials leaked.
pub fn exposes_passwords(classes: &[String]) -> bool {
    classes.iter().any(|c| {
        let l = c.to_lowercase();
        l.contains("password") || l.contains("mot de passe") || l.contains("passwort")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xon_analytics() {
        let body = br#"{"BreachesSummary":{"site":"SweClockers"},"ExposedBreaches":{"breaches_details":[
            {"breach":"SweClockers","domain":"sweclockers.com","xposed_data":"Usernames;Email addresses;Passwords",
             "xposed_date":"2015","xposed_records":254967,"password_risk":"hardtocrack"},
            {"breach":"","xposed_data":"x"},
            {"breach":"Other","xposed_date":2019}]},"BreachMetrics":null}"#;
        let hits = parse_xon_analytics(body).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].breach, "SweClockers");
        assert_eq!(hits[0].date.as_deref(), Some("2015"));
        assert_eq!(
            hits[0].data_classes,
            vec!["Usernames", "Email addresses", "Passwords"]
        );
        assert!(exposes_passwords(&hits[0].data_classes));
        assert_eq!(hits[1].date.as_deref(), Some("2019"));
        let none =
            br#"{"BreachesSummary":{"site":""},"ExposedBreaches":null,"BreachMetrics":null}"#;
        assert!(parse_xon_analytics(none).unwrap().is_empty());
        assert!(parse_xon_analytics(b"[1,2]").is_err());
    }

    #[test]
    fn xon_check_and_hibp() {
        let body = br#"{"breaches":[["Tesco","KiwiFarms"]],"email":"test@example.com","status":"success"}"#;
        let hits = parse_xon_check(body).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.breach.as_str()).collect::<Vec<_>>(),
            vec!["Tesco", "KiwiFarms"]
        );
        let hibp = br#"[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04",
            "DataClasses":["Email addresses","Password hints","Passwords","Usernames"],"IsVerified":true}]"#;
        let hits = parse_hibp(hibp).unwrap();
        assert_eq!(hits[0].breach, "Adobe");
        assert_eq!(hits[0].date.as_deref(), Some("2013-10-04"));
        assert!(exposes_passwords(&hits[0].data_classes));
        assert!(!exposes_passwords(&["Email addresses".to_string()]));
    }

    #[test]
    fn urls_encode_the_address() {
        let u = url_with_segment(
            "https://haveibeenpwned.com/api/v3",
            &["breachedaccount", "a+b@x.fr"],
        )
        .unwrap();
        assert_eq!(
            u.as_str(),
            "https://haveibeenpwned.com/api/v3/breachedaccount/a+b@x.fr"
        );
        let u = url_with_segment("https://h/api/", &["x", "a/b"]).unwrap();
        assert_eq!(u.as_str(), "https://h/api/x/a%2Fb");
    }
}
