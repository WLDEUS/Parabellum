//! Hardened HTTP client shared by every updater operation.
//!
//! - HTTPS only (redirects included); plain HTTP to loopback is allowed only in unit tests.
//! - `User-Agent: Parabellum/<version>`.
//! - The optional GitHub token is attached only to `github.com` / `api.github.com` URLs. reqwest strips
//!   `Authorization` when a redirect leaves the host (GitHub asset downloads redirect to a signed CDN URL).
//! - Connect / read / total timeouts, size caps (checked against `Content-Length` *and* while streaming),
//!   streaming to a `.part` file renamed into place on success.
//! - No transparent decompression (signatures are computed over the exact bytes served).

use crate::UpdateError;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// GitHub REST API media type.
pub const GITHUB_JSON: &str = "application/vnd.github+json";
/// Accept header that makes the GitHub *asset API URL* return the binary (works for private repos).
pub const OCTET_STREAM: &str = "application/octet-stream";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Default total timeout for small requests (JSON, manifests, signatures).
pub const SMALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Total timeout for large downloads (bundle, installers).
pub const LARGE_TIMEOUT: Duration = Duration::from_secs(45 * 60);

/// The `User-Agent` sent with every request.
pub fn user_agent() -> String {
    format!("Parabellum/{}", pb_core::VERSION)
}

/// HTTP client with Parabellum's security policy baked in.
#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    token: Option<String>,
    allow_loopback_http: bool,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Http {
    /// Production client (HTTPS only).
    pub fn new(github_token: Option<String>) -> Result<Self, UpdateError> {
        Self::build(github_token, false)
    }

    /// Test client: additionally accepts `http://127.0.0.1` / `http://[::1]` / `http://localhost`.
    #[cfg(test)]
    pub(crate) fn new_for_tests(github_token: Option<String>) -> Self {
        match Self::build(github_token, true) {
            Ok(h) => h,
            Err(e) => panic!("test http client: {e}"),
        }
    }

    fn build(github_token: Option<String>, allow_loopback_http: bool) -> Result<Self, UpdateError> {
        let policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if url_allowed(attempt.url(), allow_loopback_http) {
                attempt.follow()
            } else {
                attempt.error("redirect to a non-HTTPS URL refused")
            }
        });
        let mut builder = reqwest::Client::builder()
            .user_agent(user_agent())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .redirect(policy)
            .no_gzip();
        if allow_loopback_http {
            builder = builder.no_proxy();
        } else {
            builder = builder.https_only(true);
        }
        let client = builder
            .build()
            .map_err(|e| UpdateError::Http(e.to_string()))?;
        let token = github_token
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        Ok(Self {
            client,
            token,
            allow_loopback_http,
        })
    }

    /// True when a GitHub token is configured.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    fn parse_checked(&self, url: &str) -> Result<Url, UpdateError> {
        let u = Url::parse(url).map_err(|_| UpdateError::InsecureUrl(url.to_string()))?;
        if url_allowed(&u, self.allow_loopback_http) {
            Ok(u)
        } else {
            Err(UpdateError::InsecureUrl(redact(url)))
        }
    }

    fn headers_for(&self, url: &Url, accept: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = accept {
            if let Ok(v) = HeaderValue::from_str(a) {
                h.insert(ACCEPT, v);
            }
        }
        if is_github_host(url) {
            if let Some(t) = &self.token {
                if let Ok(mut v) = HeaderValue::from_str(&format!("Bearer {t}")) {
                    v.set_sensitive(true);
                    h.insert(AUTHORIZATION, v);
                }
            }
            if url.host_str() == Some("api.github.com") {
                h.insert(
                    "X-GitHub-Api-Version",
                    HeaderValue::from_static("2022-11-28"),
                );
            }
        }
        h
    }

    async fn send(
        &self,
        url: &str,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<reqwest::Response, UpdateError> {
        let u = self.parse_checked(url)?;
        let headers = self.headers_for(&u, accept);
        let resp = self
            .client
            .get(u.clone())
            .headers(headers)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| UpdateError::Http(redact(&e.to_string())))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        if (status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS)
            && is_github_host(&u)
        {
            let remaining = resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .unwrap_or("");
            if remaining == "0" || status == StatusCode::TOO_MANY_REQUESTS {
                return Err(UpdateError::RateLimited);
            }
        }
        Err(UpdateError::HttpStatus {
            url: redact(url),
            status: status.as_u16(),
        })
    }

    /// GET into memory, at most `max` bytes.
    pub async fn get_bytes(
        &self,
        url: &str,
        max: u64,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<Vec<u8>, UpdateError> {
        let mut resp = self.send(url, accept, timeout).await?;
        if resp.content_length().is_some_and(|l| l > max) {
            return Err(UpdateError::TooLarge {
                what: redact(url),
                limit: max,
            });
        }
        let mut out = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| UpdateError::Http(redact(&e.to_string())))?
        {
            if out.len() as u64 + chunk.len() as u64 > max {
                return Err(UpdateError::TooLarge {
                    what: redact(url),
                    limit: max,
                });
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// GET and decode JSON (GitHub API media type when the host is GitHub), at most `max` bytes.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        max: u64,
    ) -> Result<T, UpdateError> {
        let accept = Url::parse(url)
            .ok()
            .filter(is_github_host)
            .map(|_| GITHUB_JSON)
            .unwrap_or("application/json");
        let bytes = self
            .get_bytes(url, max, Some(accept), SMALL_TIMEOUT)
            .await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Stream a download to `dest` (via `dest.part`, renamed on success), at most `max` bytes.
    /// Returns the number of bytes written.
    pub async fn download_to_file(
        &self,
        url: &str,
        dest: &Path,
        max: u64,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<u64, UpdateError> {
        let part = part_path(dest);
        let res = self.download_inner(url, &part, max, accept, timeout).await;
        match res {
            Ok(n) => {
                tokio::fs::rename(&part, dest).await?;
                Ok(n)
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                Err(e)
            }
        }
    }

    async fn download_inner(
        &self,
        url: &str,
        part: &Path,
        max: u64,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<u64, UpdateError> {
        let mut resp = self.send(url, accept, timeout).await?;
        if resp.content_length().is_some_and(|l| l > max) {
            return Err(UpdateError::TooLarge {
                what: redact(url),
                limit: max,
            });
        }
        let _ = tokio::fs::remove_file(part).await;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(part)
            .await?;
        let mut total: u64 = 0;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| UpdateError::Http(redact(&e.to_string())))?
        {
            total += chunk.len() as u64;
            if total > max {
                return Err(UpdateError::TooLarge {
                    what: redact(url),
                    limit: max,
                });
            }
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        file.sync_all().await?;
        Ok(total)
    }
}

fn part_path(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

fn is_loopback_host(u: &Url) -> bool {
    match u.host_str() {
        Some(h) => {
            let h = h.trim_start_matches('[').trim_end_matches(']');
            h.eq_ignore_ascii_case("localhost")
                || h.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        None => false,
    }
}

fn url_allowed(u: &Url, allow_loopback_http: bool) -> bool {
    match u.scheme() {
        "https" => u.host().is_some(),
        "http" => allow_loopback_http && is_loopback_host(u),
        _ => false,
    }
}

/// Hosts that may receive the GitHub token.
pub fn is_github_host(u: &Url) -> bool {
    u.scheme() == "https" && matches!(u.host_str(), Some("github.com") | Some("api.github.com"))
}

/// Strip query strings (signed CDN URLs carry credentials) from text shown to the user / logs.
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut skipping = false;
    for c in s.chars() {
        if c == '?' {
            skipping = true;
            out.push_str("?…");
            continue;
        }
        if skipping && (c.is_whitespace() || c == ')' || c == '"') {
            skipping = false;
        }
        if !skipping {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_test_loopback() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(url_allowed(&u("https://github.com/x"), false));
        assert!(!url_allowed(&u("http://github.com/x"), false));
        assert!(!url_allowed(&u("http://127.0.0.1:8080/x"), false));
        assert!(url_allowed(&u("http://127.0.0.1:8080/x"), true));
        assert!(!url_allowed(&u("http://10.0.0.1/x"), true));
        assert!(!url_allowed(&u("file:///etc/passwd"), true));
    }

    #[test]
    fn token_only_for_github() {
        let h = Http::new_for_tests(Some("secret".into()));
        let gh = h.headers_for(
            &Url::parse("https://api.github.com/repos/a/b").unwrap(),
            None,
        );
        assert!(gh.contains_key(AUTHORIZATION));
        let other = h.headers_for(
            &Url::parse("https://objects.githubusercontent.com/x").unwrap(),
            None,
        );
        assert!(!other.contains_key(AUTHORIZATION));
        let plain = h.headers_for(&Url::parse("http://127.0.0.1/x").unwrap(), None);
        assert!(!plain.contains_key(AUTHORIZATION));
    }

    #[test]
    fn redacts_query() {
        assert_eq!(redact("https://x/y?sig=abc def"), "https://x/y?… def");
        assert_eq!(redact("no query"), "no query");
    }

    #[tokio::test]
    async fn caps_and_streams() {
        let srv = crate::testutil::TestServer::start(vec![("/big".into(), vec![7u8; 4096])]).await;
        let h = Http::new_for_tests(None);
        let err = h
            .get_bytes(&srv.url("/big"), 100, None, SMALL_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::TooLarge { .. }));
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("f");
        let n = h
            .download_to_file(&srv.url("/big"), &dest, 10_000, None, SMALL_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(n, 4096);
        assert_eq!(std::fs::read(&dest).unwrap().len(), 4096);
        let err = h
            .download_to_file(&srv.url("/missing"), &dest, 10_000, None, SMALL_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::HttpStatus { status: 404, .. }));
        assert!(!part_path(&dest).exists());
        srv.set_status("/err", 500);
        let err = h
            .get_bytes(&srv.url("/err"), 100, None, SMALL_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::HttpStatus { status: 500, .. }));
    }
}
