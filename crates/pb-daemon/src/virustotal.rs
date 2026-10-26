//! Opt-in VirusTotal hash lookups (API v3, hash only — files never leave the Mac).
//!
//! `GET https://www.virustotal.com/api/v3/files/{sha256}` with the `x-apikey` header, rate-limited by a token
//! bucket (4 requests / minute, the public API quota) and an in-memory result cache.

use crate::backends::{BackendError, HashReputation};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_BASE: &str = "https://www.virustotal.com/api/v3";
const MAX_BODY: usize = 4 * 1024 * 1024;
const CACHE_TTL: Duration = Duration::from_secs(7 * 86_400);
const CACHE_MAX: usize = 2_000;
const MAX_PENDING: usize = 32;

/// Token bucket: `capacity` tokens, one token regained every `refill`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill: Duration,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill: Duration, now: Instant) -> Self {
        Self {
            capacity: capacity as f64,
            tokens: capacity as f64,
            refill,
            last: now,
        }
    }

    /// Take a token, or return how long to wait for the next one.
    pub fn try_take(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() / self.refill.as_secs_f64()).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(self.refill.mul_f64(1.0 - self.tokens))
        }
    }
}

/// VirusTotal API v3 client.
pub struct VirusTotal {
    base: String,
    client: Mutex<Option<reqwest::Client>>,
    bucket: tokio::sync::Mutex<TokenBucket>,
    cache: Mutex<HashMap<String, (Option<u32>, Instant)>>,
    pending: AtomicUsize,
}

impl Default for VirusTotal {
    fn default() -> Self {
        Self::new()
    }
}

impl VirusTotal {
    /// Client for the public API (4 requests/minute).
    pub fn new() -> Self {
        Self::with_base(DEFAULT_BASE, 4, Duration::from_secs(15))
    }

    /// Custom endpoint / rate (tests).
    pub fn with_base(base: &str, per_window: u32, refill: Duration) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            client: Mutex::new(None),
            bucket: tokio::sync::Mutex::new(TokenBucket::new(per_window, refill, Instant::now())),
            cache: Mutex::new(HashMap::new()),
            pending: AtomicUsize::new(0),
        }
    }

    fn client(&self) -> Result<reqwest::Client, BackendError> {
        let mut g = self.client.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let c = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(format!("parabellum/{}", pb_core::VERSION))
            .build()
            .map_err(|e| BackendError::Failed(format!("client HTTP : {e}")))?;
        *g = Some(c.clone());
        Ok(c)
    }

    fn cached(&self, sha: &str) -> Option<Option<u32>> {
        let g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        g.get(sha)
            .filter(|(_, at)| at.elapsed() < CACHE_TTL)
            .map(|(v, _)| *v)
    }

    fn remember(&self, sha: &str, v: Option<u32>) {
        let mut g = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= CACHE_MAX {
            g.retain(|_, (_, at)| at.elapsed() < CACHE_TTL);
            if g.len() >= CACHE_MAX {
                g.clear();
            }
        }
        g.insert(sha.to_string(), (v, Instant::now()));
    }

    async fn wait_token(&self) {
        let mut b = self.bucket.lock().await;
        loop {
            match b.try_take(Instant::now()) {
                Ok(()) => return,
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }

    async fn fetch(&self, sha: &str, api_key: &str) -> Result<Option<u32>, BackendError> {
        let url = format!("{}/files/{sha}", self.base);
        let mut resp = self
            .client()?
            .get(&url)
            .header("x-apikey", api_key)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| BackendError::Failed(format!("VirusTotal injoignable : {e}")))?;
        match resp.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            401 | 403 => return Err(BackendError::Invalid("clé API VirusTotal refusée".into())),
            429 => return Err(BackendError::Unavailable("quota VirusTotal dépassé".into())),
            s => return Err(BackendError::Failed(format!("VirusTotal : HTTP {s}"))),
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| BackendError::Failed(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(BackendError::Failed(
                    "réponse VirusTotal trop grande".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        parse_file_report(&body).map(Some)
    }
}

/// Extract `data.attributes.last_analysis_stats.malicious` from a v3 file report.
pub fn parse_file_report(body: &[u8]) -> Result<u32, BackendError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| BackendError::Failed(format!("réponse VirusTotal invalide : {e}")))?;
    v.pointer("/data/attributes/last_analysis_stats/malicious")
        .and_then(|m| m.as_u64())
        .map(|m| m.min(u32::MAX as u64) as u32)
        .ok_or_else(|| BackendError::Failed("réponse VirusTotal sans last_analysis_stats".into()))
}

/// Lowercase 64-hex check.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

struct PendingGuard<'a>(&'a AtomicUsize);
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl HashReputation for VirusTotal {
    async fn malicious_engines(
        &self,
        sha256: &str,
        api_key: &str,
    ) -> Result<Option<u32>, BackendError> {
        if !is_sha256_hex(sha256) {
            return Err(BackendError::Invalid("SHA-256 invalide".into()));
        }
        if api_key.trim().is_empty() {
            return Err(BackendError::Invalid("clé API VirusTotal absente".into()));
        }
        let sha = sha256.to_ascii_lowercase();
        if let Some(v) = self.cached(&sha) {
            return Ok(v);
        }
        if self.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING {
            self.pending.fetch_sub(1, Ordering::SeqCst);
            return Err(BackendError::Unavailable(
                "trop de recherches VirusTotal en attente".into(),
            ));
        }
        let _guard = PendingGuard(&self.pending);
        self.wait_token().await;
        let v = self.fetch(&sha, api_key.trim()).await?;
        self.remember(&sha, v);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_waits() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(4, Duration::from_secs(15), t0);
        for _ in 0..4 {
            assert!(b.try_take(t0).is_ok());
        }
        let wait = b.try_take(t0).unwrap_err();
        assert!(wait <= Duration::from_secs(15) && wait > Duration::from_secs(14));
        assert!(b.try_take(t0 + Duration::from_secs(15)).is_ok());
        assert!(b.try_take(t0 + Duration::from_secs(16)).is_err());
        // Never more than `capacity` stored.
        assert!(b.try_take(t0 + Duration::from_secs(3600)).is_ok());
        let t = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(b.try_take(t).is_ok());
        }
        assert!(b.try_take(t).is_err());
    }

    #[test]
    fn parses_reports() {
        let body =
            br#"{"data":{"attributes":{"last_analysis_stats":{"malicious":12,"undetected":50}}}}"#;
        assert_eq!(parse_file_report(body).unwrap(), 12);
        assert!(parse_file_report(b"{}").is_err());
        assert!(parse_file_report(b"not json").is_err());
    }

    #[tokio::test]
    async fn rejects_bad_input_without_network() {
        let vt = VirusTotal::new();
        assert!(matches!(
            vt.malicious_engines("zz", "k").await,
            Err(BackendError::Invalid(_))
        ));
        assert!(matches!(
            vt.malicious_engines(&"a".repeat(64), " ").await,
            Err(BackendError::Invalid(_))
        ));
        vt.remember(&"b".repeat(64), Some(7));
        assert_eq!(
            vt.malicious_engines(&"B".repeat(64), "k").await.unwrap(),
            Some(7)
        );
    }

    #[tokio::test]
    async fn talks_to_a_local_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(req.contains("x-apikey: KEY"));
                let (status, body) = if req.contains(&"c".repeat(64)) {
                    (
                        "200 OK",
                        r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":9}}}}"#,
                    )
                } else {
                    ("404 Not Found", "{}")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        // Bypass any proxy configured in the environment for this loopback test.
        let vt = VirusTotal::with_base(&format!("http://{addr}"), 4, Duration::from_millis(10));
        *vt.client.lock().unwrap() = Some(reqwest::Client::builder().no_proxy().build().unwrap());
        assert_eq!(
            vt.malicious_engines(&"c".repeat(64), "KEY").await.unwrap(),
            Some(9)
        );
        assert_eq!(
            vt.malicious_engines(&"d".repeat(64), "KEY").await.unwrap(),
            None
        );
        // Cached: no third request reaches the server.
        assert_eq!(
            vt.malicious_engines(&"c".repeat(64), "KEY").await.unwrap(),
            Some(9)
        );
        server.await.unwrap();
    }
}
