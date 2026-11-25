//! Bounded HTTP bodies. A provider (or anything on the path) answering with gigabytes must not exhaust
//! the root daemon's memory (audit NET-7); every response is read through these.

use std::future::Future;

/// Response bodies of the breach, alias and password-range APIs stay far below this.
pub(crate) const MAX_API_BODY: usize = 4 * 1024 * 1024;

/// The whole body, or an error as soon as it would exceed `max` bytes.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, String> {
    let too_big = || format!("réponse trop volumineuse (plus de {} Kio)", max / 1024);
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_big());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if out.len() + chunk.len() > max {
            return Err(too_big());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Follow redirects only within the same scheme, host and port: clients that send a key in a custom
/// header (`hibp-api-key`, `Authentication`) must never hand it to another server, which reqwest only
/// prevents for `Authorization` and cookies (audit NET-7).
pub(crate) fn same_origin_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let same = attempt.previous().first().is_some_and(|first| {
            first.scheme() == attempt.url().scheme()
                && first.host_str() == attempt.url().host_str()
                && first.port_or_known_default() == attempt.url().port_or_known_default()
        });
        if same && attempt.previous().len() < 3 {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// `.json()` with the [`MAX_API_BODY`] cap.
pub(crate) trait CappedJson {
    fn json_capped(self) -> impl Future<Output = Result<serde_json::Value, String>> + Send;
}

impl CappedJson for reqwest::Response {
    async fn json_capped(self) -> Result<serde_json::Value, String> {
        let body = read_capped(self, MAX_API_BODY).await?;
        serde_json::from_slice(&body).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve(body: Vec<u8>, chunked: bool) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            let head = if chunked {
                // No Content-Length: the cap must hold while streaming.
                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string()
            } else {
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
            };
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn bodies_over_the_cap_are_refused() {
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        for chunked in [false, true] {
            let url = serve(vec![b'a'; 64 * 1024], chunked).await;
            let resp = http.get(url).send().await.unwrap();
            assert!(
                read_capped(resp, 16 * 1024).await.is_err(),
                "chunked={chunked}"
            );
        }
        let url = serve(br#"{"ok":true}"#.to_vec(), false).await;
        let v = http
            .get(url)
            .send()
            .await
            .unwrap()
            .json_capped()
            .await
            .unwrap();
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn a_key_header_never_follows_a_redirect_to_another_server() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            // Same host, other port: another origin.
            let _ = s
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/steal\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(same_origin_redirects())
            .build()
            .unwrap();
        let resp = http
            .get(format!("http://{addr}/"))
            .header("hibp-api-key", "k")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 302);
    }
}
