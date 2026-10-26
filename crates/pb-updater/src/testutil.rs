//! Test helpers: a tiny hand-rolled HTTP/1.1 server on 127.0.0.1 (no real network in unit tests).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Route {
    status: u16,
    body: Vec<u8>,
}

type Routes = Arc<Mutex<HashMap<String, Route>>>;

/// Serves fixed bodies by exact path; unknown paths get 404. Records the raw request heads.
pub(crate) struct TestServer {
    addr: SocketAddr,
    routes: Routes,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub(crate) async fn start(routes: Vec<(String, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let map: HashMap<String, Route> = routes
            .into_iter()
            .map(|(p, body)| (p, Route { status: 200, body }))
            .collect();
        let routes: Routes = Arc::new(Mutex::new(map));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (r2, q2) = (routes.clone(), requests.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let (r3, q3) = (r2.clone(), q2.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let Ok(n) = sock.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 65536 {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    q3.lock().unwrap().push(head);
                    let route = r3.lock().unwrap().get(&path).cloned();
                    let (status, body) = match route {
                        Some(r) => (r.status, r.body),
                        None => (404, b"not found".to_vec()),
                    };
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let resp_head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(resp_head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Self {
            addr,
            routes,
            requests,
            task,
        }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub(crate) fn set(&self, path: &str, body: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_string(), Route { status: 200, body });
    }

    pub(crate) fn set_status(&self, path: &str, status: u16) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            Route {
                status,
                body: Vec::new(),
            },
        );
    }

    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}
