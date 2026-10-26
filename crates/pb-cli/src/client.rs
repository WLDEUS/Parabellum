//! Synchronous JSON-lines client for the daemon socket.

use pb_core::ipc::*;
use serde::de::DeserializeOwned;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("impossible de joindre parabellumd sur {path} : {source}")]
    Connect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("délai dépassé en attendant parabellumd")]
    Timeout,
    #[error("connexion au daemon fermée")]
    Closed,
    #[error("erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),
    #[error("réponse invalide du daemon : {0}")]
    Protocol(String),
    #[error("{}", .0.message)]
    Daemon(IpcError),
}

impl ClientError {
    /// Daemon error code, if the daemon answered with an error.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Daemon(e) => Some(e.code),
            _ => None,
        }
    }
}

/// Default socket path (honours `PARABELLUM_SOCKET` / `PARABELLUM_ROOT`).
pub fn default_socket() -> PathBuf {
    pb_core::paths::Paths::system().socket
}

/// One connection to the daemon.
pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    next_id: u64,
    events: VecDeque<DaemonEvent>,
    timeout: Option<Duration>,
}

impl Client {
    /// Connect with a per-request read timeout (`None` = wait forever).
    pub fn connect(path: &Path, timeout: Option<Duration>) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(|source| ClientError::Connect {
            path: path.to_path_buf(),
            source,
        })?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_read_timeout(timeout)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self {
            writer: stream,
            reader,
            next_id: 1,
            events: VecDeque::new(),
            timeout,
        })
    }

    /// Change the read timeout (`None` = block).
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), ClientError> {
        self.timeout = timeout;
        self.reader.get_ref().set_read_timeout(timeout)?;
        Ok(())
    }

    fn read_message(&mut self) -> Result<ServerMessage, ClientError> {
        let mut line = Vec::new();
        let n = (&mut self.reader)
            .take(MAX_FRAME as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| {
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) {
                    ClientError::Timeout
                } else {
                    ClientError::Io(e)
                }
            })?;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        if line.len() > MAX_FRAME {
            return Err(ClientError::Protocol("ligne trop longue".into()));
        }
        serde_json::from_slice(line.trim_ascii()).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Send a request and return the raw `data` (`Null` when absent). Events received meanwhile are queued.
    pub fn call_raw(&mut self, request: Request) -> Result<serde_json::Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let line = encode_line(&RequestEnvelope { id, auth: None, request })
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.writer.write_all(&line)?;
        loop {
            match self.read_message()? {
                ServerMessage::Event(ev) => {
                    if self.events.len() < 10_000 {
                        self.events.push_back(ev);
                    }
                }
                ServerMessage::Response(r) if r.id == id || r.id == 0 => {
                    if !r.ok {
                        return Err(ClientError::Daemon(r.error.unwrap_or_else(|| {
                            IpcError::new(ErrorCode::Internal, "erreur inconnue")
                        })));
                    }
                    return Ok(r.data.unwrap_or(serde_json::Value::Null));
                }
                ServerMessage::Response(_) => {}
            }
        }
    }

    /// Send a request and decode `data`.
    pub fn call<T: DeserializeOwned>(&mut self, request: Request) -> Result<T, ClientError> {
        let v = self.call_raw(request)?;
        serde_json::from_value(v).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Start receiving events on this connection.
    pub fn subscribe(&mut self) -> Result<(), ClientError> {
        self.call_raw(Request::Subscribe).map(|_| ())
    }

    /// Next pushed event (queued ones first). Blocks up to the current timeout.
    pub fn next_event(&mut self) -> Result<DaemonEvent, ClientError> {
        if let Some(ev) = self.events.pop_front() {
            return Ok(ev);
        }
        loop {
            match self.read_message()? {
                ServerMessage::Event(ev) => return Ok(ev),
                ServerMessage::Response(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::model::*;
    use std::os::unix::net::UnixListener;

    /// Tiny fake daemon: answers ping, pushes an event before the response of `subscribe`'s follow-up.
    fn fake_server(path: PathBuf) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            let mut line = String::new();
            while r.read_line(&mut line).unwrap() > 0 {
                let env: RequestEnvelope = serde_json::from_str(line.trim()).unwrap();
                line.clear();
                let resp = match env.request {
                    Request::Ping => ResponseEnvelope::ok(
                        env.id,
                        &PingResponse {
                            version: "x".into(),
                            protocol: 1,
                        },
                    ),
                    Request::Subscribe => ResponseEnvelope::ok_empty(env.id),
                    Request::Status => {
                        let ev = DaemonEvent::UpdateFinished(UpdateResult {
                            target: UpdateTarget::Db,
                            ok: true,
                            started_at: 1,
                            finished_at: 2,
                            messages: vec![],
                            new_db_version: None,
                        });
                        w.write_all(&encode_line(&ev).unwrap()).unwrap();
                        // A stale response with another id is skipped by the client.
                        w.write_all(&encode_line(&ResponseEnvelope::ok_empty(999)).unwrap())
                            .unwrap();
                        ResponseEnvelope::ok(env.id, &StatusInfo::default())
                    }
                    _ => ResponseEnvelope::err(env.id, IpcError::new(ErrorCode::NotFound, "nope")),
                };
                w.write_all(&encode_line(&resp).unwrap()).unwrap();
            }
        })
    }

    #[test]
    fn request_response_and_events() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("s.sock");
        let h = fake_server(path.clone());
        let mut c = Client::connect(&path, Some(Duration::from_secs(5))).unwrap();
        let p: PingResponse = c.call(Request::Ping).unwrap();
        assert_eq!(p.protocol, 1);
        c.subscribe().unwrap();
        let _s: StatusInfo = c.call(Request::Status).unwrap();
        assert!(matches!(
            c.next_event().unwrap(),
            DaemonEvent::UpdateFinished(_)
        ));
        let e = c.call_raw(Request::ListQuarantine).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::NotFound));
        assert_eq!(e.to_string(), "nope");
        drop(c);
        h.join().unwrap();
    }

    #[test]
    fn connect_error_mentions_path() {
        let e = Client::connect(Path::new("/nonexistent/sock"), None)
            .err()
            .unwrap();
        assert!(e.to_string().contains("/nonexistent/sock"));
    }
}
