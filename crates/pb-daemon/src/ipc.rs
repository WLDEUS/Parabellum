//! Unix-socket JSON-lines server.
//!
//! One task per connection; requests are answered in order; after `subscribe` the connection also receives
//! events, interleaved. Malformed lines get a `bad_request` response (id 0 when it cannot be read) and never
//! crash the daemon. A line longer than [`MAX_FRAME`] closes the connection. A subscriber that cannot keep up
//! (bus lag or full output buffer) is disconnected rather than slowing anything down.
//!
//! Authorization: mutating commands require root, or the console user running the installed app / CLI
//! (executable path checked with `proc_pidpath`). Development instances (`PARABELLUM_ROOT`) skip the
//! executable check and also accept the daemon's own uid.

use crate::ctx::Ctx;
use crate::router::{self, Peer};
use crate::system;
use pb_core::ipc::*;
use pb_core::paths::Paths;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, Notify, Semaphore};

/// Installed executables allowed to send mutating commands (with the console user's uid).
pub const APP_EXECUTABLE: &str = "/Applications/Parabellum.app/Contents/MacOS/Parabellum";
pub const CLI_EXECUTABLE: &str = "/Library/Application Support/Parabellum/bin/parabellum";
/// Concurrent client connections.
pub const MAX_CONNECTIONS: usize = 64;
/// Outgoing lines buffered per connection.
pub const OUT_BUFFER: usize = 512;

/// May this peer run mutating commands?
pub fn authorize(
    peer_uid: u32,
    exe: Option<&Path>,
    console_uid: Option<u32>,
    daemon_uid: u32,
    dev_mode: bool,
) -> bool {
    if peer_uid == 0 {
        return true;
    }
    if dev_mode {
        return Some(peer_uid) == console_uid || peer_uid == daemon_uid;
    }
    Some(peer_uid) == console_uid
        && exe
            .map(|e| e == Path::new(APP_EXECUTABLE) || e == Path::new(CLI_EXECUTABLE))
            .unwrap_or(false)
}

/// Bind the socket: remove a stale one, then restrict it (root:admin 0660, or 0600 in dev mode).
pub fn bind(paths: &Paths, dev_mode: bool) -> std::io::Result<UnixListener> {
    let path = &paths.socket;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            use std::os::unix::fs::FileTypeExt;
            if !md.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} existe et n'est pas une socket", path.display()),
                ));
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("un daemon écoute déjà sur {}", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    if dev_mode || !system::is_root() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    } else {
        std::os::unix::fs::chown(path, Some(0), Some(system::ADMIN_GID))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    Ok(listener)
}

/// Accept loop (until shutdown).
pub async fn serve(ctx: Arc<Ctx>, listener: UnixListener) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut shutdown = ctx.shutdown_rx();
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        tracing::warn!("too many IPC connections, refusing one");
                        continue;
                    };
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        handle_connection(ctx, stream).await;
                        drop(permit);
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            },
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Result of reading one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Line,
    Eof,
    TooLong,
}

/// Read one `\n`-terminated line into `buf` (without the newline), refusing more than `max` bytes.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Frame> {
    buf.clear();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() {
                Frame::Eof
            } else {
                Frame::Line
            });
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if buf.len() + i > max {
                    r.consume(i + 1);
                    return Ok(Frame::TooLong);
                }
                buf.extend_from_slice(&available[..i]);
                r.consume(i + 1);
                return Ok(Frame::Line);
            }
            None => {
                let n = available.len();
                if buf.len() + n > max {
                    r.consume(n);
                    return Ok(Frame::TooLong);
                }
                buf.extend_from_slice(available);
                r.consume(n);
            }
        }
    }
}

fn line_of<T: serde::Serialize>(msg: &T) -> Vec<u8> {
    encode_line(msg).unwrap_or_else(|_| {
        b"{\"id\":0,\"ok\":false,\"error\":{\"code\":\"internal\",\"message\":\"encode\"}}\n"
            .to_vec()
    })
}

/// Parse a request line; on failure return the best-effort id and an error.
pub fn parse_request(line: &[u8]) -> Result<RequestEnvelope, (u64, IpcError)> {
    match serde_json::from_slice::<RequestEnvelope>(line) {
        Ok(r) => Ok(r),
        Err(e) => {
            let id = serde_json::from_slice::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                .unwrap_or(0);
            Err((
                id,
                IpcError::new(ErrorCode::BadRequest, format!("requête invalide : {e}")),
            ))
        }
    }
}

/// Access policy knobs (production: root is admin, no bypass; dev mode: bypass, logged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessPolicy {
    /// Development instance: `requires_admin` commands are accepted from peers allowed to mutate (logged).
    pub dev_bypass: bool,
    /// Peers running as uid 0 count as administrators (`sudo parabellum …`). Off only in tests.
    pub root_is_admin: bool,
}

impl AccessPolicy {
    pub fn for_mode(dev_mode: bool) -> Self {
        Self {
            dev_bypass: dev_mode,
            root_is_admin: true,
        }
    }
}

/// Outcome of the access check of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `admin`: root or administrator-approved (secrets may be returned).
    Allowed {
        admin: bool,
    },
    AuthRequired,
    PermissionDenied,
}

/// Access rules. `requires_admin` ⇒ root, or (installed client of the console user **and** valid `auth`),
/// or the dev bypass; other mutating commands ⇒ root or installed client of the console user.
pub fn decide(
    req: &Request,
    is_root: bool,
    can_mutate: bool,
    auth_ok: bool,
    dev_bypass: bool,
) -> Access {
    let admin = is_root || (can_mutate && auth_ok);
    if req.requires_admin() {
        return if admin || (dev_bypass && can_mutate) {
            Access::Allowed { admin: true }
        } else {
            Access::AuthRequired
        };
    }
    if req.is_mutating() && !(can_mutate || is_root) {
        return Access::PermissionDenied;
    }
    Access::Allowed {
        admin: admin || (dev_bypass && can_mutate),
    }
}

fn peer_cred(stream: &UnixStream) -> Option<system::PeerCred> {
    match system::peer_credentials(stream.as_raw_fd()) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "cannot read peer credentials");
            None
        }
    }
}

/// Re-evaluated for every request: the peer may have exec'd another image or the console user changed.
fn current_peer(ctx: &Ctx, cred: &system::PeerCred) -> Peer {
    let exe: Option<PathBuf> = system::peer_executable(cred);
    let console = system::console_user().map(|u| u.uid);
    let can_mutate = authorize(
        cred.uid,
        exe.as_deref(),
        console,
        system::euid(),
        ctx.dev_mode,
    );
    let is_root = cred.uid == 0 && ctx.access.root_is_admin;
    Peer {
        uid: cred.uid,
        pid: cred.pid,
        exe,
        can_mutate,
        admin: is_root,
    }
}

/// Check access for one request (verifies `auth` with Authorization Services only when it matters).
async fn check_access(ctx: &Ctx, peer: &mut Peer, env: &RequestEnvelope) -> Result<(), IpcError> {
    let wants_admin = env.request.requires_admin() || env.request == Request::GetConfig;
    let is_root = peer.admin;
    let auth_ok = match (&env.auth, wants_admin && !is_root) {
        (Some(a), true) => {
            let a = a.clone();
            tokio::task::spawn_blocking(move || crate::auth::verify_admin_auth(&a))
                .await
                .unwrap_or(false)
        }
        _ => false,
    };
    match decide(
        &env.request,
        is_root,
        peer.can_mutate,
        auth_ok,
        ctx.access.dev_bypass,
    ) {
        Access::Allowed { admin } => {
            if env.request.requires_admin() && !is_root && !auth_ok {
                tracing::warn!(uid = peer.uid, "dev mode: administrator approval bypassed");
            }
            peer.admin = admin;
            Ok(())
        }
        Access::AuthRequired => {
            tracing::warn!(uid = peer.uid, exe = ?peer.exe, with_auth = env.auth.is_some(), "admin command refused");
            Err(IpcError::new(
                ErrorCode::AuthRequired,
                crate::auth::AUTH_REQUIRED_MESSAGE,
            ))
        }
        Access::PermissionDenied => {
            tracing::warn!(uid = peer.uid, exe = ?peer.exe, "mutating command refused");
            Err(IpcError::new(
                ErrorCode::PermissionDenied,
                "commande réservée à root ou à l'app/CLI Parabellum de l'utilisateur connecté",
            ))
        }
    }
}

async fn handle_connection(ctx: Arc<Ctx>, stream: UnixStream) {
    let Some(cred) = peer_cred(&stream) else {
        return;
    };
    tracing::debug!(uid = cred.uid, pid = ?cred.pid, "ipc client");
    let (rd, mut wr) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(OUT_BUFFER);
    let kill = Arc::new(Notify::new());
    let writer = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if wr.write_all(&line).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    let mut forwarder: Option<tokio::task::JoinHandle<()>> = None;
    let mut reader = BufReader::with_capacity(64 * 1024, rd);
    let mut buf = Vec::new();
    let mut shutdown = ctx.shutdown_rx();
    loop {
        let frame = tokio::select! {
            f = read_frame(&mut reader, &mut buf, MAX_FRAME) => f,
            _ = kill.notified() => {
                tracing::info!(uid = cred.uid, "slow subscriber disconnected");
                break;
            }
            _ = shutdown.changed() => break,
        };
        let response = match frame {
            Err(_) | Ok(Frame::Eof) => break,
            Ok(Frame::TooLong) => {
                let r = ResponseEnvelope::err(
                    0,
                    IpcError::new(ErrorCode::BadRequest, "ligne trop longue"),
                );
                let _ = out_tx.send(line_of(&r)).await;
                break;
            }
            Ok(Frame::Line) => {
                let trimmed = buf.trim_ascii();
                if trimmed.is_empty() {
                    continue;
                }
                match parse_request(trimmed) {
                    Err((id, e)) => ResponseEnvelope::err(id, e),
                    Ok(env) => {
                        let id = env.id;
                        let mut peer = current_peer(&ctx, &cred);
                        if let Err(e) = check_access(&ctx, &mut peer, &env).await {
                            ResponseEnvelope::err(id, e)
                        } else if env.request == Request::Subscribe {
                            if forwarder.is_none() {
                                forwarder = Some(spawn_forwarder(
                                    ctx.bus.subscribe(),
                                    out_tx.clone(),
                                    kill.clone(),
                                ));
                            }
                            ResponseEnvelope::ok_empty(id)
                        } else {
                            match router::handle(&ctx, &peer, env.request).await {
                                Ok(v) if v.is_null() => ResponseEnvelope::ok_empty(id),
                                Ok(v) => ResponseEnvelope {
                                    id,
                                    ok: true,
                                    data: Some(v),
                                    error: None,
                                },
                                Err(e) => ResponseEnvelope::err(id, e),
                            }
                        }
                    }
                }
            }
        };
        if out_tx.send(line_of(&response)).await.is_err() {
            break;
        }
    }
    if let Some(f) = forwarder {
        f.abort();
    }
    drop(out_tx);
    let _ = writer.await;
}

fn spawn_forwarder(
    mut rx: broadcast::Receiver<DaemonEvent>,
    out: mpsc::Sender<Vec<u8>>,
    kill: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => match out.try_send(line_of(&ev)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        kill.notify_one();
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                },
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!(missed = n, "subscriber lagged");
                    kill.notify_one();
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_rules() {
        let app = Path::new(APP_EXECUTABLE);
        let cli = Path::new(CLI_EXECUTABLE);
        let other = Path::new("/tmp/evil");
        assert!(authorize(0, None, None, 0, false));
        assert!(authorize(501, Some(app), Some(501), 0, false));
        assert!(authorize(501, Some(cli), Some(501), 0, false));
        assert!(!authorize(501, Some(other), Some(501), 0, false));
        assert!(!authorize(501, None, Some(501), 0, false));
        assert!(!authorize(502, Some(app), Some(501), 0, false));
        assert!(!authorize(501, Some(app), None, 0, false));
        // Dev mode: no executable check, daemon's own uid accepted.
        assert!(authorize(501, Some(other), Some(501), 1000, true));
        assert!(authorize(1000, None, None, 1000, true));
        assert!(!authorize(1001, None, Some(501), 1000, true));
    }

    #[test]
    fn access_decisions() {
        let fp = Request::ReportFalsePositive {
            sha256: "a".repeat(64),
            path: None,
            note: None,
        };
        let scan = Request::Scan {
            paths: vec!["/x".into()],
            recursive: true,
            use_clamav: None,
        };
        // requires_admin: root, or installed client + valid auth, or dev bypass.
        assert_eq!(
            decide(&fp, true, false, false, false),
            Access::Allowed { admin: true }
        );
        assert_eq!(
            decide(&fp, false, true, true, false),
            Access::Allowed { admin: true }
        );
        assert_eq!(decide(&fp, false, true, false, false), Access::AuthRequired);
        assert_eq!(decide(&fp, false, false, true, false), Access::AuthRequired);
        assert_eq!(
            decide(&fp, false, true, false, true),
            Access::Allowed { admin: true }
        );
        assert_eq!(decide(&fp, false, false, false, true), Access::AuthRequired);
        // plain mutating
        assert_eq!(
            decide(&scan, false, true, false, false),
            Access::Allowed { admin: false }
        );
        assert_eq!(
            decide(&scan, false, false, false, false),
            Access::PermissionDenied
        );
        assert_eq!(
            decide(&scan, true, false, false, false),
            Access::Allowed { admin: true }
        );
        // read-only: anyone; secrets only for admins
        assert_eq!(
            decide(&Request::GetConfig, false, false, false, false),
            Access::Allowed { admin: false }
        );
        assert_eq!(
            decide(&Request::GetConfig, false, true, true, false),
            Access::Allowed { admin: true }
        );
        assert_eq!(
            decide(
                &Request::SetDns { enabled: true },
                false,
                true,
                false,
                false
            ),
            Access::Allowed { admin: false }
        );
        assert_eq!(
            decide(
                &Request::SetDns { enabled: false },
                false,
                true,
                false,
                false
            ),
            Access::AuthRequired
        );
    }

    #[test]
    fn request_parsing_errors_keep_id() {
        assert_eq!(parse_request(br#"{"id":4,"cmd":"ping"}"#).unwrap().id, 4);
        let (id, e) = parse_request(br#"{"id":9,"cmd":"nope"}"#).unwrap_err();
        assert_eq!((id, e.code), (9, ErrorCode::BadRequest));
        let (id, _) = parse_request(b"not json").unwrap_err();
        assert_eq!(id, 0);
        let (id, _) = parse_request(br#"{"id":-3,"cmd":"ping"}"#).unwrap_err();
        assert_eq!(id, 0);
    }

    #[tokio::test]
    async fn frames() {
        let data = b"abc\n\nxyz".to_vec();
        let mut r = BufReader::new(&data[..]);
        let mut buf = Vec::new();
        assert_eq!(
            read_frame(&mut r, &mut buf, 100).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"abc");
        assert_eq!(
            read_frame(&mut r, &mut buf, 100).await.unwrap(),
            Frame::Line
        );
        assert!(buf.is_empty());
        assert_eq!(
            read_frame(&mut r, &mut buf, 100).await.unwrap(),
            Frame::Line
        );
        assert_eq!(buf, b"xyz");
        assert_eq!(read_frame(&mut r, &mut buf, 100).await.unwrap(), Frame::Eof);
        let long = [b'a'; 50];
        let mut r = BufReader::with_capacity(8, &long[..]);
        assert_eq!(
            read_frame(&mut r, &mut buf, 10).await.unwrap(),
            Frame::TooLong
        );
    }

    #[test]
    fn stale_socket_is_replaced_but_files_are_not() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let l = bind(&paths, true).unwrap();
            drop(l); // socket file left behind
            let _l2 = bind(&paths, true).unwrap();
            assert_eq!(
                std::fs::metadata(&paths.socket)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            // Someone listening: refuse.
            assert!(bind(&paths, true).is_err());
        });
        let other = Paths {
            socket: d.path().join("plainfile"),
            ..Paths::with_root(d.path())
        };
        std::fs::write(&other.socket, b"x").unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { assert!(bind(&other, true).is_err()) });
    }
}
