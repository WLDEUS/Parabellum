//! Subprocess helper: absolute program path, argument vector (never a shell), stdin closed,
//! bounded output, timeout (the child is killed when the timeout fires), and a **trust check** of the
//! binary when running as root (see [`crate::trust`]): untrusted binaries are refused, or — for harmless
//! probes such as `--version` — run as their unprivileged owner.

use crate::trust::{inspect_binary, running_as_root};
use crate::UpdateError;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Max bytes kept from each of stdout / stderr.
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;

/// Captured result of a finished command.
#[derive(Debug, Clone, Default)]
pub(crate) struct CmdOutput {
    /// Exit code (`None` if killed by a signal).
    pub(crate) code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl CmdOutput {
    pub(crate) fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// stdout + stderr, trimmed, for messages.
    pub(crate) fn combined(&self) -> String {
        let mut s = self.stdout.trim().to_string();
        let e = self.stderr.trim();
        if !e.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(e);
        }
        s
    }

    /// Short single-line summary for error messages.
    pub(crate) fn summary(&self) -> String {
        let c = self.combined();
        let line: String = c
            .lines()
            .rfind(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(300)
            .collect();
        format!("code {:?} : {line}", self.code)
    }
}

/// What to do with a binary that root must not trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Untrusted {
    /// Refuse to run it ([`UpdateError::Untrusted`]).
    Refuse,
    /// Run it as its unprivileged owner (refused when there is none).
    RunAsOwner,
}

/// Options for [`run`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct RunOpts {
    pub(crate) timeout: Duration,
    pub(crate) untrusted: Untrusted,
}

impl RunOpts {
    pub(crate) fn timeout(secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(secs),
            untrusted: Untrusted::Refuse,
        }
    }

    pub(crate) fn as_owner_if_untrusted(mut self) -> Self {
        self.untrusted = Untrusted::RunAsOwner;
        self
    }
}

/// Run `program args…` and capture its output.
pub(crate) async fn run<I, S>(
    program: &Path,
    args: I,
    opts: RunOpts,
) -> Result<CmdOutput, UpdateError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_checked(program, args, opts, Path::new("/")).await
}

/// [`run`] with an explicit trust boundary (tests).
pub(crate) async fn run_checked<I, S>(
    program: &Path,
    args: I,
    opts: RunOpts,
    boundary: &Path,
) -> Result<CmdOutput, UpdateError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if !program.is_absolute() {
        return Err(UpdateError::Command(format!(
            "chemin non absolu refusé : {}",
            program.display()
        )));
    }
    let name = program.display().to_string();
    let info = crate::trust::inspect_binary_under(program, boundary)
        .map_err(|e| UpdateError::Command(format!("{name} : {e}")))?;
    let mut as_user = None;
    if running_as_root() && !info.trusted {
        let why = info.reasons.join(" ; ");
        match (opts.untrusted, info.run_as) {
            (Untrusted::RunAsOwner, Some(ids)) => {
                tracing::info!(binary = %name, uid = ids.0, "untrusted binary run as its owner");
                as_user = Some(ids);
            }
            _ => return Err(UpdateError::Untrusted(format!("{name} : {why}"))),
        }
    }
    let mut cmd = tokio::process::Command::new(&info.canonical);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .kill_on_drop(true);
    #[cfg(unix)]
    if let Some((uid, gid)) = as_user {
        // std drops supplementary groups (setgroups(0)) before setgid/setuid when started as root.
        cmd.gid(gid).uid(uid).current_dir("/");
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| UpdateError::Command(format!("{name} : {e}")))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let read_out = async move {
        let mut buf = Vec::new();
        if let Some(s) = stdout {
            let _ = s.take(MAX_OUTPUT).read_to_end(&mut buf).await;
        }
        buf
    };
    let read_err = async move {
        let mut buf = Vec::new();
        if let Some(s) = stderr {
            let _ = s.take(MAX_OUTPUT).read_to_end(&mut buf).await;
        }
        buf
    };
    let fut = async { tokio::join!(read_out, read_err, child.wait()) };
    let res = tokio::time::timeout(opts.timeout, fut).await;
    match res {
        Ok((o, e, status)) => {
            let status = status.map_err(|e| UpdateError::Command(format!("{name} : {e}")))?;
            Ok(CmdOutput {
                code: status.code(),
                stdout: String::from_utf8_lossy(&o).into_owned(),
                stderr: String::from_utf8_lossy(&e).into_owned(),
            })
        }
        Err(_) => {
            let _ = child.start_kill();
            Err(UpdateError::Timeout(format!(
                "{name} ({} s)",
                opts.timeout.as_secs()
            )))
        }
    }
}

/// Probe whether `program` may be executed by root as is (always true when not root).
pub(crate) fn trusted_for_root(program: &Path) -> Result<(), String> {
    if !running_as_root() {
        return Ok(());
    }
    match inspect_binary(program) {
        Ok(i) if i.trusted => Ok(()),
        Ok(i) => Err(i.reasons.join(" ; ")),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn runs_and_times_out() {
        let out = run(
            Path::new("/bin/sh"),
            ["-c", "echo hi; echo err >&2; exit 3"],
            RunOpts::timeout(10),
        )
        .await
        .unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout.trim(), "hi");
        assert!(out.combined().contains("err"));
        let err = run(
            Path::new("/bin/sleep"),
            ["5"],
            RunOpts {
                timeout: Duration::from_millis(200),
                untrusted: Untrusted::Refuse,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpdateError::Timeout(_)));
        assert!(run(Path::new("sh"), ["-c", "true"], RunOpts::timeout(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn untrusted_binaries_are_refused_or_run_as_owner() {
        if !running_as_root() {
            return; // trust only matters for root
        }
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let brew = root.join("brew");
        std::fs::create_dir(&brew).unwrap();
        std::fs::set_permissions(&brew, std::fs::Permissions::from_mode(0o755)).unwrap();
        let tool = brew.join("id-probe");
        std::fs::write(&tool, "#!/bin/sh\n/usr/bin/id -u\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Root-owned chain: runs as root.
        let out = run_checked(&tool, Vec::<String>::new(), RunOpts::timeout(10), root)
            .await
            .unwrap();
        assert_eq!(out.stdout.trim(), "0");

        // User-owned directory (like /opt/homebrew): refused by default, run as the owner on request.
        std::os::unix::fs::chown(&brew, Some(65534), Some(65534)).unwrap();
        let err = run_checked(&tool, Vec::<String>::new(), RunOpts::timeout(10), root)
            .await
            .unwrap_err();
        assert!(matches!(err, UpdateError::Untrusted(_)), "{err}");
        let out = run_checked(
            &tool,
            Vec::<String>::new(),
            RunOpts::timeout(10).as_owner_if_untrusted(),
            root,
        )
        .await
        .unwrap();
        assert_eq!(out.stdout.trim(), "65534");
        assert!(trusted_for_root(&tool).is_err());
    }
}
