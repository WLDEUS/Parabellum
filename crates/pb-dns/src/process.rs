//! Subprocess helper: absolute path, argument vector, stdin closed, bounded output, timeout (child killed).

use crate::DnsError;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const MAX_OUTPUT: u64 = 1024 * 1024;

/// Captured output.
#[derive(Debug, Clone, Default)]
pub(crate) struct CmdOutput {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl CmdOutput {
    /// stdout followed by stderr.
    pub(crate) fn text(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

pub(crate) async fn run<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
) -> Result<CmdOutput, DnsError> {
    if !program.is_absolute() {
        return Err(DnsError::Command(format!(
            "chemin non absolu refusé : {}",
            program.display()
        )));
    }
    let name = program.display().to_string();
    // Root never executes a binary an unprivileged user could replace (see `crate::trust`).
    let info = crate::trust::inspect_binary(program)
        .map_err(|e| DnsError::Command(format!("{name} : {e}")))?;
    if crate::trust::running_as_root() && !info.trusted {
        return Err(DnsError::Untrusted(format!(
            "{name} : {}",
            info.reasons.join(" ; ")
        )));
    }
    let mut child = tokio::process::Command::new(&info.canonical)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| DnsError::Command(format!("{name} : {e}")))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let fut = async {
        let read = |s: Option<tokio::process::ChildStdout>| async move {
            let mut b = Vec::new();
            if let Some(s) = s {
                let _ = s.take(MAX_OUTPUT).read_to_end(&mut b).await;
            }
            b
        };
        let read_err = |s: Option<tokio::process::ChildStderr>| async move {
            let mut b = Vec::new();
            if let Some(s) = s {
                let _ = s.take(MAX_OUTPUT).read_to_end(&mut b).await;
            }
            b
        };
        tokio::join!(read(stdout), read_err(stderr), child.wait())
    };
    let res = tokio::time::timeout(timeout, fut).await;
    match res {
        Ok((o, e, status)) => {
            let status = status.map_err(|e| DnsError::Command(format!("{name} : {e}")))?;
            Ok(CmdOutput {
                code: status.code(),
                stdout: String::from_utf8_lossy(&o).into_owned(),
                stderr: String::from_utf8_lossy(&e).into_owned(),
            })
        }
        Err(_) => {
            let _ = child.start_kill();
            Err(DnsError::Command(format!(
                "{name} : délai dépassé ({} s)",
                timeout.as_secs()
            )))
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_with_timeout() {
        let out = run(
            Path::new("/bin/sh"),
            &["-c", "echo ok"],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(out.code, Some(0));
        assert_eq!(out.text().trim(), "ok");
        assert!(
            run(Path::new("/bin/sleep"), &["5"], Duration::from_millis(100))
                .await
                .is_err()
        );
        assert!(run(Path::new("sleep"), &["1"], Duration::from_secs(1))
            .await
            .is_err());
    }
}
