//! `parabellumd [--foreground] [--check-config]` — the Parabellum root daemon (LaunchDaemon).

use pb_core::config::Config;
use pb_core::paths::{Paths, ROOT_ENV};
use pb_daemon::daemon::{self, DaemonOptions};
use pb_daemon::{adapters, setup, system};
use std::process::ExitCode;

const USAGE: &str = "Usage : parabellumd [--foreground] [--check-config]\n\
  --foreground    rester au premier plan (comportement par défaut sous launchd)\n\
  --check-config  valider config.toml et quitter\n\
  --version       afficher la version";

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    foreground: bool,
    check_config: bool,
    version: bool,
    help: bool,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut a = Args::default();
    for arg in args {
        match arg.as_str() {
            "--foreground" | "-f" => a.foreground = true,
            "--check-config" => a.check_config = true,
            "--version" | "-V" => a.version = true,
            "--help" | "-h" => a.help = true,
            other => return Err(format!("option inconnue : {other}")),
        }
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if args.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.version {
        println!("parabellumd {}", pb_core::VERSION);
        return ExitCode::SUCCESS;
    }
    let paths = Paths::system();
    if args.check_config {
        return match Config::load(&paths.config_file()) {
            Ok(_) => {
                println!("{} : configuration valide", paths.config_file().display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{} : {e}", paths.config_file().display());
                ExitCode::FAILURE
            }
        };
    }
    let dev_mode = std::env::var_os(ROOT_ENV)
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !system::is_root() && !dev_mode {
        eprintln!("parabellumd doit tourner en root (définir {ROOT_ENV} pour une instance de développement)");
        return ExitCode::FAILURE;
    }
    if !dev_mode {
        // Root daemon: files we create are private unless explicitly opened up.
        // SAFETY: umask has no preconditions.
        unsafe {
            libc::umask(0o077);
        }
    }
    if let Err(e) = setup::prepare_dirs(&paths, !dev_mode) {
        eprintln!("préparation des dossiers impossible : {e}");
        return ExitCode::FAILURE;
    }
    let _log = setup::init_logging(&paths);
    let _lock = match setup::acquire_lock(&paths) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot acquire the instance lock");
            return ExitCode::FAILURE;
        }
    };
    system::lower_process_priority();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .thread_name("parabellumd")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the runtime");
            return ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(async move {
        let backends = adapters::production(&paths);
        let opts = DaemonOptions {
            paths,
            dev_mode,
            backends,
            start_monitors: true,
            start_scheduler: true,
        };
        let d = match daemon::start(opts).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "startup failed");
                return ExitCode::FAILURE;
            }
        };
        wait_for_signal().await;
        d.shutdown().await;
        ExitCode::SUCCESS
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    code
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot install SIGTERM handler");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received"),
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args() {
        let p = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        assert_eq!(p(&[]).unwrap(), Args::default());
        assert!(p(&["--foreground"]).unwrap().foreground);
        assert!(p(&["--check-config"]).unwrap().check_config);
        assert!(p(&["--bogus"]).is_err());
    }
}
