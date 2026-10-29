//! Process setup: directories and permissions, logging, single-instance lock, configuration file.

use pb_core::config::Config;
use pb_core::paths::Paths;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Create every directory of the layout with its permissions and wipe `tmp/`.
///
/// Production (root): owned root:wheel, 0755; `quarantine/` and `state/` 0700. Directories outside our
/// own tree (e.g. `/var/run` holding the socket) are only created if missing, never re-permissioned.
pub fn prepare_dirs(paths: &Paths, as_root: bool) -> std::io::Result<()> {
    for dir in paths.all_dirs() {
        let ours = dir.starts_with(&paths.root) || dir.starts_with(&paths.log_dir);
        std::fs::create_dir_all(&dir)?;
        if !ours {
            continue;
        }
        let private = dir == paths.quarantine_dir()
            || dir == paths.state_dir()
            || dir == paths.vpn_dir()
            || dir == paths.privacy_dir()
            || dir == paths.tmp_dir();
        let mode = if private { 0o700 } else { 0o755 };
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))?;
        if as_root {
            std::os::unix::fs::chown(&dir, Some(0), Some(0))?;
        }
    }
    wipe_dir_contents(&paths.tmp_dir())
}

/// Remove everything under `dir` without crossing filesystem boundaries: an entry living on another
/// device is a leftover mount point (DMG attached by a crashed scan) — it is detached on macOS and
/// otherwise left alone, so we never delete files on a mounted volume.
pub fn wipe_dir_contents(dir: &Path) -> std::io::Result<()> {
    let root_dev = std::fs::symlink_metadata(dir)?.dev();
    wipe_inner(dir, root_dev, 0)
}

fn wipe_inner(dir: &Path, root_dev: u64, depth: u32) -> std::io::Result<()> {
    if depth > 64 {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let md = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.dev() != root_dev {
            tracing::warn!(path = %path.display(), "mount point left in tmp/, detaching");
            detach_mount(&path);
            // Still mounted (detach failed): never descend into it.
            if std::fs::symlink_metadata(&path)
                .map(|m| m.dev() != root_dev)
                .unwrap_or(true)
            {
                continue;
            }
        }
        let md = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_dir() {
            wipe_inner(&path, root_dev, depth + 1)?;
            if let Err(e) = std::fs::remove_dir(&path) {
                tracing::warn!(path = %path.display(), error = %e, "cannot remove tmp dir");
            }
        } else if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), error = %e, "cannot remove tmp file");
        }
    }
    Ok(())
}

fn detach_mount(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let ok = crate::system::run_sync(
            "/usr/bin/hdiutil",
            &[
                std::ffi::OsStr::new("detach"),
                std::ffi::OsStr::new("-force"),
                path.as_os_str(),
            ],
            std::time::Duration::from_secs(30),
        );
        if !ok {
            tracing::warn!(path = %path.display(), "hdiutil detach failed");
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
}

/// Exclusive, non-blocking `flock` on `state/daemon.lock`. Keep the returned file alive.
pub fn acquire_lock(paths: &Paths) -> std::io::Result<File> {
    use std::os::fd::AsRawFd;
    let path = paths.state_dir().join("daemon.lock");
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    // SAFETY: flock on a file descriptor we own.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            e.kind(),
            format!("une autre instance de parabellumd tourne déjà ({e})"),
        ));
    }
    let _ = f.set_len(0);
    let _ = std::io::Write::write_all(&mut &f, format!("{}\n", std::process::id()).as_bytes());
    Ok(f)
}

/// Keeps the non-blocking log writer alive.
pub struct LogGuard {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Logging to `paths.log_file()` (daily rotation, 7 files kept) + stderr. `RUST_LOG` filter, default `info`.
pub fn init_logging(paths: &Paths) -> LogGuard {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let log_file = paths.log_file();
    let dir = log_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.log_dir.clone());
    let prefix = log_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("parabellumd")
        .to_string();
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(prefix)
        .filename_suffix("log")
        .max_log_files(7)
        .build(&dir);
    // Under launchd stderr goes to a file nobody rotates: only mirror logs there on a terminal.
    let tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let stderr_layer = |enabled: bool| {
        enabled.then(|| {
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
        })
    };
    match appender {
        Ok(appender) => {
            let stderr_layer = stderr_layer(tty);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let file_layer = tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true);
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stderr_layer)
                .with(file_layer)
                .try_init();
            LogGuard {
                _guard: Some(guard),
            }
        }
        Err(e) => {
            // No log file: stderr is the only place left.
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stderr_layer(true))
                .try_init();
            tracing::warn!(error = %e, dir = %dir.display(), "file logging unavailable");
            LogGuard { _guard: None }
        }
    }
}

/// Result of loading `config.toml`.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    /// Set when the file was invalid and a fallback (`.bak`, then defaults) was used.
    pub fallback_error: Option<String>,
}

/// `config.toml.bak` next to the config file.
pub fn backup_path(config_file: &Path) -> PathBuf {
    let mut s = config_file.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

/// Load the configuration: write defaults if absent; on a parse/validation error fall back to the last good
/// copy (`.bak`), then to defaults, and report the error. A good file is copied to `.bak`.
pub fn load_config(paths: &Paths) -> LoadedConfig {
    let file = paths.config_file();
    let bak = backup_path(&file);
    match std::fs::read_to_string(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let config = Config::default();
            if let Err(e) = write_config_file(&file, &config) {
                tracing::warn!(error = %e, "cannot write default config");
            }
            LoadedConfig {
                config,
                fallback_error: None,
            }
        }
        Err(e) => fallback(
            &bak,
            format!("lecture de {} impossible : {e}", file.display()),
        ),
        Ok(text) => match Config::from_toml(&text) {
            Ok(config) => {
                let same = std::fs::read_to_string(&bak)
                    .map(|b| b == text)
                    .unwrap_or(false);
                if !same {
                    if let Err(e) = write_private(&bak, text.as_bytes()) {
                        tracing::warn!(error = %e, "cannot write config backup");
                    }
                }
                LoadedConfig {
                    config,
                    fallback_error: None,
                }
            }
            Err(e) => fallback(&bak, format!("{} invalide : {e}", file.display())),
        },
    }
}

fn fallback(bak: &Path, error: String) -> LoadedConfig {
    tracing::error!(%error, "invalid configuration, falling back");
    if let Ok(text) = std::fs::read_to_string(bak) {
        if let Ok(config) = Config::from_toml(&text) {
            return LoadedConfig {
                config,
                fallback_error: Some(format!("{error} — dernière configuration valide utilisée")),
            };
        }
    }
    LoadedConfig {
        config: Config::default(),
        fallback_error: Some(format!("{error} — valeurs par défaut utilisées")),
    }
}

/// Validate and save atomically (0600: the file may hold API tokens), then refresh `.bak`.
pub fn save_config(paths: &Paths, config: &Config) -> Result<(), pb_core::config::ConfigError> {
    config.validate()?;
    let file = paths.config_file();
    write_config_file(&file, config)?;
    let _ = write_private(&backup_path(&file), config.to_toml()?.as_bytes());
    Ok(())
}

fn write_config_file(file: &Path, config: &Config) -> Result<(), pb_core::config::ConfigError> {
    let text = config.to_toml()?;
    let tmp = file.with_extension("toml.tmp");
    write_private(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, file)?;
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_and_permissions() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path().join("pb"));
        std::fs::create_dir_all(paths.tmp_dir().join("sub/deeper")).unwrap();
        std::fs::write(paths.tmp_dir().join("sub/deeper/f"), b"x").unwrap();
        std::fs::write(paths.tmp_dir().join("g"), b"x").unwrap();
        prepare_dirs(&paths, false).unwrap();
        for dir in paths.all_dirs() {
            assert!(dir.is_dir(), "{}", dir.display());
        }
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&paths.quarantine_dir()), 0o700);
        assert_eq!(mode(&paths.state_dir()), 0o700);
        assert_eq!(mode(&paths.tmp_dir()), 0o700);
        assert_eq!(mode(&paths.db_dir()), 0o755);
        assert_eq!(std::fs::read_dir(paths.tmp_dir()).unwrap().count(), 0);
    }

    #[test]
    fn lock_is_exclusive() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        prepare_dirs(&paths, false).unwrap();
        let l = acquire_lock(&paths).unwrap();
        assert!(acquire_lock(&paths).is_err());
        drop(l);
        assert!(acquire_lock(&paths).is_ok());
    }

    #[test]
    fn config_defaults_backup_and_fallback() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        prepare_dirs(&paths, false).unwrap();
        // Absent: defaults written.
        let l = load_config(&paths);
        assert!(l.fallback_error.is_none());
        assert_eq!(l.config, Config::default());
        assert!(paths.config_file().exists());
        assert_eq!(
            std::fs::metadata(paths.config_file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Good file: backed up.
        let mut c = Config::default();
        c.dns.enabled = true;
        save_config(&paths, &c).unwrap();
        let l = load_config(&paths);
        assert!(l.config.dns.enabled && l.fallback_error.is_none());
        assert!(backup_path(&paths.config_file()).exists());
        // Broken file: last good copy.
        std::fs::write(paths.config_file(), "[[[ nope").unwrap();
        let l = load_config(&paths);
        assert!(l.config.dns.enabled);
        assert!(l
            .fallback_error
            .as_deref()
            .unwrap()
            .contains("dernière configuration valide"));
        // Broken backup too: defaults.
        std::fs::write(
            backup_path(&paths.config_file()),
            "[ml]\nsuspicious_threshold = 9.0\n",
        )
        .unwrap();
        let l = load_config(&paths);
        assert_eq!(l.config, Config::default());
        assert!(l.fallback_error.unwrap().contains("défaut"));
    }
}
