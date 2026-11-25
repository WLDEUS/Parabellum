//! Plain text that nothing on macOS executes by itself: source code, rule sources, data files.
//!
//! Pattern rules (YARA / heuristics) describe what malware *does*, so at rest they fire on any text that
//! merely talks about it: our own rules, test samples, security write-ups. The engine skips them on
//! these files at rest. The one way such a file turns dangerous is being handed to an interpreter
//! (`sh payload.json`, `osascript notes.md`): the real-time monitor scans it fully at that moment.
//! Plain `.txt` is deliberately absent (common payload staging name, always scanned).

use std::path::Path;

pub const INERT_TEXT_EXTENSIONS: &[&str] = &[
    "rs", "swift", "c", "h", "cc", "cpp", "hpp", "m", "mm", "go", "java", "kt", "yar", "yara",
    "json", "toml", "yaml", "yml", "md", "lock",
];

/// Extension in [`INERT_TEXT_EXTENSIONS`] (case-insensitive). Says nothing about the content.
pub fn has_inert_extension(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        INERT_TEXT_EXTENSIONS
            .iter()
            .any(|x| x.eq_ignore_ascii_case(e))
    })
}

/// In-progress download / temporary names that the file watchers skip at rest (`.crdownload`,
/// `.part`, `.partial`, `.tmp`, Office `~$` locks, anything inside a Safari `.download` bundle).
pub fn has_transient_name(path: &Path) -> bool {
    let mut components = path.components().peekable();
    while let Some(c) = components.next() {
        let lower = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        if lower.ends_with(".download") {
            return true;
        }
        if components.peek().is_none()
            && (lower.ends_with(".crdownload")
                || lower.ends_with(".part")
                || lower.ends_with(".partial")
                || lower.ends_with(".tmp")
                || lower.starts_with("~$"))
        {
            return true;
        }
    }
    false
}

/// Skipped at rest, so it must be scanned when an interpreter runs it as its script.
fn skipped_at_rest(path: &Path) -> bool {
    has_inert_extension(path) || has_transient_name(path)
}

/// Shells and script interpreters that run a file given as argument.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "tcsh",
    "csh",
    "fish",
    "osascript",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "php",
    "lua",
    "tclsh",
    "swift",
    "jsc",
    "awk",
    "osacompile",
];

fn interpreter_name(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&base).then_some(base)
}

/// Options that take a separate value, per interpreter (`osascript -l JavaScript`, `python -W ignore`,
/// `awk -F ,`, `ruby -r lib`, `bash -o posix`): the value is not the script. Per interpreter because
/// one global list got it wrong both ways: `-x` takes no value in `sh -x /tmp/p.json` (trace) nor in
/// python (skip first line), so treating it as valued hid the script (audit FILE-8).
fn valued_options(name: &str) -> &'static [&'static str] {
    match name {
        "sh" | "bash" | "zsh" | "dash" | "ksh" => &["-o", "+o", "-O", "+O"],
        "python" | "python3" => &["-W", "-X"],
        "osascript" | "osacompile" => &["-l", "-s", "-o"],
        "ruby" => &["-r", "-I", "-C", "-E", "-F"],
        "node" => &[
            "-r",
            "--require",
            "--import",
            "--loader",
            "--conditions",
            "-C",
        ],
        "php" => &["-c", "-d", "-z"],
        "lua" => &["-l"],
        "awk" => &["-F", "-v"],
        "perl" => &["-I"],
        _ => &[],
    }
}

/// Options that mean "the code is inline, there is no script file".
fn inline_options(name: &str) -> &'static [&'static str] {
    match name {
        "python" | "python3" => &["-c", "-m"],
        "node" => &["-e", "--eval", "-p", "--print"],
        "php" => &["-r"],
        "perl" => &["-e", "-E"],
        _ => &["-c", "-e"],
    }
}

/// `interpreter <options> file.json …`: the path of a file skipped at rest (inert extension or
/// temporary name, `sh /tmp/x.part`) run as the script: the disguise those skips would otherwise let
/// through (audit FILE-3). Only the script position counts:
/// in `python3 /opt/tool.py /data/x.json` the JSON is data, not code. Inline code (`-c`, `-e`, `-m`…)
/// has no file. `awk -f FILE` / `php -f FILE` name their program file explicitly; awk's first
/// positional is program text. A relative path is resolved against the process working directory
/// when eslogger gives it, and ignored otherwise.
pub fn disguised_script(exe: &str, args: &[String], cwd: Option<&str>) -> Option<String> {
    let name = interpreter_name(exe)?;
    let inert = |a: &String| -> Option<String> {
        if !skipped_at_rest(Path::new(a)) {
            return None;
        }
        if a.starts_with('/') {
            return Some(a.clone());
        }
        let dir = cwd.filter(|c| c.starts_with('/'))?;
        Some(format!("{}/{a}", dir.trim_end_matches('/')))
    };
    let valued = valued_options(name);
    let inline = inline_options(name);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            v if inline.contains(&v) => return None,
            "-f" if name == "awk" || name == "php" => return inert(it.next()?),
            v if valued.contains(&v) => {
                it.next();
            }
            "--" => return it.next().and_then(inert),
            v if v.starts_with('-') || (v.starts_with('+') && name != "awk") => {}
            _ if name == "awk" => return None,
            _ => return inert(a),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn extensions() {
        assert!(has_inert_extension(Path::new("/r/rules/x.YAR")));
        assert!(!has_inert_extension(Path::new("/tmp/payload.txt")));
        assert!(!has_inert_extension(Path::new("/tmp/run.sh")));
        assert!(!has_inert_extension(Path::new("/tmp/noext")));
    }

    #[test]
    fn disguised_scripts() {
        let run = |exe, a: &[&str]| disguised_script(exe, &v(a), None);
        assert_eq!(
            run("/bin/sh", &["sh", "/tmp/p.json"]).as_deref(),
            Some("/tmp/p.json")
        );
        assert_eq!(
            run(
                "/usr/bin/osascript",
                &["osascript", "-l", "JavaScript", "/Users/Shared/x.md"]
            )
            .as_deref(),
            Some("/Users/Shared/x.md")
        );
        assert_eq!(
            run("/opt/homebrew/bin/python3.12", &["python3", "/a/b.yaml"]).as_deref(),
            Some("/a/b.yaml")
        );
        // Normal scripts are scanned at rest already; inline code has no file; non-interpreters ignored.
        assert_eq!(run("/bin/zsh", &["zsh", "/tmp/run.sh"]), None);
        assert_eq!(run("/bin/sh", &["sh", "-c", "cat /tmp/x.json"]), None);
        assert_eq!(run("/usr/bin/cat", &["cat", "/tmp/x.json"]), None);
        assert_eq!(run("/bin/sh", &["sh", "rel/x.json"]), None);
        // Data after the script is not the script.
        assert_eq!(
            run(
                "/usr/bin/python3",
                &["python3", "/opt/tool.py", "/data/x.json"]
            ),
            None
        );
        assert_eq!(
            run("/usr/bin/awk", &["awk", "{print}", "/data/x.json"]),
            None
        );
        assert_eq!(
            run("/usr/bin/awk", &["awk", "-f", "/tmp/prog.md", "/data/x"]).as_deref(),
            Some("/tmp/prog.md")
        );
        assert_eq!(
            run("/bin/sh", &["sh", "--", "/tmp/p.yaml"]).as_deref(),
            Some("/tmp/p.yaml")
        );
        assert_eq!(
            run("/usr/bin/python3", &["python3", "-W", "/x.json", "/y.json"]).as_deref(),
            Some("/y.json")
        );
    }

    #[test]
    fn flags_without_value_and_relative_paths() {
        let run = |exe, a: &[&str], cwd| disguised_script(exe, &v(a), cwd);
        // `-x` is a flag for sh and python: the next word is the script (audit FILE-8).
        assert_eq!(
            run("/bin/sh", &["sh", "-x", "/tmp/p.json"], None).as_deref(),
            Some("/tmp/p.json")
        );
        assert_eq!(
            run("/usr/bin/python3", &["python3", "-x", "/tmp/p.yaml"], None).as_deref(),
            Some("/tmp/p.yaml")
        );
        assert_eq!(
            run("/bin/bash", &["bash", "-o", "posix", "/tmp/p.md"], None).as_deref(),
            Some("/tmp/p.md")
        );
        // `node -r mod x.json` preloads mod; x.json is the entry.
        assert_eq!(
            run(
                "/opt/homebrew/bin/node",
                &["node", "-r", "/a/b.json", "/c/d.json"],
                None
            )
            .as_deref(),
            Some("/c/d.json")
        );
        assert_eq!(
            run("/usr/bin/php", &["php", "-f", "/tmp/x.txt.yml"], None).as_deref(),
            Some("/tmp/x.txt.yml")
        );
        assert_eq!(
            run("/usr/bin/perl", &["perl", "-e", "1", "/x.json"], None),
            None
        );
        // Relative: resolved against the working directory when known, ignored otherwise.
        assert_eq!(
            run("/bin/sh", &["sh", "p.json"], Some("/Users/Shared/")).as_deref(),
            Some("/Users/Shared/p.json")
        );
        assert_eq!(run("/bin/sh", &["sh", "p.json"], None), None);
        assert_eq!(run("/bin/sh", &["sh", "p.json"], Some("rel")), None);
        // Temporary names are skipped at rest too.
        assert_eq!(
            run(
                "/bin/zsh",
                &["zsh", "/Users/q/Downloads/x.crdownload"],
                None
            )
            .as_deref(),
            Some("/Users/q/Downloads/x.crdownload")
        );
        assert_eq!(
            run(
                "/bin/sh",
                &["sh", "/Users/q/Downloads/a.download/run"],
                None
            )
            .as_deref(),
            Some("/Users/q/Downloads/a.download/run")
        );
    }
}
