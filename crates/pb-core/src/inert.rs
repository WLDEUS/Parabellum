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

/// Options that take a value (`osascript -l JavaScript`, `python -W ignore`, `awk -F,`, `ruby -r lib`…):
/// the value is not the script.
const VALUED_OPTIONS: &[&str] = &[
    "-l", "-s", "-W", "-X", "-F", "-v", "-I", "-r", "-o", "-O", "-x",
];

/// `interpreter <options> /abs/file.json …`: the absolute path of an inert-extension file run as the
/// script (the disguise that inert-text skipping would otherwise let through). Only the script position
/// counts: in `python3 /opt/tool.py /data/x.json` the JSON is data, not code. Inline code (`-c`, `-e`,
/// `-m`) has no file. `awk -f FILE` names its program file explicitly; awk's first positional is
/// program text. Relative paths are ignored (eslogger gives no working directory).
pub fn disguised_script<'a>(exe: &str, args: &'a [String]) -> Option<&'a str> {
    let name = interpreter_name(exe)?;
    let inert_abs = |a: &'a String| -> Option<&'a str> {
        (a.starts_with('/') && has_inert_extension(Path::new(a))).then_some(a.as_str())
    };
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "-e" | "-m" => return None,
            "-f" if name == "awk" => return inert_abs(it.next()?),
            v if VALUED_OPTIONS.contains(&v) => {
                it.next();
            }
            "--" => return it.next().and_then(inert_abs),
            v if v.starts_with('-') => {}
            _ => return inert_abs(a),
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
        let run = |exe, a: &[&str]| disguised_script(exe, &v(a)).map(str::to_string);
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
}
