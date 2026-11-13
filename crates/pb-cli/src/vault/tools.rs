//! External tools of the vault (`hdiutil`, `lsof`, `fdesetup`): a [`Runner`] abstraction (faked in
//! tests) and pure parsers of their output. Nothing here interprets a shell string: every tool is run
//! by absolute path with an argument vector, a cleared environment and a timeout; secrets only travel
//! on stdin.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const HDIUTIL: &str = "/usr/bin/hdiutil";
pub const LSOF: &str = "/usr/sbin/lsof";
pub const FDESETUP: &str = "/usr/bin/fdesetup";

/// Result of one tool run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolOutput {
    /// Exit code (-1 when killed by a signal or the timeout).
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl ToolOutput {
    pub fn ok(&self) -> bool {
        self.status == 0 && !self.timed_out
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Runs external tools. `stdin` is written then closed (secrets go there, never in argv or env).
pub trait Runner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> io::Result<ToolOutput>;
}

/// The real thing: absolute program path, cleared environment (PATH, HOME, TMPDIR and an English
/// locale so error messages can be matched), killed after `timeout`.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> io::Result<ToolOutput> {
        if !Path::new(program).is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chemin d'outil non absolu",
            ));
        }
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "en_US.UTF-8")
            .env("LC_ALL", "en_US.UTF-8")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in ["HOME", "TMPDIR", "USER"] {
            if let Some(v) = std::env::var_os(key) {
                cmd.env(key, v);
            }
        }
        let mut child = cmd.spawn()?;
        if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
            // A tool that exits early closes the pipe: ignore EPIPE, the exit status tells the story.
            let _ = pipe.write_all(data);
            drop(pipe);
        }
        let mut out = child.stdout.take();
        let mut err = child.stderr.take();
        let out_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(o) = out.as_mut() {
                let _ = o.read_to_end(&mut buf);
            }
            buf
        });
        let err_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(e) = err.as_mut() {
                let _ = e.read_to_end(&mut buf);
            }
            buf
        });
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if start.elapsed() >= timeout {
                timed_out = true;
                let _ = child.kill();
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = out_thread.join().unwrap_or_default();
        let stderr = err_thread.join().unwrap_or_default();
        Ok(ToolOutput {
            status: status.code().unwrap_or(-1),
            stdout,
            stderr,
            timed_out,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// hdiutil -plist parsers
// ---------------------------------------------------------------------------------------------

/// One entry of `system-entities` (attach / info).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SystemEntity {
    #[serde(rename = "dev-entry", default)]
    pub dev_entry: String,
    #[serde(rename = "mount-point", default)]
    pub mount_point: Option<String>,
    #[serde(rename = "content-hint", default)]
    pub content_hint: Option<String>,
    #[serde(rename = "volume-kind", default)]
    pub volume_kind: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AttachPlist {
    #[serde(rename = "system-entities", default)]
    system_entities: Vec<SystemEntity>,
}

#[derive(Debug, Default, Deserialize)]
struct InfoImage {
    #[serde(rename = "image-path", default)]
    image_path: String,
    #[serde(rename = "system-entities", default)]
    system_entities: Vec<SystemEntity>,
}

#[derive(Debug, Default, Deserialize)]
struct InfoPlist {
    #[serde(default)]
    images: Vec<InfoImage>,
}

/// An attached image: whole-disk device (what `hdiutil detach` takes) and mounted volume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attached {
    pub image_path: String,
    /// `/dev/diskN` of the image itself (first whole disk listed).
    pub device: String,
    pub mount_point: Option<String>,
}

/// `/dev/diskN` without a slice suffix.
fn is_whole_disk(dev: &str) -> bool {
    dev.strip_prefix("/dev/disk")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn attached_from(image_path: String, entities: &[SystemEntity]) -> Option<Attached> {
    let device = entities
        .iter()
        .map(|e| e.dev_entry.as_str())
        .find(|d| is_whole_disk(d))?
        .to_string();
    let mount_point = entities
        .iter()
        .filter_map(|e| e.mount_point.clone())
        .find(|m| !m.is_empty());
    Some(Attached {
        image_path,
        device,
        mount_point,
    })
}

fn plist_err(e: plist::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("sortie de hdiutil illisible : {e}"),
    )
}

/// `hdiutil attach -plist`.
pub fn parse_attach(xml: &[u8]) -> io::Result<Attached> {
    let p: AttachPlist = plist::from_bytes(xml).map_err(plist_err)?;
    attached_from(String::new(), &p.system_entities).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "hdiutil attach : aucun disque dans la réponse",
        )
    })
}

/// `hdiutil info -plist`: every attached image.
pub fn parse_info(xml: &[u8]) -> io::Result<Vec<Attached>> {
    let p: InfoPlist = plist::from_bytes(xml).map_err(plist_err)?;
    Ok(p.images
        .into_iter()
        .filter_map(|i| attached_from(i.image_path, &i.system_entities))
        .collect())
}

/// `hdiutil create -plist`: the created image path(s).
pub fn parse_create(xml: &[u8]) -> io::Result<Vec<String>> {
    plist::from_bytes::<Vec<String>>(xml).map_err(plist_err)
}

/// Keys of `<bundle>.sparsebundle/Info.plist` (stored in clear next to the encrypted bands).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct BundleInfo {
    /// Maximum size of the image, in bytes.
    #[serde(default)]
    pub size: u64,
    #[serde(rename = "band-size", default)]
    pub band_size: u64,
    #[serde(rename = "diskimage-bundle-type", default)]
    pub bundle_type: String,
}

pub fn parse_bundle_info(xml: &[u8]) -> io::Result<BundleInfo> {
    plist::from_bytes(xml).map_err(plist_err)
}

/// hdiutil reported a wrong passphrase.
pub fn is_auth_error(stderr: &str) -> bool {
    let l = stderr.to_ascii_lowercase();
    l.contains("authentication error") || l.contains("authentification")
}

/// hdiutil could not unmount because files are open.
pub fn is_busy(out: &ToolOutput) -> bool {
    out.status == 16
        || out
            .stderr_text()
            .to_ascii_lowercase()
            .contains("resource busy")
}

// ---------------------------------------------------------------------------------------------
// lsof
// ---------------------------------------------------------------------------------------------

/// A process holding a file open inside the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub pid: i32,
    pub command: String,
    /// Open files (at most [`MAX_HOLDER_PATHS`]).
    pub paths: Vec<String>,
}

pub const MAX_HOLDER_PATHS: usize = 5;

/// `lsof -F pcn` output (`p<pid>`, `c<command>`, `f<fd>`, `n<name>` lines), grouped by process.
pub fn parse_lsof(out: &str) -> Vec<Holder> {
    let mut v: Vec<Holder> = Vec::new();
    for line in out.lines() {
        let (tag, rest) = match line.char_indices().nth(1) {
            Some((i, _)) => (&line[..i], &line[i..]),
            None => continue,
        };
        match tag {
            "p" => {
                if let Ok(pid) = rest.trim().parse::<i32>() {
                    v.push(Holder {
                        pid,
                        command: String::new(),
                        paths: Vec::new(),
                    });
                }
            }
            "c" => {
                if let Some(h) = v.last_mut() {
                    h.command = rest.to_string();
                }
            }
            "n" => {
                if let Some(h) = v.last_mut() {
                    if h.paths.len() < MAX_HOLDER_PATHS && !h.paths.iter().any(|p| p == rest) {
                        h.paths.push(rest.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    v
}

// ---------------------------------------------------------------------------------------------
// FileVault
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileVaultState {
    On,
    Off,
    Encrypting,
    Decrypting,
    #[default]
    Unknown,
}

/// `fdesetup status` (runs without root).
pub fn parse_fdesetup(out: &str) -> FileVaultState {
    let l = out.to_ascii_lowercase();
    if l.contains("decryption in progress") {
        FileVaultState::Decrypting
    } else if l.contains("encryption in progress") {
        FileVaultState::Encrypting
    } else if l.contains("filevault is on") {
        FileVaultState::On
    } else if l.contains("filevault is off") {
        FileVaultState::Off
    } else {
        FileVaultState::Unknown
    }
}

// ---------------------------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------------------------

/// hdiutil size argument (`500m`, `20g`, `1.5t`) -> bytes. Accepts `Go`/`Mo`/`To` (French) too.
pub fn parse_size(s: &str) -> Option<u64> {
    let t = s.trim().to_ascii_lowercase();
    let t = t
        .strip_suffix('o')
        .or_else(|| t.strip_suffix('b'))
        .unwrap_or(&t);
    let (num, mult) = match t.chars().last()? {
        'k' => (&t[..t.len() - 1], 1u64 << 10),
        'm' => (&t[..t.len() - 1], 1 << 20),
        'g' => (&t[..t.len() - 1], 1 << 30),
        't' => (&t[..t.len() - 1], 1 << 40),
        _ => return None,
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let n: f64 = num.parse().ok()?;
    if !n.is_finite() || n <= 0.0 {
        return None;
    }
    Some((n * mult as f64) as u64)
}

/// Bytes -> hdiutil argument in whole megabytes (`20480m`), the most portable form.
pub fn hdiutil_size_arg(bytes: u64) -> String {
    format!("{}m", bytes.div_ceil(1 << 20))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hdiutil attach -plist` of an encrypted APFS sparse bundle (macOS 14), trimmed of nothing.
    pub const ATTACH_APFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>system-entities</key>
	<array>
		<dict>
			<key>content-hint</key>
			<string>GUID_partition_scheme</string>
			<key>dev-entry</key>
			<string>/dev/disk4</string>
			<key>potentially-mountable</key>
			<false/>
			<key>unmapped-content-hint</key>
			<string>GUID_partition_scheme</string>
		</dict>
		<dict>
			<key>content-hint</key>
			<string>Apple_APFS</string>
			<key>dev-entry</key>
			<string>/dev/disk4s1</string>
			<key>potentially-mountable</key>
			<true/>
			<key>unmapped-content-hint</key>
			<string>7C3457EF-0000-11AA-AA11-00306543ECAC</string>
		</dict>
		<dict>
			<key>content-hint</key>
			<string>41504653-0000-11AA-AA11-00306543ECAC</string>
			<key>dev-entry</key>
			<string>/dev/disk5s1</string>
			<key>mount-point</key>
			<string>/Volumes/Coffre</string>
			<key>potentially-mountable</key>
			<true/>
			<key>unmapped-content-hint</key>
			<string>41504653-0000-11AA-AA11-00306543ECAC</string>
			<key>volume-kind</key>
			<string>apfs</string>
		</dict>
		<dict>
			<key>content-hint</key>
			<string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
			<key>dev-entry</key>
			<string>/dev/disk5</string>
			<key>potentially-mountable</key>
			<false/>
			<key>unmapped-content-hint</key>
			<string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
		</dict>
	</array>
</dict>
</plist>
"#;

    /// `hdiutil info -plist` with the vault and an unrelated read-only DMG attached.
    pub const INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>framework</key>
	<string>671.100.2</string>
	<key>images</key>
	<array>
		<dict>
			<key>autodiskmount</key>
			<true/>
			<key>icon-path</key>
			<string>/System/Library/PrivateFrameworks/DiskImages.framework/Resources/CDiskImage.icns</string>
			<key>image-encrypted</key>
			<false/>
			<key>image-path</key>
			<string>/Users/camille/Downloads/Firefox 132.0.dmg</string>
			<key>image-type</key>
			<string>UDIF read-only compressed (zlib)</string>
			<key>owner-uid</key>
			<integer>501</integer>
			<key>removable</key>
			<true/>
			<key>system-entities</key>
			<array>
				<dict>
					<key>content-hint</key>
					<string>GUID_partition_scheme</string>
					<key>dev-entry</key>
					<string>/dev/disk6</string>
					<key>potentially-mountable</key>
					<false/>
				</dict>
				<dict>
					<key>content-hint</key>
					<string>Apple_HFS</string>
					<key>dev-entry</key>
					<string>/dev/disk6s1</string>
					<key>mount-point</key>
					<string>/Volumes/Firefox</string>
					<key>potentially-mountable</key>
					<true/>
					<key>volume-kind</key>
					<string>hfs</string>
				</dict>
			</array>
			<key>writeable</key>
			<false/>
		</dict>
		<dict>
			<key>autodiskmount</key>
			<true/>
			<key>image-encrypted</key>
			<true/>
			<key>image-path</key>
			<string>/Users/camille/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle</string>
			<key>image-type</key>
			<string>sparse bundle disk image</string>
			<key>owner-uid</key>
			<integer>501</integer>
			<key>removable</key>
			<true/>
			<key>system-entities</key>
			<array>
				<dict>
					<key>content-hint</key>
					<string>GUID_partition_scheme</string>
					<key>dev-entry</key>
					<string>/dev/disk4</string>
					<key>potentially-mountable</key>
					<false/>
				</dict>
				<dict>
					<key>content-hint</key>
					<string>Apple_APFS</string>
					<key>dev-entry</key>
					<string>/dev/disk4s1</string>
					<key>potentially-mountable</key>
					<true/>
				</dict>
				<dict>
					<key>content-hint</key>
					<string>41504653-0000-11AA-AA11-00306543ECAC</string>
					<key>dev-entry</key>
					<string>/dev/disk5s1</string>
					<key>mount-point</key>
					<string>/Volumes/Coffre</string>
					<key>potentially-mountable</key>
					<true/>
					<key>volume-kind</key>
					<string>apfs</string>
				</dict>
				<dict>
					<key>content-hint</key>
					<string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
					<key>dev-entry</key>
					<string>/dev/disk5</string>
					<key>potentially-mountable</key>
					<false/>
				</dict>
			</array>
			<key>writeable</key>
			<true/>
		</dict>
	</array>
	<key>revision</key>
	<string>671.100.2</string>
	<key>vendor</key>
	<string>Apple</string>
</dict>
</plist>
"#;

    pub const CREATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<string>/Users/camille/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle</string>
</array>
</plist>
"#;

    pub const BUNDLE_INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>band-size</key>
	<integer>8388608</integer>
	<key>bundle-backingstore-version</key>
	<integer>2</integer>
	<key>diskimage-bundle-type</key>
	<string>com.apple.diskimage.sparsebundle</string>
	<key>size</key>
	<integer>21474836480</integer>
</dict>
</plist>
"#;

    #[test]
    fn attach_plist() {
        let a = parse_attach(ATTACH_APFS.as_bytes()).unwrap();
        assert_eq!(a.device, "/dev/disk4");
        assert_eq!(a.mount_point.as_deref(), Some("/Volumes/Coffre"));
        assert!(parse_attach(b"<plist><dict/></plist>").is_err());
        assert!(parse_attach(b"garbage").is_err());
    }

    #[test]
    fn info_plist() {
        let v = parse_info(INFO.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].device, "/dev/disk6");
        assert_eq!(v[0].mount_point.as_deref(), Some("/Volumes/Firefox"));
        assert!(v[1].image_path.ends_with("Vault/Coffre.sparsebundle"));
        assert_eq!(v[1].device, "/dev/disk4");
        assert_eq!(v[1].mount_point.as_deref(), Some("/Volumes/Coffre"));
        // Nothing attached.
        let empty = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>framework</key><string>671</string><key>images</key><array/></dict></plist>"#;
        assert!(parse_info(empty.as_bytes()).unwrap().is_empty());
        let no_images =
            r#"<plist version="1.0"><dict><key>vendor</key><string>Apple</string></dict></plist>"#;
        assert!(parse_info(no_images.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn create_and_bundle_plists() {
        let v = parse_create(CREATE.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].ends_with("Coffre.sparsebundle"));
        let b = parse_bundle_info(BUNDLE_INFO.as_bytes()).unwrap();
        assert_eq!(b.size, 20 << 30);
        assert_eq!(b.band_size, 8 << 20);
        assert_eq!(b.bundle_type, "com.apple.diskimage.sparsebundle");
    }

    #[test]
    fn whole_disks() {
        assert!(is_whole_disk("/dev/disk4"));
        assert!(is_whole_disk("/dev/disk12"));
        assert!(!is_whole_disk("/dev/disk4s1"));
        assert!(!is_whole_disk("/dev/disk"));
        assert!(!is_whole_disk("/dev/rdisk4"));
    }

    #[test]
    fn errors() {
        assert!(is_auth_error(
            "hdiutil: attach failed - Authentication error"
        ));
        assert!(!is_auth_error(
            "hdiutil: attach failed - No such file or directory"
        ));
        let busy = ToolOutput {
            status: 16,
            stderr: b"hdiutil: couldn't unmount \"disk4\" - Resource busy\n".to_vec(),
            ..Default::default()
        };
        assert!(is_busy(&busy));
        let other = ToolOutput {
            status: 1,
            stderr: b"hdiutil: detach failed - No such file or directory".to_vec(),
            ..Default::default()
        };
        assert!(!is_busy(&other));
    }

    #[test]
    fn lsof_output() {
        let out = "p812\ncPreview\nf12\nn/Volumes/Coffre/Impôts 2026.pdf\nf13\nn/Volumes/Coffre/Impôts 2026.pdf\np90\ncbash\nfcwd\nn/Volumes/Coffre\n";
        let h = parse_lsof(out);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].pid, 812);
        assert_eq!(h[0].command, "Preview");
        assert_eq!(h[0].paths, vec!["/Volumes/Coffre/Impôts 2026.pdf"]);
        assert_eq!(h[1].command, "bash");
        assert!(parse_lsof("").is_empty());
        assert!(parse_lsof("pnope\nn/x\n").is_empty());
    }

    #[test]
    fn filevault() {
        assert_eq!(parse_fdesetup("FileVault is On.\n"), FileVaultState::On);
        assert_eq!(parse_fdesetup("FileVault is Off.\n"), FileVaultState::Off);
        assert_eq!(
            parse_fdesetup("FileVault is On.\nEncryption in progress: Percent completed = 34.5\n"),
            FileVaultState::Encrypting
        );
        assert_eq!(
            parse_fdesetup("FileVault is On.\nDecryption in progress: Percent completed = 3\n"),
            FileVaultState::Decrypting
        );
        assert_eq!(parse_fdesetup(""), FileVaultState::Unknown);
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("20g"), Some(20 << 30));
        assert_eq!(parse_size("20G"), Some(20 << 30));
        assert_eq!(parse_size("20 Go"), None);
        assert_eq!(parse_size("20Go"), Some(20 << 30));
        assert_eq!(parse_size("500m"), Some(500 << 20));
        assert_eq!(parse_size("1.5t"), Some(3 << 39));
        assert_eq!(parse_size("0g"), None);
        assert_eq!(parse_size("-1g"), None);
        assert_eq!(parse_size("g"), None);
        assert_eq!(parse_size("12"), None);
        assert_eq!(parse_size("1e3g"), None);
        assert_eq!(hdiutil_size_arg(20 << 30), "20480m");
        assert_eq!(hdiutil_size_arg((20 << 30) + 1), "20481m");
    }

    #[test]
    fn system_runner_uses_stdin_and_timeout() {
        let r = SystemRunner;
        let o = r
            .run("/bin/cat", &[], Some(b"secret\0"), Duration::from_secs(5))
            .unwrap();
        assert!(o.ok());
        assert_eq!(o.stdout, b"secret\0");
        let o = r
            .run(
                "/bin/sleep",
                &["5".into()],
                None,
                Duration::from_millis(200),
            )
            .unwrap();
        assert!(o.timed_out);
        assert!(!o.ok());
        assert!(r.run("sleep", &[], None, Duration::from_secs(1)).is_err());
    }
}
