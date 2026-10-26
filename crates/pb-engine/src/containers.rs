//! Container expansion: ZIP, tar, gzip (in memory, streaming, with zip-bomb limits) everywhere;
//! DMG (`hdiutil attach -readonly -nobrowse`) and PKG (`pkgutil --expand-full`) on macOS.
//!
//! Limits (shared by all nesting levels of one top-level container, see [`Budget`]):
//! entry count, total uncompressed bytes, nesting depth; a member whose uncompressed size exceeds
//! 100× its compressed size (and 1 MiB) aborts the archive as a suspected zip bomb. The ZIP central
//! directory's declared entry count is checked *before* parsing it, so a crafted directory cannot make
//! the parser allocate millions of entries.

use crate::hashdb::Digest;
use crate::{filetype, Analysis, Budget, ContentInfo, Ctx, Engine, Rollup, IN_MEMORY_LIMIT};
use pb_core::model::{FileKind, ScanReport};
use sha2::{Digest as _, Sha256};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Uncompressed/compressed ratio above which a member is a suspected bomb.
const BOMB_RATIO: u64 = 100;
/// Members smaller than this are never considered bombs (tiny files compress extremely well).
const BOMB_MIN_BYTES: u64 = 1024 * 1024;
const READ_CHUNK: usize = 256 * 1024;

fn is_bomb(uncompressed: u64, compressed: u64) -> bool {
    uncompressed > BOMB_MIN_BYTES && uncompressed / compressed.max(1) > BOMB_RATIO
}

/// Reads a member: keeps the first `keep` bytes, hashes everything, stops after `max_total` bytes
/// (digest `None` then). `compressed` enables the streaming bomb check.
fn read_member<R: Read>(
    r: &mut R,
    keep: u64,
    max_total: u64,
    compressed: Option<u64>,
) -> Result<(Vec<u8>, Option<Digest>, u64), String> {
    let mut h = Sha256::new();
    let mut data = Vec::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        };
        if total + n as u64 > max_total {
            let allowed = (max_total - total) as usize;
            h.update(&buf[..allowed]);
            let room = keep.saturating_sub(data.len() as u64) as usize;
            data.extend_from_slice(&buf[..allowed.min(room)]);
            return Ok((data, None, max_total));
        }
        total += n as u64;
        h.update(&buf[..n]);
        let room = keep.saturating_sub(data.len() as u64) as usize;
        data.extend_from_slice(&buf[..n.min(room)]);
        if let Some(c) = compressed {
            if is_bomb(total, c) {
                return Err(format!("zip bomb suspected: more than {total} bytes from {c} compressed (ratio > {BOMB_RATIO})"));
            }
        }
    }
    Ok((data, Some(h.finalize().into()), total))
}

/// Reader counting decompressed bytes, failing on a bomb ratio against `compressed`.
struct BombGuard<R: Read> {
    inner: R,
    count: u64,
    compressed: u64,
}

impl<R: Read> Read for BombGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        if is_bomb(self.count, self.compressed) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "zip bomb suspected: {} bytes from {} compressed (ratio > {BOMB_RATIO})",
                    self.count, self.compressed
                ),
            ));
        }
        Ok(n)
    }
}

/// Entry count declared by the ZIP end-of-central-directory record (ZIP64 aware), without parsing
/// the central directory. `None` when no EOCD is found.
pub(crate) fn zip_declared_entries<R: Read + Seek>(r: &mut R) -> Option<u64> {
    let len = r.seek(SeekFrom::End(0)).ok()?;
    let tail_len = len.min(65_557);
    r.seek(SeekFrom::Start(len - tail_len)).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    r.read_exact(&mut tail).ok()?;
    let _ = r.seek(SeekFrom::Start(0));
    let pos = tail.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    let total = u16::from_le_bytes([*tail.get(pos + 10)?, *tail.get(pos + 11)?]);
    if total != 0xffff {
        return Some(u64::from(total));
    }
    let loc = pos.checked_sub(20)?;
    if tail.get(loc..loc + 4)? != b"PK\x06\x07" {
        return Some(u64::from(total));
    }
    let mut off = [0u8; 8];
    off.copy_from_slice(tail.get(loc + 8..loc + 16)?);
    let off = u64::from_le_bytes(off);
    r.seek(SeekFrom::Start(off)).ok()?;
    let mut rec = [0u8; 56];
    let ok = r.read_exact(&mut rec).is_ok();
    let _ = r.seek(SeekFrom::Start(0));
    if !ok || &rec[0..4] != b"PK\x06\x06" {
        return None;
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&rec[32..40]);
    Some(u64::from_le_bytes(n))
}

fn member_keep(declared: u64, ctx: &Ctx<'_>) -> u64 {
    if declared > ctx.opts.max_file_size {
        filetype::HEAD_LEN as u64
    } else {
        IN_MEMORY_LIMIT.min(ctx.opts.max_file_size)
    }
}

fn clean_member_name(raw: &str) -> String {
    let s = raw.trim_start_matches("./").trim_start_matches('/');
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Parsed `hdiutil attach -plist` output: (device entries, mount points).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn parse_hdiutil_attach(stdout: &[u8]) -> Option<(Vec<String>, Vec<PathBuf>)> {
    // The plist may be preceded by other text (e.g. a license agreement).
    let start = stdout
        .windows(5)
        .position(|w| w == b"<?xml")
        .or_else(|| stdout.windows(6).position(|w| w == b"<plist"))?;
    let end = stdout.windows(8).rposition(|w| w == b"</plist>")? + 8;
    let v = plist::Value::from_reader_xml(Cursor::new(stdout.get(start..end)?)).ok()?;
    let entities = v.as_dictionary()?.get("system-entities")?.as_array()?;
    let mut devs = Vec::new();
    let mut mounts = Vec::new();
    for e in entities {
        let Some(d) = e.as_dictionary() else { continue };
        if let Some(dev) = d.get("dev-entry").and_then(|x| x.as_string()) {
            devs.push(dev.to_owned());
        }
        if let Some(m) = d.get("mount-point").and_then(|x| x.as_string()) {
            mounts.push(PathBuf::from(m));
        }
    }
    Some((devs, mounts))
}

impl Engine {
    /// Expands `data` (or the on-disk file) if it is a container, scanning every member.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_container<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        a: &mut Analysis,
        kind: FileKind,
        data: &[u8],
        info: &ContentInfo<'_>,
        depth: u32,
        budget: &mut Budget,
        sink: &mut dyn FnMut(ScanReport),
    ) {
        let container = a.report.path.clone();
        let mut rollup = Rollup::default();
        let res: Result<(), String> = match kind {
            FileKind::Zip => {
                if !info.truncated {
                    self.zip_members(
                        ctx,
                        Cursor::new(data),
                        &container,
                        depth,
                        budget,
                        &mut rollup,
                        sink,
                    )
                } else if let Some(p) = info.disk_path {
                    match std::fs::File::open(p) {
                        Ok(f) => self.zip_members(
                            ctx,
                            io::BufReader::new(f),
                            &container,
                            depth,
                            budget,
                            &mut rollup,
                            sink,
                        ),
                        Err(e) => Err(format!("cannot reopen archive: {e}")),
                    }
                } else {
                    Err("archive too large to expand in memory".into())
                }
            }
            FileKind::Archive => {
                let head = &data[..data.len().min(filetype::HEAD_LEN)];
                let is_gzip = head.starts_with(&[0x1f, 0x8b]);
                let is_tar = head.get(257..262) == Some(b"ustar");
                if !(is_gzip || is_tar) {
                    Ok(()) // bzip2 / xz / 7z / rar: left to ClamAV
                } else if !info.truncated {
                    self.tar_gz_members(
                        ctx,
                        Cursor::new(data),
                        is_gzip,
                        info.size,
                        &container,
                        depth,
                        budget,
                        &mut rollup,
                        sink,
                    )
                } else if let Some(p) = info.disk_path {
                    match std::fs::File::open(p) {
                        Ok(f) => self.tar_gz_members(
                            ctx,
                            io::BufReader::new(f),
                            is_gzip,
                            info.size,
                            &container,
                            depth,
                            budget,
                            &mut rollup,
                            sink,
                        ),
                        Err(e) => Err(format!("cannot reopen archive: {e}")),
                    }
                } else {
                    Err("archive too large to expand in memory".into())
                }
            }
            FileKind::Dmg if ctx.opts.mount_dmg => self.disk_image(
                ctx,
                data,
                info,
                true,
                &container,
                depth,
                budget,
                &mut rollup,
                sink,
            ),
            FileKind::Pkg if ctx.opts.expand_pkg => self.disk_image(
                ctx,
                data,
                info,
                false,
                &container,
                depth,
                budget,
                &mut rollup,
                sink,
            ),
            _ => Ok(()),
        };
        if let Err(e) = res {
            a.note(e);
        }
        a.members = rollup;
    }

    #[allow(clippy::too_many_arguments)]
    fn zip_members<'e, R: Read + Seek>(
        &'e self,
        ctx: &mut Ctx<'e>,
        mut reader: R,
        container: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        if let Some(n) = zip_declared_entries(&mut reader) {
            if n > u64::from(budget.entries) {
                return Err(format!(
                    "archive declares {n} entries (limit {}): not expanded",
                    budget.entries
                ));
            }
        }
        let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("zip: {e}"))?;
        let mut notes: Vec<String> = Vec::new();
        for i in 0..zip.len() {
            if ctx.cancelled() {
                return Ok(());
            }
            if budget.bytes == 0 {
                return Err("archive size limit reached".into());
            }
            let mut f = match zip.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(m)) => {
                    if notes.len() < 3 {
                        notes.push(format!("entry {i}: {m}"));
                    }
                    continue;
                }
                Err(e) => return Err(format!("zip entry {i}: {e}")),
            };
            if f.is_dir() || f.is_symlink() {
                continue;
            }
            if !budget.take_entry() {
                return Err("archive entry limit reached".into());
            }
            let name = clean_member_name(f.name());
            let (declared, compressed) = (f.size(), f.compressed_size());
            if is_bomb(declared, compressed) {
                return Err(format!("zip bomb suspected: {name} declares {declared} bytes from {compressed} compressed (ratio > {BOMB_RATIO})"));
            }
            let keep = member_keep(declared, ctx);
            let (data, digest, total) = read_member(&mut f, keep, budget.bytes, Some(compressed))
                .map_err(|e| format!("{name}: {e}"))?;
            drop(f);
            budget.take_bytes(total);
            let report = self.analyze_member(
                ctx,
                format!("{container}!/{name}"),
                &data,
                total,
                digest,
                depth + 1,
                budget,
                sink,
            );
            rollup.add(&report, container);
            sink(report);
        }
        if notes.is_empty() {
            Ok(())
        } else {
            Err(notes.join("; "))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tar_gz_members<'e, R: Read>(
        &'e self,
        ctx: &mut Ctx<'e>,
        reader: R,
        is_gzip: bool,
        compressed_size: u64,
        container: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        if !is_gzip {
            return self.tar_members(ctx, reader, container, depth, budget, rollup, sink);
        }
        let mut dec = BombGuard {
            inner: flate2::read::MultiGzDecoder::new(reader),
            count: 0,
            compressed: compressed_size,
        };
        let mut first = vec![0u8; filetype::HEAD_LEN];
        let n = filetype::read_up_to(&mut dec, &mut first).map_err(|e| format!("gzip: {e}"))?;
        first.truncate(n);
        let chained = Cursor::new(first.clone()).chain(dec);
        if first.get(257..262) == Some(b"ustar") {
            return self.tar_members(ctx, chained, container, depth, budget, rollup, sink);
        }
        // Single gzip member: `name.gz` -> `name`.
        if !budget.take_entry() {
            return Err("archive entry limit reached".into());
        }
        let base = Path::new(container.rsplit("!/").next().unwrap_or(container))
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let inner = base
            .strip_suffix(".gz")
            .or_else(|| base.strip_suffix(".gzip"))
            .filter(|s| !s.is_empty())
            .unwrap_or("data")
            .to_owned();
        let mut chained = chained;
        let (data, digest, total) = read_member(
            &mut chained,
            IN_MEMORY_LIMIT.min(ctx.opts.max_file_size),
            budget.bytes,
            None,
        )?;
        budget.take_bytes(total);
        let report = self.analyze_member(
            ctx,
            format!("{container}!/{inner}"),
            &data,
            total,
            digest,
            depth + 1,
            budget,
            sink,
        );
        rollup.add(&report, container);
        sink(report);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn tar_members<'e, R: Read>(
        &'e self,
        ctx: &mut Ctx<'e>,
        reader: R,
        container: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        let mut ar = tar::Archive::new(reader);
        let entries = ar.entries().map_err(|e| format!("tar: {e}"))?;
        for entry in entries {
            if ctx.cancelled() {
                return Ok(());
            }
            let mut entry = entry.map_err(|e| format!("tar: {e}"))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            if budget.bytes == 0 {
                return Err("archive size limit reached".into());
            }
            if !budget.take_entry() {
                return Err("archive entry limit reached".into());
            }
            let name = entry
                .path()
                .map(|p| clean_member_name(&p.to_string_lossy()))
                .unwrap_or_else(|_| "?".into());
            let keep = member_keep(entry.size(), ctx);
            let (data, digest, total) = read_member(&mut entry, keep, budget.bytes, None)
                .map_err(|e| format!("tar: {name}: {e}"))?;
            budget.take_bytes(total);
            let report = self.analyze_member(
                ctx,
                format!("{container}!/{name}"),
                &data,
                total,
                digest,
                depth + 1,
                budget,
                sink,
            );
            rollup.add(&report, container);
            sink(report);
        }
        Ok(())
    }

    /// Scans every regular file under `root` (mounted DMG volume, expanded PKG) as members of
    /// `container`, without following symlinks.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn disk_tree_members<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        root: &Path,
        container: &str,
        prefix: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            if ctx.cancelled() {
                return Ok(());
            }
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }
            if budget.bytes == 0 {
                return Err("archive size limit reached".into());
            }
            if !budget.take_entry() {
                return Err("archive entry limit reached".into());
            }
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .into_owned();
            let display = if prefix.is_empty() {
                format!("{container}!/{rel}")
            } else {
                format!("{container}!/{prefix}/{rel}")
            };
            let mut a = self.analyze_disk(ctx, entry.path(), display, depth + 1, budget, sink);
            budget.take_bytes(a.report.size);
            a.finalize();
            rollup.add(&a.report, container);
            sink(a.report);
        }
        Ok(())
    }

    /// DMG (`dmg = true`) or PKG expansion; needs an on-disk file (members are copied to a temp file).
    #[allow(clippy::too_many_arguments)]
    #[cfg(target_os = "macos")]
    fn disk_image<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        data: &[u8],
        info: &ContentInfo<'_>,
        dmg: bool,
        container: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        use std::io::Write;
        let tmp_dir = self.paths.tmp_dir();
        std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("tmp dir: {e}"))?;
        // Members of an archive are copied to a temp file (removed on drop) for hdiutil / pkgutil.
        let copy = match info.disk_path {
            Some(_) => None,
            None => {
                if info.truncated {
                    return Err("disk image too large to copy out of the archive".into());
                }
                let mut f = tempfile::Builder::new()
                    .prefix("member-")
                    .tempfile_in(&tmp_dir)
                    .map_err(|e| format!("temp file: {e}"))?;
                f.write_all(data)
                    .and_then(|_| f.flush())
                    .map_err(|e| format!("temp file: {e}"))?;
                Some(f)
            }
        };
        let path: &Path = match (info.disk_path, copy.as_ref()) {
            (Some(p), _) => p,
            (None, Some(f)) => f.path(),
            (None, None) => return Err("no file to expand".into()),
        };
        if dmg {
            self.dmg_members(ctx, path, container, depth, budget, rollup, sink)
        } else {
            self.pkg_members(ctx, path, info.size, container, depth, budget, rollup, sink)
        }
    }

    /// Non-macOS: DMG/PKG are only hashed and YARA-scanned as raw files.
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(target_os = "macos"))]
    fn disk_image<'e>(
        &'e self,
        _ctx: &mut Ctx<'e>,
        _data: &[u8],
        _info: &ContentInfo<'_>,
        dmg: bool,
        _container: &str,
        _depth: u32,
        _budget: &mut Budget,
        _rollup: &mut Rollup,
        _sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        Err(format!(
            "{} expansion is macOS-only (scanned as a raw file)",
            if dmg { "DMG" } else { "PKG" }
        ))
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(target_os = "macos")]
    fn dmg_members<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        dmg: &Path,
        container: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        use std::process::Command;
        use std::time::Duration;
        const HDIUTIL: &str = "/usr/bin/hdiutil";

        /// Always detaches what was attached, even on error or panic.
        struct Detach(Vec<String>);
        impl Drop for Detach {
            fn drop(&mut self) {
                for target in &self.0 {
                    let mut cmd = Command::new(HDIUTIL);
                    cmd.arg("detach").arg(target).arg("-force");
                    match crate::proc::run(cmd, None, Duration::from_secs(60), None, 64 * 1024) {
                        Ok(o) if o.success() => return,
                        Ok(o) => {
                            tracing::warn!(target = %target, stderr = %String::from_utf8_lossy(&o.stderr), "hdiutil detach failed")
                        }
                        Err(e) => {
                            tracing::warn!(target = %target, error = %e, "hdiutil detach failed")
                        }
                    }
                }
            }
        }

        let mount_root = self.paths.tmp_dir();
        let mut cmd = Command::new(HDIUTIL);
        cmd.args([
            "attach",
            "-readonly",
            "-nobrowse",
            "-noautoopen",
            "-noverify",
            "-mountrandom",
        ])
        .arg(&mount_root)
        .arg("-plist")
        .arg(dmg)
        // Images with a license agreement: no pager, answer "Y" on stdin.
        .env("PAGER", "/usr/bin/true");
        let out = crate::proc::run(
            cmd,
            Some(b"Y\n".to_vec()),
            Duration::from_secs(180),
            Some(ctx.cancel),
            4 * 1024 * 1024,
        )
        .map_err(|e| format!("cannot run hdiutil: {e}"))?;
        let (devs, mounts) = parse_hdiutil_attach(&out.stdout).unwrap_or_default();
        // Whole-disk device first (shortest name, e.g. /dev/disk4), then each mount point.
        let mut targets: Vec<String> = devs.clone();
        targets.sort_by_key(|d| d.len());
        targets.truncate(1);
        targets.extend(mounts.iter().map(|m| m.to_string_lossy().into_owned()));
        let _guard = Detach(targets);
        if !out.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "hdiutil attach failed: {}",
                err.lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .trim()
            ));
        }
        if mounts.is_empty() {
            return Err("disk image has no mountable volume".into());
        }
        let multi = mounts.len() > 1;
        for m in &mounts {
            if !m.starts_with(&mount_root) {
                tracing::warn!(mount = %m.display(), "unexpected DMG mount point, not scanned");
                continue;
            }
            let prefix = if multi {
                m.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            self.disk_tree_members(ctx, m, container, &prefix, depth, budget, rollup, sink)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(target_os = "macos")]
    fn pkg_members<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        pkg: &Path,
        size: u64,
        container: &str,
        depth: u32,
        budget: &mut Budget,
        rollup: &mut Rollup,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Result<(), String> {
        use std::time::Duration;
        if size > ctx.opts.archive_max_total {
            return Err("package larger than the archive size limit: not expanded".into());
        }
        // Defense in depth: the untrusted package is expanded by `nobody` (when we are root), in
        // a fresh workspace owned by `nobody`, from a private copy it can read. The workspace lives
        // in the system temp dir because the daemon's own tmp/ is root-only (0700).
        let ids = crate::proc::unprivileged_ids();
        let tmp = crate::proc::unprivileged_workspace(&std::env::temp_dir(), ids)
            .map_err(|e| format!("temp dir: {e}"))?;
        let input = tmp.path().join("in.pkg");
        std::fs::copy(pkg, &input).map_err(|e| format!("cannot copy package: {e}"))?;
        if let Some((uid, gid)) = ids {
            std::os::unix::fs::chown(&input, Some(uid), Some(gid))
                .map_err(|e| format!("chown: {e}"))?;
        }
        let dest = tmp.path().join("x");
        let mut cmd = crate::proc::background_command(Path::new("/usr/sbin/pkgutil"), true);
        crate::proc::drop_privileges(&mut cmd, ids);
        cmd.arg("--expand-full").arg(&input).arg(&dest);
        let out = crate::proc::run(
            cmd,
            None,
            Duration::from_secs(600),
            Some(ctx.cancel),
            256 * 1024,
        )
        .map_err(|e| format!("cannot run pkgutil: {e}"))?;
        if !out.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "pkgutil --expand-full failed: {}",
                err.lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .trim()
            ));
        }
        self.disk_tree_members(ctx, &dest, container, "", depth, budget, rollup, sink)
        // `tmp` is removed on drop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdiutil_plist() {
        let out = br#"Software License Agreement blah
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>system-entities</key>
	<array>
		<dict>
			<key>content-hint</key><string>GUID_partition_scheme</string>
			<key>dev-entry</key><string>/dev/disk4</string>
			<key>potentially-mountable</key><false/>
		</dict>
		<dict>
			<key>content-hint</key><string>Apple_HFS</string>
			<key>dev-entry</key><string>/dev/disk4s1</string>
			<key>mount-point</key><string>/Library/Application Support/Parabellum/tmp/dmg.Ab12Cd</string>
			<key>potentially-mountable</key><true/>
		</dict>
	</array>
</dict>
</plist>
"#;
        let (devs, mounts) = parse_hdiutil_attach(out).unwrap();
        assert_eq!(devs, vec!["/dev/disk4", "/dev/disk4s1"]);
        assert_eq!(
            mounts,
            vec![PathBuf::from(
                "/Library/Application Support/Parabellum/tmp/dmg.Ab12Cd"
            )]
        );
        assert!(parse_hdiutil_attach(b"hdiutil: attach failed").is_none());
    }

    #[test]
    fn member_reader_limits() {
        let data = vec![7u8; 3 * 1024 * 1024];
        let (kept, digest, total) =
            read_member(&mut Cursor::new(&data), 1000, u64::MAX, None).unwrap();
        assert_eq!((kept.len(), total), (1000, data.len() as u64));
        assert_eq!(digest.unwrap(), <[u8; 32]>::from(Sha256::digest(&data)));
        let (_, digest, total) = read_member(&mut Cursor::new(&data), 10, 4096, None).unwrap();
        assert!(digest.is_none());
        assert_eq!(total, 4096);
        assert!(
            read_member(&mut Cursor::new(&data), 10, u64::MAX, Some(1000))
                .unwrap_err()
                .contains("zip bomb")
        );
        assert!(!is_bomb(500_000, 10));
        assert!(is_bomb(2 * 1024 * 1024, 10_000));
    }
}
