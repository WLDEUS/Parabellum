//! Cheap system enumerations (no subprocess): mount table (`getfsstat`) and link-level interfaces
//! (`getifaddrs`). Linux implementations exist for development and tests.

use std::path::PathBuf;

/// One mounted filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    /// Device or remote source (`/dev/disk4s1`, `//user@nas/share`).
    pub mount_from: String,
    /// Filesystem type name (`apfs`, `msdos`, `exfat`, `smbfs`…).
    pub fstype: String,
    /// `f_flags` (`MNT_*`).
    pub flags: u32,
}

/// Roots under which mounts are reported as volumes.
#[cfg(target_os = "macos")]
pub const VOLUME_ROOTS: &[&str] = &["/Volumes"];
/// Roots under which mounts are reported as volumes (Linux development builds).
#[cfg(not(target_os = "macos"))]
pub const VOLUME_ROOTS: &[&str] = &["/media", "/run/media", "/mnt"];

#[cfg(target_os = "macos")]
fn c_array_to_string(arr: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = arr
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Current mount table.
#[cfg(target_os = "macos")]
pub fn list_mounts() -> Vec<MountEntry> {
    // SAFETY: a null buffer asks getfsstat for the number of mounted filesystems.
    let n = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if n <= 0 {
        return Vec::new();
    }
    let cap = (n as usize + 8).min(4096);
    let mut buf: Vec<libc::statfs> = Vec::with_capacity(cap);
    let bytes = (cap * std::mem::size_of::<libc::statfs>()) as libc::c_int;
    // SAFETY: `buf` has room for `cap` statfs structs and `bytes` is exactly that size in bytes.
    let got = unsafe { libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    if got <= 0 {
        return Vec::new();
    }
    // SAFETY: getfsstat initialized `got` (<= cap) entries.
    unsafe { buf.set_len((got as usize).min(cap)) };
    buf.iter()
        .map(|s| MountEntry {
            mount_point: PathBuf::from(c_array_to_string(&s.f_mntonname)),
            mount_from: c_array_to_string(&s.f_mntfromname),
            fstype: c_array_to_string(&s.f_fstypename),
            flags: s.f_flags,
        })
        .collect()
}

/// Current mount table (`/proc/self/mounts`, octal escapes decoded).
#[cfg(not(target_os = "macos"))]
pub fn list_mounts() -> Vec<MountEntry> {
    let Ok(text) = std::fs::read_to_string("/proc/self/mounts") else {
        return Vec::new();
    };
    parse_proc_mounts(&text)
}

#[cfg(not(target_os = "macos"))]
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn parse_proc_mounts(text: &str) -> Vec<MountEntry> {
    text.lines()
        .take(4096)
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let from = f.next()?;
            let on = f.next()?;
            let ty = f.next()?;
            Some(MountEntry {
                mount_point: PathBuf::from(unescape_mount(on)),
                mount_from: unescape_mount(from),
                fstype: ty.into(),
                flags: 0,
            })
        })
        .collect()
}

/// A network interface with its link-level (MAC) address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkInterface {
    pub name: String,
    /// Lowercase `aa:bb:cc:dd:ee:ff`; `None` when the interface has no hardware address.
    pub mac: Option<String>,
}

fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 || bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Interfaces with a link-level address (`AF_LINK` on macOS, `AF_PACKET` on Linux).
pub fn list_link_interfaces() -> Vec<LinkInterface> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head we free with freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Vec::new();
    }
    let mut out: Vec<LinkInterface> = Vec::new();
    let mut cur = ifap;
    let mut guard = 0usize;
    while !cur.is_null() && guard < 4096 {
        guard += 1;
        // SAFETY: `cur` is a node of the list returned by getifaddrs (valid until freeifaddrs).
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: ifa_addr is non-null and points to a sockaddr of at least sa_family's size.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        #[cfg(target_os = "macos")]
        let mac = if family == libc::AF_LINK {
            let sdl = ifa.ifa_addr as *const libc::sockaddr_dl;
            // SAFETY: AF_LINK addresses are sockaddr_dl; header fields are within the struct.
            let (len, nlen, alen) = unsafe {
                (
                    (*sdl).sdl_len as usize,
                    (*sdl).sdl_nlen as usize,
                    (*sdl).sdl_alen as usize,
                )
            };
            let off = std::mem::offset_of!(libc::sockaddr_dl, sdl_data);
            if alen == 6 && off + nlen + alen <= len {
                // SAFETY: bytes [off+nlen, off+nlen+alen) lie within the sdl_len bytes of this
                // variable-length sockaddr_dl allocated by getifaddrs.
                let bytes =
                    unsafe { std::slice::from_raw_parts((sdl as *const u8).add(off + nlen), alen) };
                Some(format_mac(bytes))
            } else {
                Some(None)
            }
        } else {
            None
        };
        #[cfg(not(target_os = "macos"))]
        let mac = if family == libc::AF_PACKET {
            let sll = ifa.ifa_addr as *const libc::sockaddr_ll;
            // SAFETY: AF_PACKET addresses from getifaddrs are sockaddr_ll.
            let (halen, addr) = unsafe { ((*sll).sll_halen as usize, (*sll).sll_addr) };
            Some(format_mac(&addr[..halen.min(addr.len())]))
        } else {
            None
        };
        if let Some(mac) = mac {
            if !out.iter().any(|i| i.name == name) {
                out.push(LinkInterface { name, mac });
            }
        }
    }
    // SAFETY: `ifap` came from a successful getifaddrs call and is freed exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_macs() {
        assert_eq!(
            format_mac(&[0x3c, 0x22, 0xfb, 1, 2, 3]).as_deref(),
            Some("3c:22:fb:01:02:03")
        );
        assert_eq!(format_mac(&[0; 6]), None);
        assert_eq!(format_mac(&[1, 2]), None);
    }

    #[test]
    fn enumerations_do_not_fail() {
        let mounts = list_mounts();
        assert!(mounts
            .iter()
            .any(|m| m.mount_point == std::path::Path::new("/")));
        let _ = list_link_interfaces();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parses_proc_mounts() {
        let m = parse_proc_mounts(
            "/dev/sdb1 /media/q/USB\\040KEY vfat rw 0 0\nproc /proc proc rw 0 0\n",
        );
        assert_eq!(m[0].mount_point, PathBuf::from("/media/q/USB KEY"));
        assert_eq!(m[0].fstype, "vfat");
        assert_eq!(m.len(), 2);
    }
}
