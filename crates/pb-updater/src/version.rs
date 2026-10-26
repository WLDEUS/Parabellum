//! Version parsing and comparison.
//!
//! - Threat-DB versions are `YYYY.MM.DD.N` and compare numerically field by field.
//! - Third-party release versions (`1.5.4`, `v4.5.3`, `clamav-1.5.4`, `2.1.20`) compare numerically on
//!   their dotted numeric core; missing fields count as 0.
//! - `min_client_version` uses semver.

use std::cmp::Ordering;

/// Parse a threat-DB version `YYYY.MM.DD.N` (exactly four numeric fields).
pub fn parse_db_version(s: &str) -> Option<[u64; 4]> {
    let mut out = [0u64; 4];
    let mut parts = s.split('.');
    for slot in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 10 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = p.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Compare two threat-DB versions; `None` if either is malformed.
pub fn compare_db_versions(a: &str, b: &str) -> Option<Ordering> {
    Some(parse_db_version(a)?.cmp(&parse_db_version(b)?))
}

/// Extract the dotted numeric core of a release tag / version string:
/// `v4.5.3` → `[4,5,3]`, `clamav-1.5.4` → `[1,5,4]`, `2.1.20` → `[2,1,20]`, `5.24.0-rc1` → `[5,24,0]`.
pub fn parse_release_version(s: &str) -> Option<Vec<u64>> {
    let start = s.find(|c: char| c.is_ascii_digit())?;
    let core: String = s[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Vec<u64> = core
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.is_empty() || parts.len() > 6 {
        return None;
    }
    Some(parts)
}

/// Normalized display form of a release version (`v4.5.3` → `4.5.3`).
pub fn normalize_release_version(s: &str) -> Option<String> {
    parse_release_version(s).map(|v| v.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

/// Compare two release versions numerically (missing fields = 0). Unparsable sorts lowest.
pub fn compare_release_versions(a: &str, b: &str) -> Ordering {
    match (parse_release_version(a), parse_release_version(b)) {
        (Some(x), Some(y)) => {
            let n = x.len().max(y.len());
            for i in 0..n {
                let (p, q) = (
                    x.get(i).copied().unwrap_or(0),
                    y.get(i).copied().unwrap_or(0),
                );
                match p.cmp(&q) {
                    Ordering::Equal => continue,
                    o => return o,
                }
            }
            Ordering::Equal
        }
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

/// True when `current` (semver) satisfies `min_required` (semver). Errors on malformed input.
pub fn client_satisfies(min_required: &str, current: &str) -> Result<bool, String> {
    let req = semver::Version::parse(min_required.trim())
        .map_err(|e| format!("min_client_version invalide '{min_required}': {e}"))?;
    let cur = semver::Version::parse(current.trim())
        .map_err(|e| format!("version client invalide '{current}': {e}"))?;
    Ok(cur >= req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_versions() {
        assert_eq!(parse_db_version("2026.10.25.1"), Some([2026, 10, 25, 1]));
        assert!(parse_db_version("2026.10.25").is_none());
        assert!(parse_db_version("2026.10.25.1.2").is_none());
        assert!(parse_db_version("2026.10.x.1").is_none());
        assert!(parse_db_version("../x").is_none());
        assert_eq!(
            compare_db_versions("2026.10.25.2", "2026.10.25.10"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_db_versions("2026.11.1.1", "2026.10.31.9"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_db_versions("2026.10.25.1", "2026.10.25.1"),
            Some(Ordering::Equal)
        );
        assert_eq!(compare_db_versions("bad", "2026.10.25.1"), None);
    }

    #[test]
    fn release_versions() {
        assert_eq!(parse_release_version("v4.5.3"), Some(vec![4, 5, 3]));
        assert_eq!(parse_release_version("clamav-1.5.4"), Some(vec![1, 5, 4]));
        assert_eq!(parse_release_version("5.24.0-rc1"), Some(vec![5, 24, 0]));
        assert_eq!(parse_release_version("db-latest"), None);
        assert_eq!(
            normalize_release_version("v2.5.2").as_deref(),
            Some("2.5.2")
        );
        assert_eq!(
            compare_release_versions("1.5.10", "1.5.9"),
            Ordering::Greater
        );
        assert_eq!(compare_release_versions("v2.1", "2.1.0"), Ordering::Equal);
        assert_eq!(
            compare_release_versions("2.1.20", "2.1.3"),
            Ordering::Greater
        );
        assert_eq!(compare_release_versions("x", "0.0.1"), Ordering::Less);
    }

    #[test]
    fn semver_gate() {
        assert_eq!(client_satisfies("0.1.0", "0.1.0"), Ok(true));
        assert_eq!(client_satisfies("0.2.0", "0.1.9"), Ok(false));
        assert_eq!(client_satisfies("1.0.0", "1.10.0"), Ok(true));
        assert!(client_satisfies("x", "0.1.0").is_err());
    }
}
