//! GitHub Releases API model and helpers.

use crate::http::{Http, OCTET_STREAM};
#[cfg(test)]
use crate::version::{compare_release_versions, parse_release_version};
use crate::UpdateError;
use serde::{Deserialize, Serialize};

/// Production GitHub API base.
pub(crate) const GITHUB_API: &str = "https://api.github.com";
/// Max size of a releases JSON document.
pub(crate) const MAX_RELEASES_JSON: u64 = 8 * 1024 * 1024;

/// Subset of a GitHub release object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct GhRelease {
    pub(crate) tag_name: String,
    #[serde(default)]
    pub(crate) draft: bool,
    #[serde(default)]
    pub(crate) prerelease: bool,
    #[serde(default)]
    pub(crate) html_url: Option<String>,
    #[serde(default)]
    pub(crate) assets: Vec<GhAsset>,
}

/// Subset of a GitHub release asset object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct GhAsset {
    pub(crate) name: String,
    /// API URL (`/repos/o/r/releases/assets/<id>`): returns the binary with `Accept: application/octet-stream`,
    /// the only way to download assets of a private repository.
    pub(crate) url: String,
    pub(crate) browser_download_url: String,
    #[serde(default)]
    pub(crate) size: u64,
}

impl GhRelease {
    pub(crate) fn asset(&self, name: &str) -> Option<&GhAsset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

/// How to download an asset: URL + optional `Accept` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AssetSource {
    pub(crate) url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) accept: Option<String>,
}

impl AssetSource {
    /// Prefer the API URL when a token is configured (private repos), the public download URL otherwise.
    pub(crate) fn for_asset(asset: &GhAsset, has_token: bool) -> Self {
        if has_token && !asset.url.is_empty() {
            Self {
                url: asset.url.clone(),
                accept: Some(OCTET_STREAM.to_string()),
            }
        } else {
            Self {
                url: asset.browser_download_url.clone(),
                accept: None,
            }
        }
    }

    pub(crate) fn direct(url: String) -> Self {
        Self { url, accept: None }
    }
}

/// Pick the newest non-draft, non-prerelease release whose tag parses as a version, satisfying `filter`.
#[cfg(test)]
pub(crate) fn pick_latest(
    releases: &[GhRelease],
    filter: impl Fn(&GhRelease) -> bool,
) -> Option<&GhRelease> {
    releases
        .iter()
        .filter(|r| {
            !r.draft && !r.prerelease && parse_release_version(&r.tag_name).is_some() && filter(r)
        })
        .max_by(|a, b| compare_release_versions(&a.tag_name, &b.tag_name))
}

/// `GET {api}/repos/{repo}/releases?per_page=N`.
pub(crate) async fn list_releases(
    http: &Http,
    api_base: &str,
    repo: &str,
) -> Result<Vec<GhRelease>, UpdateError> {
    let url = format!(
        "{}/repos/{repo}/releases?per_page=100",
        api_base.trim_end_matches('/')
    );
    http.get_json(&url, MAX_RELEASES_JSON).await
}

/// `GET <releases api url>` where the caller gives the full URL (`updates.app_releases_api`).
pub(crate) async fn list_releases_at(
    http: &Http,
    url: &str,
) -> Result<Vec<GhRelease>, UpdateError> {
    let sep = if url.contains('?') { '&' } else { '?' };
    http.get_json(&format!("{url}{sep}per_page=100"), MAX_RELEASES_JSON)
        .await
}

/// `GET {api}/repos/{owner}/{repo}/releases/tags/{tag}`.
pub(crate) async fn release_by_tag(
    http: &Http,
    api_base: &str,
    owner: &str,
    repo: &str,
    tag: &str,
) -> Result<GhRelease, UpdateError> {
    let url = format!(
        "{}/repos/{owner}/{repo}/releases/tags/{tag}",
        api_base.trim_end_matches('/')
    );
    http.get_json(&url, MAX_RELEASES_JSON).await
}

/// Parse `https://github.com/<owner>/<repo>/releases/download/<tag>` → `(owner, repo, tag)`.
pub(crate) fn parse_release_download_base(base: &str) -> Option<(String, String, String)> {
    let rest = base
        .trim_end_matches('/')
        .strip_prefix("https://github.com/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [owner, repo, "releases", "download", tag]
            if [owner, repo, tag].iter().all(|s| valid_segment(s)) =>
        {
            Some((owner.to_string(), repo.to_string(), tag.to_string()))
        }
        _ => None,
    }
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/clamav_releases.json");

    #[test]
    fn parses_fixture_and_picks_newest_with_asset() {
        let rels: Vec<GhRelease> = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(rels.len(), 4);
        // 1.6.0-rc is a prerelease, 1.4.7 (LTS) was published after 1.5.4 but is older.
        let latest = pick_latest(&rels, |r| {
            let v = crate::version::normalize_release_version(&r.tag_name).unwrap_or_default();
            r.asset(&format!("clamav-{v}.macos.universal.pkg"))
                .is_some()
        })
        .unwrap();
        assert_eq!(latest.tag_name, "clamav-1.5.4");
        let a = latest.asset("clamav-1.5.4.macos.universal.pkg").unwrap();
        assert_eq!(AssetSource::for_asset(a, false).url, a.browser_download_url);
        let api = AssetSource::for_asset(a, true);
        assert_eq!(api.url, a.url);
        assert_eq!(api.accept.as_deref(), Some(OCTET_STREAM));
    }

    #[test]
    fn parses_download_base() {
        assert_eq!(
            parse_release_download_base(
                "https://github.com/WLDEUS/Parabellum/releases/download/db-latest/"
            ),
            Some(("WLDEUS".into(), "Parabellum".into(), "db-latest".into()))
        );
        assert_eq!(parse_release_download_base("https://example.com/db"), None);
        assert_eq!(
            parse_release_download_base("https://github.com/a/b/releases/download/../x"),
            None
        );
    }
}
