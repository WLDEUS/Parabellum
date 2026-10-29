//! The signed broker list (`privacy/brokers.json` in the threat DB): loading, validation, region filter.

use pb_core::config::is_email;
use pb_core::db::{BrokersFile, PRIVACY_BROKERS};
use pb_core::model::BrokerInfo;
use std::path::Path;

/// Known regions (see `DataRemovalConfig::regions`).
pub const REGIONS: [&str; 3] = ["eu", "global", "us"];
/// Max size of `privacy/brokers.json`.
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// Load `<db_dir>/privacy/brokers.json`, keeping only valid entries (see [`sanitize`]).
pub fn load(db_dir: &Path) -> Result<Vec<BrokerInfo>, String> {
    let path = db_dir.join(PRIVACY_BROKERS);
    let md = std::fs::metadata(&path)
        .map_err(|_| "liste des courtiers absente de la base de menaces".to_string())?;
    if md.len() > MAX_FILE {
        return Err("liste des courtiers trop volumineuse".into());
    }
    let data = std::fs::read(&path).map_err(|e| format!("lecture de {PRIVACY_BROKERS} : {e}"))?;
    let file: BrokersFile =
        serde_json::from_slice(&data).map_err(|e| format!("{PRIVACY_BROKERS} illisible : {e}"))?;
    if file.format > 1 {
        return Err(format!(
            "{PRIVACY_BROKERS} : format {} non pris en charge",
            file.format
        ));
    }
    Ok(file.brokers.into_iter().filter_map(sanitize).collect())
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn https_url(u: Option<String>) -> Option<String> {
    u.map(|s| s.trim().to_string()).filter(|s| {
        s.starts_with("https://")
            && s.len() <= 2048
            && !s.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

/// Normalise one entry: invalid email / non-HTTPS URLs dropped; entries without a usable contact (email or
/// opt-out form), with a bad id or an unknown region are rejected.
pub fn sanitize(mut b: BrokerInfo) -> Option<BrokerInfo> {
    b.id = b.id.trim().to_string();
    b.name = b.name.trim().chars().filter(|c| !c.is_control()).collect();
    b.region = b.region.trim().to_ascii_lowercase();
    b.category = b.category.trim().to_ascii_lowercase();
    if !is_slug(&b.id) || b.name.is_empty() || b.name.len() > 256 {
        return None;
    }
    if !REGIONS.contains(&b.region.as_str()) {
        return None;
    }
    b.email = b
        .email
        .map(|e| e.trim().to_string())
        .filter(|e| is_email(e));
    b.website = https_url(b.website);
    b.opt_out_url = https_url(b.opt_out_url);
    if b.email.is_none() && b.opt_out_url.is_none() {
        return None;
    }
    Some(b)
}

/// Brokers of the given regions, sorted by name (case-insensitive), then id.
pub fn filter(brokers: Vec<BrokerInfo>, regions: &[String]) -> Vec<BrokerInfo> {
    let mut out: Vec<BrokerInfo> = brokers
        .into_iter()
        .filter(|b| regions.iter().any(|r| r.eq_ignore_ascii_case(&b.region)))
        .collect();
    out.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.id.cmp(&b.id))
    });
    out
}

#[cfg(test)]
pub(crate) fn sample(id: &str, region: &str, email: Option<&str>) -> BrokerInfo {
    BrokerInfo {
        id: id.into(),
        name: format!("Broker {id}"),
        email: email.map(str::to_string),
        website: Some(format!("https://{id}.example.com")),
        opt_out_url: None,
        region: region.into(),
        category: "ads".into(),
        source: "datenanfragen".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn load_filters_and_sorts() {
        let d = tempfile::tempdir().unwrap();
        let mut b2 = sample("zeta", "eu", Some("dpo@zeta.fr"));
        b2.name = "alpha corp".into();
        let mut bad_url = sample("acme", "us", Some("privacy@acme.com"));
        bad_url.website = Some("http://acme.com".into());
        let mut form_only = sample("form", "global", None);
        form_only.opt_out_url = Some("https://form.example.com/optout".into());
        let file = BrokersFile {
            format: 1,
            sources: BTreeMap::new(),
            brokers: vec![
                sample("crit", "eu", Some("dpo@criteo.com")),
                b2,
                bad_url,
                form_only,
                sample("nocontact", "us", None),
                sample("bad email", "eu", Some("x@y.z")),
                sample("mars", "mars", Some("a@b.com")),
                sample("broken", "eu", Some("not-an-email")),
            ],
        };
        std::fs::create_dir_all(d.path().join("privacy")).unwrap();
        std::fs::write(
            d.path().join(PRIVACY_BROKERS),
            serde_json::to_vec(&file).unwrap(),
        )
        .unwrap();
        let all = load(d.path()).unwrap();
        let ids: Vec<&str> = all.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(ids, vec!["crit", "zeta", "acme", "form"]);
        assert_eq!(all[2].website, None);
        let eu = filter(all.clone(), &["eu".to_string()]);
        assert_eq!(
            eu.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
            vec!["alpha corp", "Broker crit"]
        );
        assert_eq!(filter(all, &["global".into(), "us".into()]).len(), 2);
        assert!(load(&d.path().join("nope")).is_err());
    }
}
