//! Lexical features of a DNS name for the phishing / malicious-domain model.
//!
//! [`DomainFeatures::extract`] turns a host name into a fixed-length `f32` vector whose layout is
//! [`feature_names`] and versioned by [`FEATURES_VERSION`]; the trainer (`ml/domains/`) gets exactly the
//! same vectors from the `pb-domain-features` binary. Nothing here touches the network: "new-looking"
//! names are captured by lexical proxies only (randomness, digits, abused TLDs), never by WHOIS / RDAP.

pub mod brands;
pub mod model;
pub mod suffix;

pub use brands::{BrandMatch, Brands};

/// Bumped whenever the vector layout or a feature's definition changes (models embed it).
pub const FEATURES_VERSION: u32 = 1;

const NAMES: &[&str] = &[
    "host_len",
    "num_labels",
    "sub_depth",
    "sub_len",
    "sld_len",
    "max_label_len",
    "sld_digits",
    "sld_digit_ratio",
    "sld_hyphens",
    "host_hyphens",
    "host_digit_ratio",
    "sld_entropy",
    "sub_entropy",
    "sld_vowel_ratio",
    "sld_max_consonant_run",
    "sld_max_repeat",
    "sld_tokens",
    "sld_hex_like",
    "tld_len",
    "tld_abused",
    "tld_common",
    "tld_country",
    "multi_label_suffix",
    "shared_platform",
    "punycode",
    "non_ascii",
    "ip_like",
    "www_prefix",
    "keyword_hits",
    "keyword_in_sld",
    "brand_in_sld",
    "brand_in_sub",
    "brand_typo_dist",
    "brand_homoglyph",
    "official_brand",
    "sub_digit_ratio",
];

const DESCRIPTIONS: &[&str] = &[
    "length of the full host name",
    "number of labels",
    "labels left of the registrable domain",
    "length of the subdomain part",
    "length of the second-level label",
    "longest label",
    "digits in the second-level label",
    "digit ratio of the second-level label",
    "hyphens in the second-level label",
    "hyphens in the host",
    "digit ratio of the host",
    "Shannon entropy (bits/char) of the second-level label",
    "Shannon entropy of the subdomain part",
    "vowel ratio of the second-level label (letters only)",
    "longest run of consonants in the second-level label",
    "longest run of one repeated character",
    "word tokens of the second-level label (split on -, _ and digit/letter changes)",
    "second-level label looks like hex (>= 8 chars, hex digits only, with a digit)",
    "length of the public suffix",
    "TLD frequently abused by phishing / malware (cheap, free or bulk)",
    "common generic TLD (com, net, org, fr, de, …)",
    "two-letter country-code TLD",
    "multi-label public suffix (co.uk, gouv.fr…)",
    "free hosting / dynamic DNS platform suffix",
    "a label is punycode (xn--)",
    "non-ASCII characters after IDN decoding",
    "contains an IP address written in labels (1-2-3-4, 1.2.3.4.nip.io…)",
    "starts with www",
    "phishing keywords in the host (login, verify, colis, remboursement…)",
    "phishing keywords in the second-level label",
    "a brand token is in the second-level label (combosquatting) and the domain is not official",
    "a brand token is in the subdomain part and the domain is not official",
    "edit distance (1-2) to the closest brand token, 0 = none",
    "the confusable skeleton equals a brand token (IDN / ASCII homoglyph)",
    "official domain of a listed brand",
    "digit ratio of the subdomain part",
];

/// Feature names in vector order (the model's `feature_names` must equal this).
pub fn feature_names() -> &'static [&'static str] {
    NAMES
}

/// Human-readable descriptions (same order).
pub fn feature_descriptions() -> &'static [&'static str] {
    DESCRIPTIONS
}

/// TLDs over-represented in phishing / malware feeds (Spamhaus / Interisle "most abused" style lists).
const ABUSED_TLDS: &[&str] = &[
    "xyz",
    "top",
    "club",
    "online",
    "site",
    "icu",
    "buzz",
    "cfd",
    "sbs",
    "monster",
    "rest",
    "bond",
    "click",
    "link",
    "live",
    "shop",
    "support",
    "help",
    "work",
    "info",
    "biz",
    "cyou",
    "quest",
    "fun",
    "space",
    "website",
    "store",
    "tech",
    "pw",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "zip",
    "mov",
    "country",
    "stream",
    "download",
    "racing",
    "win",
    "bid",
    "loan",
    "date",
    "men",
    "review",
    "trade",
    "party",
    "science",
    "cam",
    "lol",
    "beauty",
    "hair",
    "skin",
    "makeup",
    "autos",
    "boats",
    "yachts",
    "homes",
    "motorcycles",
    "mom",
    "ink",
    "kim",
    "uno",
    "vip",
    "today",
    "email",
    "life",
    "world",
    "pro",
    "best",
    "ltd",
    "digital",
    "network",
    "center",
    "services",
    "pics",
    "my",
    "su",
    "ru",
    "cn",
    "ws",
    "cc",
    "ac",
    "rs",
    "co",
    "me",
    "io",
    "app",
    "dev",
    "page",
    "one",
];

const COMMON_TLDS: &[&str] = &[
    "com", "net", "org", "fr", "de", "uk", "edu", "gov", "eu", "it", "es", "nl", "be", "ch", "ca",
    "us", "jp", "au", "se", "no", "dk", "fi", "at", "pl", "pt", "ie", "int", "mil",
];

/// Phishing vocabulary (EN + FR lures: parcels, refunds, fines, tax, health insurance…).
const KEYWORDS: &[&str] = &[
    "login",
    "logon",
    "signin",
    "sign-in",
    "secure",
    "security",
    "account",
    "verify",
    "verification",
    "update",
    "confirm",
    "billing",
    "invoice",
    "wallet",
    "auth",
    "webscr",
    "banking",
    "password",
    "recover",
    "unlock",
    "suspend",
    "support",
    "service",
    "customer",
    "client",
    "espace",
    "connexion",
    "compte",
    "securite",
    "authentification",
    "remboursement",
    "colis",
    "livraison",
    "suivi",
    "amende",
    "facture",
    "paiement",
    "payment",
    "refund",
    "tracking",
    "parcel",
    "delivery",
    "claim",
    "reward",
    "bonus",
    "gift",
    "free",
    "promo",
    "airdrop",
    "validate",
    "validation",
    "activation",
    "renew",
    "expire",
    "alert",
    "notice",
    "official",
    "helpdesk",
    "carte",
    "vitale",
    "dossier",
    "impayé",
    "impaye",
    "regularisation",
    "sinistre",
    "mise-a-jour",
    "miseajour",
    "identifiant",
    "portail",
    "assistance",
    "mfa",
    "2fa",
    "otp",
    "seed",
    "metamask",
];

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    let n = n as f32;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

fn is_vowel(c: char) -> bool {
    matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y')
}

fn max_consonant_run(s: &str) -> u32 {
    let (mut best, mut cur) = (0u32, 0u32);
    for c in s.chars() {
        if c.is_ascii_alphabetic() && !is_vowel(c) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn max_repeat(s: &str) -> u32 {
    let (mut best, mut cur, mut prev) = (0u32, 0u32, None);
    for c in s.chars() {
        if Some(c) == prev {
            cur += 1;
        } else {
            cur = 1;
            prev = Some(c);
        }
        best = best.max(cur);
    }
    best
}

/// Tokens split on `-`, `_` and letter/digit changes.
fn word_tokens(s: &str) -> u32 {
    let mut n = 0u32;
    let mut prev: Option<bool> = None; // Some(true) = digit
    for c in s.chars() {
        if c == '-' || c == '_' {
            prev = None;
            continue;
        }
        let d = c.is_ascii_digit();
        if prev != Some(d) {
            n += 1;
        }
        prev = Some(d);
    }
    n
}

fn digit_ratio(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    s.bytes().filter(u8::is_ascii_digit).count() as f32 / s.len() as f32
}

fn ip_like(host: &str) -> bool {
    // dotted (1.2.3.4.nip.io) or dashed (1-2-3-4.sslip.io / ec2-1-2-3-4) IPv4 inside the name
    let octet = |t: &str| {
        !t.is_empty()
            && t.len() <= 3
            && t.bytes().all(|b| b.is_ascii_digit())
            && t.parse::<u16>().is_ok_and(|v| v <= 255)
    };
    let labels: Vec<&str> = host.split('.').collect();
    if labels.windows(4).any(|w| w.iter().all(|t| octet(t))) {
        return true;
    }
    labels.iter().any(|l| {
        let parts: Vec<&str> = l.split('-').collect();
        parts.windows(4).any(|w| w.iter().all(|t| octet(t)))
    })
}

/// Normalizes a query name: trims, strips the trailing dot and surrounding quotes, lowercases.
/// `None` for names that are not plausible DNS host names.
pub fn normalize(name: &str) -> Option<String> {
    let n = name.trim().trim_matches('"').trim_end_matches('.');
    if n.is_empty() || n.len() > 253 {
        return None;
    }
    let n = n.to_ascii_lowercase();
    let ok = n.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(n)
}

/// Names never scored: single labels, local / reverse / special-use zones.
pub fn is_local_or_special(host: &str) -> bool {
    !host.contains('.')
        || [
            ".local",
            ".lan",
            ".home",
            ".internal",
            ".localhost",
            ".localdomain",
            ".home.arpa",
            ".in-addr.arpa",
            ".ip6.arpa",
            ".test",
            ".invalid",
            ".example",
            ".onion",
            ".corp",
            ".intranet",
            ".private",
        ]
        .iter()
        .any(|s| host.ends_with(s) || host == &s[1..])
        || host.starts_with("_")
        || host.contains("._tcp.")
        || host.contains("._udp.")
}

/// Extracted features plus the evidence used to explain a verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainFeatures {
    pub host: String,
    pub registrable: String,
    pub values: Vec<f32>,
    pub brand: BrandMatch,
    pub shared_platform: bool,
    pub official: bool,
}

impl DomainFeatures {
    /// Features of `host` (already [`normalize`]d).
    pub fn extract(host: &str, brands: &Brands) -> Self {
        let sp = suffix::split(host);
        let sld = sp.sld;
        let sub = sp.sub;
        let tld = host.rsplit('.').next().unwrap_or("");
        let labels: Vec<&str> = host.split('.').collect();
        let decoded: String = labels
            .iter()
            .map(|l| brands::decode_label(l))
            .collect::<Vec<_>>()
            .join(".");
        let letters: Vec<char> = sld.chars().filter(|c| c.is_ascii_alphabetic()).collect();
        let vowels = letters.iter().filter(|c| is_vowel(**c)).count();
        let official = brands.is_official(sp.registrable, host);
        let bm = brands.analyze(host, sp.registrable, sld, sub);
        let kw_hits = KEYWORDS.iter().filter(|k| host.contains(*k)).count();
        let kw_sld = KEYWORDS.iter().filter(|k| sld.contains(*k)).count();
        let hex_like = sld.len() >= 8
            && sld.bytes().all(|b| b.is_ascii_hexdigit())
            && sld.bytes().any(|b| b.is_ascii_digit());
        let b = |x: bool| if x { 1.0 } else { 0.0 };
        let values = vec![
            host.len() as f32,
            labels.len() as f32,
            if sub.is_empty() {
                0.0
            } else {
                sub.split('.').count() as f32
            },
            sub.len() as f32,
            sld.len() as f32,
            labels.iter().map(|l| l.len()).max().unwrap_or(0) as f32,
            sld.bytes().filter(u8::is_ascii_digit).count() as f32,
            digit_ratio(sld),
            sld.bytes().filter(|c| *c == b'-').count() as f32,
            host.bytes().filter(|c| *c == b'-').count() as f32,
            digit_ratio(host),
            shannon_entropy(sld),
            shannon_entropy(sub),
            if letters.is_empty() {
                0.0
            } else {
                vowels as f32 / letters.len() as f32
            },
            max_consonant_run(sld) as f32,
            max_repeat(sld) as f32,
            word_tokens(sld) as f32,
            b(hex_like),
            sp.suffix.len() as f32,
            b(ABUSED_TLDS.contains(&tld)),
            b(COMMON_TLDS.contains(&tld)),
            b(tld.len() == 2),
            b(sp.suffix.contains('.') && !sp.shared_platform),
            b(sp.shared_platform),
            b(labels.iter().any(|l| l.starts_with("xn--"))),
            b(!decoded.is_ascii()),
            b(ip_like(host)),
            b(host.starts_with("www.")),
            kw_hits as f32,
            kw_sld as f32,
            b(bm.in_sld.is_some()),
            b(bm.in_sub.is_some()),
            bm.typo.as_ref().map_or(0.0, |t| t.0 as f32),
            b(bm.homoglyph.is_some()),
            b(official),
            digit_ratio(sub),
        ];
        debug_assert_eq!(values.len(), NAMES.len());
        Self {
            host: host.to_string(),
            registrable: sp.registrable.to_string(),
            values,
            brand: bm,
            shared_platform: sp.shared_platform,
            official,
        }
    }

    fn value(&self, name: &str) -> f32 {
        NAMES
            .iter()
            .position(|n| *n == name)
            .and_then(|i| self.values.get(i).copied())
            .unwrap_or(0.0)
    }

    /// French explanations of the risk factors present (independent of the model's score).
    pub fn reasons(&self) -> Vec<String> {
        let mut r = Vec::new();
        if let Some(b) = &self.brand.homoglyph {
            r.push(format!(
                "Caractères trompeurs imitant « {b} » (homoglyphes)"
            ));
        }
        if let Some((d, b)) = &self.brand.typo {
            r.push(format!("Ressemble à « {b} » ({d} faute(s) de frappe)"));
        }
        if let Some(b) = &self.brand.in_sub {
            r.push(format!("La marque « {b} » apparaît dans un sous-domaine"));
        }
        if let Some(b) = &self.brand.in_sld {
            r.push(format!(
                "Contient la marque « {b} » sans être un domaine officiel"
            ));
        }
        if self.value("keyword_hits") >= 1.0 {
            r.push("Mots typiques d'hameçonnage (connexion, vérification, colis…)".into());
        }
        if self.value("sld_entropy") >= 3.6 && self.value("sld_len") >= 10.0
            || self.value("sld_hex_like") > 0.0
        {
            r.push("Nom d'apparence aléatoire (généré automatiquement)".into());
        }
        if self.value("tld_abused") > 0.0 {
            let tld = self.host.rsplit('.').next().unwrap_or("");
            r.push(format!(
                "Extension .{tld} souvent utilisée par des sites malveillants"
            ));
        }
        if self.value("host_hyphens") >= 3.0 || self.value("sld_digits") >= 4.0 {
            r.push("Nombreux tirets ou chiffres".into());
        }
        if self.value("sub_depth") >= 4.0 {
            r.push("Sous-domaines anormalement nombreux".into());
        }
        if self.shared_platform {
            r.push("Hébergé sur une plateforme gratuite ou un DNS dynamique".into());
        }
        if self.value("punycode") > 0.0 && self.brand.homoglyph.is_none() {
            r.push("Nom internationalisé (punycode)".into());
        }
        if self.value("ip_like") > 0.0 {
            r.push("Adresse IP déguisée en nom de domaine".into());
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_consistent() {
        assert_eq!(NAMES.len(), DESCRIPTIONS.len());
        let b = Brands::builtin();
        let f = DomainFeatures::extract("www.example.com", &b);
        assert_eq!(f.values.len(), feature_names().len());
        let mut sorted = NAMES.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), NAMES.len(), "duplicate feature name");
    }

    #[test]
    fn normalization_and_special_names() {
        assert_eq!(
            normalize(" WWW.Example.COM. ").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(normalize("\"a.b\"").as_deref(), Some("a.b"));
        assert!(normalize("bad name.com").is_none());
        assert!(normalize("a..b").is_none());
        assert!(normalize("").is_none());
        assert!(is_local_or_special("macbook.local"));
        assert!(is_local_or_special("1.0.168.192.in-addr.arpa"));
        assert!(is_local_or_special("router"));
        assert!(is_local_or_special("_dns.resolver.arpa") || is_local_or_special("_dns.x.com"));
        assert!(!is_local_or_special("example.com"));
    }

    #[test]
    fn phishing_shapes_light_up() {
        let b = Brands::builtin();
        let f = DomainFeatures::extract("paypal.com.secure-login-verify.xyz", &b);
        assert_eq!(f.value("brand_in_sub"), 1.0);
        assert_eq!(f.value("tld_abused"), 1.0);
        assert!(f.value("keyword_hits") >= 2.0);
        assert_eq!(f.registrable, "secure-login-verify.xyz");
        assert!(f.reasons().iter().any(|r| r.contains("paypal")));

        let f = DomainFeatures::extract("xn--80ak6aa92e.com", &b);
        assert_eq!(f.value("punycode"), 1.0);
        assert_eq!(f.value("non_ascii"), 1.0);
        assert_eq!(f.value("brand_homoglyph"), 1.0);

        let f = DomainFeatures::extract("qxzvbkwrtplmn7f3.top", &b);
        assert!(f.value("sld_entropy") > 3.5);
        assert!(f.value("sld_max_consonant_run") >= 6.0);
        assert!(f.reasons().iter().any(|r| r.contains("aléatoire")));

        let f = DomainFeatures::extract("ec2-54-12-3-4.compute-1.amazonaws.com", &b);
        assert_eq!(f.value("ip_like"), 1.0);

        let f = DomainFeatures::extract("www.impots.gouv.fr", &b);
        assert_eq!(f.value("official_brand"), 1.0);
        assert_eq!(f.value("multi_label_suffix"), 1.0);
        assert_eq!(f.value("brand_in_sld"), 0.0);
        assert!(f.reasons().is_empty());

        let f = DomainFeatures::extract("impots-gouv-remboursement.com", &b);
        assert_eq!(f.value("brand_in_sld"), 1.0);
        assert!(f.value("keyword_in_sld") >= 1.0);
    }

    #[test]
    fn helpers() {
        assert_eq!(word_tokens("abc-12de"), 3);
        assert_eq!(max_repeat("aaab"), 3);
        assert_eq!(max_consonant_run("strength"), 4);
        assert!((shannon_entropy("abab") - 1.0).abs() < 1e-6);
        assert!(ip_like("1.2.3.4.nip.io"));
        assert!(!ip_like("www.example.com"));
    }
}
