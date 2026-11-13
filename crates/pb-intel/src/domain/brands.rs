//! Brand list (typosquat / combosquat / homoglyph features), IDNA punycode decoding and confusable
//! skeletons.

use std::collections::HashSet;

/// The brand list compiled into the binary (`pipeline/data/brands.txt`). The bundle ships the exact list
/// the model was trained with (`ml/domain_brands.txt`), which takes precedence.
pub const BUILTIN_BRANDS: &str = include_str!("../../../../pipeline/data/brands.txt");

/// Max brands accepted from a file.
const MAX_BRANDS: usize = 5_000;

/// One brand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brand {
    pub token: String,
    /// Exact-label matching only (short / generic words).
    pub exact_only: bool,
    pub official: Vec<String>,
}

/// Parsed brand list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Brands {
    pub brands: Vec<Brand>,
    official: HashSet<String>,
}

fn valid_token(t: &str) -> bool {
    (2..=40).contains(&t.len())
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

impl Brands {
    /// Parses the `brands.txt` syntax (see the file header). Invalid lines are skipped.
    pub fn parse(text: &str) -> Self {
        let mut brands = Vec::new();
        let mut official = HashSet::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(tok) = parts.next() else { continue };
            let (token, exact_only) = match tok.strip_suffix('=') {
                Some(t) => (t, true),
                None => (tok, false),
            };
            let token = token.to_ascii_lowercase();
            if !valid_token(&token) {
                continue;
            }
            let doms: Vec<String> = parts
                .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
                .filter(|d| d.contains('.') && d.len() <= 253)
                .collect();
            official.extend(doms.iter().cloned());
            brands.push(Brand {
                token,
                exact_only,
                official: doms,
            });
            if brands.len() >= MAX_BRANDS {
                break;
            }
        }
        Self { brands, official }
    }

    /// The compiled-in list.
    pub fn builtin() -> Self {
        Self::parse(BUILTIN_BRANDS)
    }

    pub fn len(&self) -> usize {
        self.brands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.brands.is_empty()
    }

    /// `registrable` (or a parent of it) is an official domain of some brand.
    pub fn is_official(&self, registrable: &str, host: &str) -> bool {
        if self.official.contains(registrable) {
            return true;
        }
        // Official domains listed with more labels than the registrable part (e.g. `mabanque.bnpparibas`).
        let mut h = host;
        loop {
            if self.official.contains(h) {
                return true;
            }
            match h.find('.') {
                Some(i) => h = &h[i + 1..],
                None => return false,
            }
        }
    }
}

/// Brand evidence found in a host name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BrandMatch {
    /// A brand token equals or is contained in the second-level label (combosquatting) or equals it.
    pub in_sld: Option<String>,
    /// A brand token is a label (or label token) of the subdomain part.
    pub in_sub: Option<String>,
    /// Smallest edit distance (1..=2) between a label token and a brand token, with that brand.
    pub typo: Option<(u32, String)>,
    /// The confusable skeleton of a label equals a brand token while the raw label does not.
    pub homoglyph: Option<String>,
}

/// Splits a label into word tokens on `-` and `_`.
fn tokens(label: &str) -> impl Iterator<Item = &str> {
    label.split(['-', '_']).filter(|t| !t.is_empty())
}

/// Optimal-string-alignment (restricted Damerau-Levenshtein) distance, early exit above `max`.
pub fn osa_distance(a: &[u8], b: &[u8], max: u32) -> u32 {
    let (n, m) = (a.len(), b.len());
    if n.abs_diff(m) as u32 > max {
        return max + 1;
    }
    if n > 64 || m > 64 {
        return max + 1;
    }
    let w = m + 1;
    let mut d = vec![0u32; (n + 1) * w];
    for i in 0..=n {
        d[i * w] = i as u32;
    }
    for (j, cell) in d.iter_mut().enumerate().take(m + 1) {
        *cell = j as u32;
    }
    for i in 1..=n {
        let mut row_min = u32::MAX;
        for j in 1..=m {
            let cost = u32::from(a[i - 1] != b[j - 1]);
            let mut v = (d[(i - 1) * w + j] + 1)
                .min(d[i * w + j - 1] + 1)
                .min(d[(i - 1) * w + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[(i - 2) * w + j - 2] + 1);
            }
            d[i * w + j] = v;
            row_min = row_min.min(v);
        }
        if row_min > max {
            return max + 1;
        }
    }
    d[n * w + m]
}

/// Max edit distance considered a typo for a brand token of this length (0 = none).
fn typo_budget(len: usize) -> u32 {
    match len {
        0..=4 => 0,
        5..=7 => 1,
        _ => 2,
    }
}

/// Unicode confusables folded to ASCII (Cyrillic / Greek / Latin look-alikes used in IDN homograph
/// attacks) plus the classic ASCII swaps (`0`→`o`, `1`→`l`, `rn`→`m`, `vv`→`w`).
pub fn skeleton(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        let m = match c {
            'а' | 'ɑ' | 'α' | 'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' | 'ạ' | 'ą' => 'a',
            'Ь' | 'ь' | 'ƅ' => 'b',
            'с' | 'ϲ' | 'ç' | 'ć' | 'č' => 'c',
            'ԁ' | 'ɗ' | 'đ' => 'd',
            'е' | 'ё' | 'ε' | 'è' | 'é' | 'ê' | 'ë' | 'ė' | 'ę' | 'ẹ' => 'e',
            'ɡ' | 'ġ' | 'ğ' => 'g',
            'һ' | 'ḥ' => 'h',
            'і' | 'ı' | 'ɩ' | 'ι' | 'ì' | 'í' | 'î' | 'ï' | 'ị' | 'ӏ' | '1' => {
                if c == 'ӏ' || c == '1' {
                    'l'
                } else {
                    'i'
                }
            }
            'ј' | 'ʝ' => 'j',
            'κ' | 'к' => 'k',
            'ⅼ' | 'ł' | 'ḷ' => 'l',
            'ո' | 'ñ' | 'ń' | 'η' => 'n',
            'о' | 'ο' | 'σ' | 'ò' | 'ó' | 'ô' | 'ö' | 'õ' | 'ø' | 'ọ' | '0' => 'o',
            'р' | 'ρ' => 'p',
            'ԛ' => 'q',
            'г' => 'r',
            'ѕ' | 'ś' | 'š' | 'ş' | '5' => 's',
            'т' | 'τ' => 't',
            'υ' | 'ս' | 'ù' | 'ú' | 'û' | 'ü' | 'ụ' => 'u',
            'ν' | 'ѵ' => 'v',
            'ԝ' | 'ẃ' | 'ω' => 'w',
            'х' | 'χ' => 'x',
            'у' | 'ү' | 'ý' | 'ÿ' => 'y',
            'ż' | 'ź' | 'ž' => 'z',
            c => c,
        };
        out.push(m);
    }
    out.replace("rn", "m").replace("vv", "w")
}

/// RFC 3492 punycode decoding of one `xn--` label body (without the prefix). `None` if invalid.
pub fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    if input.len() > 63 || !input.is_ascii() {
        return None;
    }
    let (basic, rest) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    let mut out: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let digits: Vec<u8> = rest.bytes().collect();
    let mut pos = 0usize;
    fn adapt(mut delta: u32, num: u32, first: bool) -> u32 {
        delta = if first { delta / DAMP } else { delta / 2 };
        delta += delta / num;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + SKEW)
    }
    while pos < digits.len() {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let c = *digits.get(pos)?;
            pos += 1;
            let digit = match c {
                b'a'..=b'z' => u32::from(c - b'a'),
                b'A'..=b'Z' => u32::from(c - b'A'),
                b'0'..=b'9' => u32::from(c - b'0') + 26,
                _ => return None,
            };
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let len = out.len() as u32 + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        n = n.checked_add(i / len)?;
        i %= len;
        out.insert(i as usize, char::from_u32(n)?);
        i += 1;
        if out.len() > 63 {
            return None;
        }
    }
    Some(out.into_iter().collect())
}

/// Decodes `xn--` labels (others unchanged).
pub fn decode_label(label: &str) -> String {
    match label.strip_prefix("xn--") {
        Some(body) => punycode_decode(body).unwrap_or_else(|| label.to_string()),
        None => label.to_string(),
    }
}

impl Brands {
    /// Brand evidence for `host` split into `sld` / `sub`. Official domains of a brand never match it.
    pub fn analyze(&self, host: &str, registrable: &str, sld: &str, sub: &str) -> BrandMatch {
        let mut m = BrandMatch::default();
        if self.is_official(registrable, host) || sld.is_empty() {
            return m;
        }
        let sld_dec = decode_label(sld);
        let sld_flat: String = sld_dec.chars().filter(|c| *c != '-' && *c != '_').collect();
        let sub_labels: Vec<String> = if sub.is_empty() {
            vec![]
        } else {
            sub.split('.').map(decode_label).collect()
        };
        let sld_skel = skeleton(&sld_flat);
        for b in &self.brands {
            let t = b.token.as_str();
            // Combosquatting / exact label in the SLD.
            if m.in_sld.is_none() {
                let hit = if b.exact_only {
                    sld_flat == t || tokens(&sld_dec).any(|x| x == t)
                } else {
                    sld_flat.contains(t)
                };
                if hit {
                    m.in_sld = Some(b.token.clone());
                }
            }
            // Brand inside the subdomain (`paypal.com.secure-login.xyz`).
            if m.in_sub.is_none() {
                let hit = sub_labels.iter().any(|l| {
                    let flat: String = l.chars().filter(|c| *c != '-' && *c != '_').collect();
                    flat == t || tokens(l).any(|x| x == t) || (!b.exact_only && flat.contains(t))
                });
                if hit {
                    m.in_sub = Some(b.token.clone());
                }
            }
            // IDN / ASCII homoglyphs.
            if m.homoglyph.is_none() && !b.exact_only && sld_skel == t && sld_flat != t {
                m.homoglyph = Some(b.token.clone());
            }
            // Typosquatting on the SLD (whole label and word tokens).
            let budget = if b.exact_only {
                0
            } else {
                typo_budget(t.len())
            };
            if budget > 0 {
                let cands = std::iter::once(sld_flat.as_str())
                    .chain(tokens(&sld_dec).filter(|x| x.len() >= 4));
                for c in cands {
                    if c == t || !c.is_ascii() {
                        continue;
                    }
                    let d = osa_distance(c.as_bytes(), t.as_bytes(), budget);
                    if d >= 1 && d <= budget && m.typo.as_ref().is_none_or(|(bd, _)| d < *bd) {
                        m.typo = Some((d, b.token.clone()));
                    }
                }
            }
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_builtin_list() {
        let b = Brands::builtin();
        assert!(b.len() >= 150, "{} brands", b.len());
        assert!(b.brands.iter().any(|x| x.token == "impots" && x.exact_only));
        assert!(b.is_official("paypal.com", "www.paypal.com"));
        assert!(b.is_official("bnpparibas", "mabanque.bnpparibas"));
        assert!(!b.is_official("paypa1.com", "paypa1.com"));
        let p = Brands::parse("# c\nfoo= foo.com\nBad!token x.com\nbar bar.fr bar.com\n");
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn edit_distance() {
        assert_eq!(osa_distance(b"paypal", b"paypal", 2), 0);
        assert_eq!(osa_distance(b"paypa1", b"paypal", 2), 1);
        assert_eq!(osa_distance(b"pyapal", b"paypal", 2), 1); // transposition
        assert_eq!(osa_distance(b"paypall", b"paypal", 2), 1);
        assert_eq!(osa_distance(b"amazon", b"netflix", 2), 3);
    }

    #[test]
    fn punycode_and_skeleton() {
        // "аpple" with a Cyrillic а (U+0430)
        assert_eq!(punycode_decode("pple-43d").as_deref(), Some("аpple"));
        assert_eq!(decode_label("xn--pple-43d"), "аpple");
        assert_eq!(skeleton("аpple"), "apple");
        assert_eq!(punycode_decode("mnchen-3ya").as_deref(), Some("münchen"));
        assert_eq!(skeleton("rnicrosoft"), "microsoft");
        assert_eq!(skeleton("g00gle"), "google");
        assert!(punycode_decode("!!").is_none());
    }

    #[test]
    fn brand_evidence() {
        let b = Brands::builtin();
        let m = b.analyze(
            "paypal.com.secure-login.xyz",
            "secure-login.xyz",
            "secure-login",
            "paypal.com",
        );
        assert_eq!(m.in_sub.as_deref(), Some("paypal"));
        assert!(m.in_sld.is_none());
        let m = b.analyze(
            "paypa1-support.com",
            "paypa1-support.com",
            "paypa1-support",
            "",
        );
        assert_eq!(m.typo.as_ref().map(|t| t.1.as_str()), Some("paypal"));
        let m = b.analyze(
            "ameli-remboursement.info",
            "ameli-remboursement.info",
            "ameli-remboursement",
            "",
        );
        assert_eq!(m.in_sld.as_deref(), Some("ameli"));
        let m = b.analyze("xn--pple-43d.com", "xn--pple-43d.com", "xn--pple-43d", "");
        assert_eq!(m.homoglyph.as_deref(), Some("apple"));
        // Official domains and unrelated names are clean.
        assert_eq!(
            b.analyze("www.paypal.com", "paypal.com", "paypal", "www"),
            BrandMatch::default()
        );
        let m = b.analyze("weather.com", "weather.com", "weather", "");
        assert!(m.in_sld.is_none() && m.typo.is_none() && m.homoglyph.is_none());
        // Exact-only tokens do not match as substrings.
        let m = b.analyze("freebies.net", "freebies.net", "freebies", "");
        assert!(m.in_sld.is_none());
        let m = b.analyze(
            "free-mobile-facture.com",
            "free-mobile-facture.com",
            "free-mobile-facture",
            "",
        );
        assert_eq!(m.in_sld.as_deref(), Some("free"));
    }
}
