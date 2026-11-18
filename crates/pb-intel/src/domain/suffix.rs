//! Registrable-domain split (eTLD+1) without the full Public Suffix List.
//!
//! The client only needs a good approximation for lexical features: single-label TLDs, the common
//! multi-label country suffixes (`co.uk`, `gouv.fr`, `com.br`…) and the shared hosting / dynamic-DNS
//! platforms where anyone can get a subdomain (`github.io`, `web.app`, `duckdns.org`…), which are
//! treated as public suffixes (`evil.github.io` is the "registrable" part) and flagged as such.

/// Multi-label public suffixes (ICANN section of the PSL, most common ones).
const MULTI_LABEL: &[&str] = &[
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "net.uk",
    "nhs.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    "co.nz",
    "org.nz",
    "net.nz",
    "govt.nz",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "ne.kr",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "edu.br",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "com.tw",
    "org.tw",
    "com.hk",
    "org.hk",
    "com.sg",
    "edu.sg",
    "com.my",
    "co.in",
    "net.in",
    "org.in",
    "gov.in",
    "ac.in",
    "co.za",
    "org.za",
    "gov.za",
    "com.mx",
    "org.mx",
    "gob.mx",
    "com.ar",
    "gob.ar",
    "com.co",
    "com.tr",
    "gov.tr",
    "com.ua",
    "co.il",
    "org.il",
    "com.pl",
    "gouv.fr",
    "asso.fr",
    "nom.fr",
    "presse.fr",
    "tm.fr",
    "com.fr",
    "gouv.qc.ca",
    "qc.ca",
    "co.id",
    "or.id",
    "go.id",
    "com.ph",
    "com.vn",
    "com.pk",
    "com.eg",
    "com.sa",
    "com.ng",
    "co.ke",
    "com.pe",
    "com.ve",
    "com.ec",
    "co.th",
    "in.th",
    "ac.th",
    "go.th",
    "eu.org",
    "com.es",
    "org.es",
    "co.at",
    "or.at",
    "com.ru",
    "co.ma",
    "gov.ma",
    "com.tn",
    "com.dz",
    "co.ve",
    "com.uy",
    "com.bd",
    "com.np",
    "com.lk",
    "co.ug",
    "co.tz",
    "com.gh",
    "com.kw",
    "com.qa",
    "co.ae",
    "gov.ae",
    "com.cy",
    "com.mt",
    "com.gr",
    "com.pt",
    "co.no",
    "com.de",
    "com.be",
    "co.it",
    "com.ro",
    "in.ua",
    "com.kz",
    "net.ru",
    "org.ru",
    "spb.ru",
    "msk.ru",
];

/// Shared hosting / dynamic DNS / tunnel platforms: subdomains belong to arbitrary customers.
const SHARED_PLATFORMS: &[&str] = &[
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "web.app",
    "firebaseapp.com",
    "appspot.com",
    "blogspot.com",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "glitch.me",
    "repl.co",
    "replit.app",
    "replit.dev",
    "azurewebsites.net",
    "cloudfront.net",
    "s3.amazonaws.com",
    "r2.dev",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "duckdns.org",
    "no-ip.org",
    "no-ip.biz",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    "serveo.net",
    "trycloudflare.com",
    "weebly.com",
    "wixsite.com",
    "square.site",
    "webflow.io",
    "framer.app",
    "framer.website",
    "godaddysites.com",
    "myshopify.com",
    "carrd.co",
    "000webhostapp.com",
    "onrender.com",
    "fly.dev",
    "surge.sh",
    "translate.goog",
    "sharepoint.com",
    "notion.site",
    "jimdosite.com",
    "mystrikingly.com",
    "wordpress.com",
    "tumblr.com",
    "blogspot.fr",
    "firebasestorage.app",
    "ipfs.dweb.link",
    "dweb.link",
    "on.fleek.co",
    "fleek.co",
    "web.core.windows.net",
    "azureedge.net",
    "z13.web.core.windows.net",
    "bitbucket.io",
    "codeberg.page",
    "sites.google.com",
    "page.link",
    "linktr.ee",
    "glide.page",
    "softr.app",
    "typedream.app",
    "temp.domains",
    "dynv6.net",
    "freeddns.org",
    "mooo.com",
    "afraid.org",
    "loca.lt",
    "lhr.life",
    "pinggy.link",
    "serveousercontent.com",
    "workers.dev",
];

/// Result of [`split`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split<'a> {
    /// Public suffix (`com`, `co.uk`, `github.io`…).
    pub suffix: &'a str,
    /// Suffix + one label (`example.com`); the whole name when it is itself a suffix.
    pub registrable: &'a str,
    /// The label just left of the suffix (`example`), empty when the name is a bare suffix.
    pub sld: &'a str,
    /// Everything left of the registrable domain, without the trailing dot (may be empty).
    pub sub: &'a str,
    /// The suffix is a shared hosting / dynamic DNS platform.
    pub shared_platform: bool,
}

fn longest_suffix_in<'a>(name: &'a str, list: &[&str]) -> Option<&'a str> {
    // Try every dot boundary from the left: the first (longest) listed suffix wins.
    let mut start = 0usize;
    loop {
        let rest = &name[start..];
        if list.contains(&rest) {
            return Some(rest);
        }
        start += rest.find('.')? + 1;
    }
}

/// Splits a normalized (lowercase, no trailing dot) host name.
pub fn split(name: &str) -> Split<'_> {
    let (suffix, shared_platform) = if let Some(s) = longest_suffix_in(name, SHARED_PLATFORMS) {
        (s, true)
    } else if let Some(s) = longest_suffix_in(name, MULTI_LABEL) {
        (s, false)
    } else {
        (name.rsplit('.').next().unwrap_or(name), false)
    };
    if suffix.len() >= name.len() {
        return Split {
            suffix,
            registrable: name,
            sld: "",
            sub: "",
            shared_platform,
        };
    }
    // name = <head>.<suffix>
    let head = &name[..name.len() - suffix.len() - 1];
    let (sub, sld) = match head.rfind('.') {
        Some(i) => (&head[..i], &head[i + 1..]),
        None => ("", head),
    };
    let registrable = &name[name.len() - suffix.len() - 1 - sld.len()..];
    Split {
        suffix,
        registrable,
        sld,
        sub,
        shared_platform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_common_shapes() {
        let s = split("www.example.com");
        assert_eq!(
            (s.suffix, s.registrable, s.sld, s.sub),
            ("com", "example.com", "example", "www")
        );
        let s = split("impots.gouv.fr");
        assert_eq!(
            (s.suffix, s.registrable, s.sld),
            ("gouv.fr", "impots.gouv.fr", "impots")
        );
        let s = split("a.b.bbc.co.uk");
        assert_eq!((s.registrable, s.sub), ("bbc.co.uk", "a.b"));
        let s = split("paypal.com.secure-login.xyz");
        assert_eq!(
            (s.registrable, s.sld, s.sub),
            ("secure-login.xyz", "secure-login", "paypal.com")
        );
        let s = split("evil-paypal.github.io");
        assert!(s.shared_platform);
        assert_eq!(
            (s.registrable, s.sld),
            ("evil-paypal.github.io", "evil-paypal")
        );
        let s = split("com");
        assert_eq!((s.registrable, s.sld, s.sub), ("com", "", ""));
        let s = split("github.io");
        assert_eq!((s.registrable, s.sld), ("github.io", ""));
        let s = split("localhost");
        assert_eq!(s.sld, "");
    }
}
