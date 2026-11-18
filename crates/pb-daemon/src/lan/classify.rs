//! Device type guess from what a scan learnt: router flag, Bonjour services and model, host / instance
//! names, vendor, open ports. Strongest evidence first; `Unknown` rather than a wild guess.

use pb_core::model::LanDeviceType as T;

/// Facts used by [`guess`].
#[derive(Debug, Clone, Default)]
pub struct Evidence<'a> {
    pub is_gateway: bool,
    pub is_self: bool,
    pub vendor: Option<&'a str>,
    pub model: Option<&'a str>,
    pub services: &'a [String],
    pub names: Vec<&'a str>,
    pub open_ports: &'a [u16],
}

fn has(services: &[String], ty: &str) -> bool {
    services.iter().any(|s| s == ty)
}

/// Apple / Google model identifiers announced over Bonjour.
fn from_model(model: &str) -> Option<T> {
    let m = model.to_ascii_lowercase();
    let starts = |p: &str| m.starts_with(p);
    if starts("iphone") {
        Some(T::Phone)
    } else if starts("ipad") {
        Some(T::Tablet)
    } else if starts("appletv") {
        Some(T::Tv)
    } else if starts("audioaccessory") || m.contains("homepod") || m.contains("sonos") {
        Some(T::Speaker)
    } else if starts("mac") || starts("imac") {
        Some(T::Computer)
    } else if m.contains("chromecast") || m.contains("google tv") || m.contains("bravia") {
        Some(T::Tv)
    } else if m.contains("nest audio") || m.contains("home mini") || m.contains("nest mini") {
        Some(T::Speaker)
    } else if m.contains("laserjet")
        || m.contains("officejet")
        || m.contains("deskjet")
        || m.contains("envy")
        || m.contains("pixma")
        || m.contains("ecotank")
    {
        Some(T::Printer)
    } else {
        None
    }
}

fn from_services(s: &[String]) -> Option<T> {
    let printer = [
        "_ipp._tcp",
        "_ipps._tcp",
        "_printer._tcp",
        "_pdl-datastream._tcp",
        "_scanner._tcp",
    ];
    if printer.iter().any(|t| has(s, t)) {
        return Some(T::Printer);
    }
    if has(s, "_googlecast._tcp") || has(s, "_androidtvremote2._tcp") || has(s, "_amzn-wplay._tcp")
    {
        return Some(T::Tv);
    }
    if has(s, "_sonos._tcp") || has(s, "_spotify-connect._tcp") {
        return Some(T::Speaker);
    }
    if has(s, "_rtsp._tcp") || has(s, "_axis-video._tcp") {
        return Some(T::Camera);
    }
    if has(s, "_hap._tcp") || has(s, "_matter._tcp") || has(s, "_hue._tcp") {
        return Some(T::Iot);
    }
    if has(s, "_ssh._tcp") || has(s, "_workstation._tcp") || has(s, "_rfb._tcp") {
        return Some(T::Computer);
    }
    None
}

fn from_names(names: &[&str]) -> Option<T> {
    for n in names {
        let l = n.to_ascii_lowercase();
        let c = |p: &str| l.contains(p);
        let t = if c("iphone") || c("galaxy-s") || c("pixel-") || c("android-") || c("oneplus") {
            Some(T::Phone)
        } else if c("ipad") || c("galaxy-tab") {
            Some(T::Tablet)
        } else if c("macbook")
            || c("imac")
            || c("mac-mini")
            || c("mac-studio")
            || c("desktop-")
            || c("laptop-")
        {
            Some(T::Computer)
        } else if c("apple-tv")
            || c("appletv")
            || c("chromecast")
            || c("bravia")
            || c("-tv")
            || c("roku")
        {
            Some(T::Tv)
        } else if c("homepod") || c("sonos") || c("echo-") {
            Some(T::Speaker)
        } else if c("printer")
            || c("imprimante")
            || c("laserjet")
            || l.starts_with("brn")
            || l.starts_with("brw")
            || c("epson")
        {
            Some(T::Printer)
        } else if c("playstation") || c("ps5") || c("xbox") || c("nintendo") {
            Some(T::Console)
        } else if c("synology")
            || c("diskstation")
            || c("qnap")
            || l.starts_with("nas-")
            || l.ends_with("-nas")
        {
            Some(T::Nas)
        } else if c("camera") || c("cam-") || c("ipcam") {
            Some(T::Camera)
        } else {
            None
        };
        if t.is_some() {
            return t;
        }
    }
    None
}

fn from_vendor(v: &str) -> Option<T> {
    let l = v.to_ascii_lowercase();
    let any = |keys: &[&str]| keys.iter().any(|k| l.contains(k));
    if any(&[
        "hewlett packard",
        "hp inc",
        "brother industries",
        "canon inc",
        "seiko epson",
        "lexmark",
        "kyocera",
        "xerox",
        "ricoh",
    ]) {
        Some(T::Printer)
    } else if any(&["sonos", "bose", "harman", "devialet"]) {
        Some(T::Speaker)
    } else if any(&["synology", "qnap", "western digital", "asustor"]) {
        Some(T::Nas)
    } else if any(&[
        "hikvision",
        "dahua",
        "axis communications",
        "reolink",
        "wyze",
        "arlo",
        "ezviz",
    ]) {
        Some(T::Camera)
    } else if any(&["nintendo", "sony interactive"]) {
        Some(T::Console)
    } else if any(&["roku", "vizio", "tcl", "hisense"]) {
        Some(T::Tv)
    } else if any(&[
        "espressif",
        "tuya",
        "shelly",
        "signify",
        "philips lighting",
        "ecobee",
        "nest labs",
        "ring llc",
        "irobot",
        "netatmo",
        "somfy",
        "sonoff",
        "itead",
        "meross",
        "lifx",
        "nanoleaf",
        "tado",
    ]) {
        Some(T::Iot)
    } else if any(&[
        "raspberry pi",
        "intel corporate",
        "dell",
        "lenovo",
        "asustek",
        "micro-star",
        "gigabyte",
    ]) {
        Some(T::Computer)
    } else {
        None
    }
}

fn from_ports(p: &[u16]) -> Option<T> {
    let has = |x: u16| p.contains(&x);
    if has(9100) || has(631) || has(515) {
        Some(T::Printer)
    } else if has(554) {
        Some(T::Camera)
    } else if has(62078) {
        Some(T::Phone)
    } else if has(8009) {
        Some(T::Tv)
    } else if has(3389) || has(5900) || has(22) {
        Some(T::Computer)
    } else {
        None
    }
}

/// Best guess (router flag > Bonjour model > Bonjour services > names > vendor > ports).
pub fn guess(e: &Evidence<'_>) -> T {
    if e.is_gateway {
        return T::Router;
    }
    if e.is_self {
        return T::Computer;
    }
    e.model
        .and_then(from_model)
        .or_else(|| from_services(e.services))
        .or_else(|| from_names(&e.names))
        .or_else(|| e.vendor.and_then(from_vendor))
        .or_else(|| from_ports(e.open_ports))
        .unwrap_or(T::Unknown)
}

/// Model from Bonjour TXT records (`model`, `md`, `am`, `rpmd`, `ty`, `product`, `usb_mdl`).
pub fn model_from_txt(txt: &std::collections::BTreeMap<String, String>) -> Option<String> {
    ["model", "md", "am", "rpmd", "ty", "product", "usb_mdl"]
        .iter()
        .filter_map(|k| txt.get(*k))
        .map(|v| {
            v.trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim()
        })
        .find(|v| !v.is_empty())
        .map(|v| v.chars().take(80).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev<'a>(services: &'a [String], ports: &'a [u16]) -> Evidence<'a> {
        Evidence {
            services,
            open_ports: ports,
            ..Default::default()
        }
    }

    #[test]
    fn guesses() {
        let none: Vec<String> = vec![];
        let mut e = ev(&none, &[]);
        assert_eq!(guess(&e), T::Unknown);
        e.is_gateway = true;
        assert_eq!(guess(&e), T::Router);
        let mut e = ev(&none, &[]);
        e.model = Some("AppleTV11,1");
        assert_eq!(guess(&e), T::Tv);
        e.model = Some("iPhone15,3");
        assert_eq!(guess(&e), T::Phone);
        let printer = vec!["_ipp._tcp".to_string()];
        assert_eq!(guess(&ev(&printer, &[])), T::Printer);
        let cast = vec!["_googlecast._tcp".to_string()];
        assert_eq!(guess(&ev(&cast, &[])), T::Tv);
        let mut e = ev(&none, &[]);
        e.names = vec!["BRW3C2AF4123456"];
        assert_eq!(guess(&e), T::Printer);
        let mut e = ev(&none, &[]);
        e.vendor = Some("Espressif Inc.");
        assert_eq!(guess(&e), T::Iot);
        e.vendor = Some("Apple, Inc.");
        assert_eq!(guess(&e), T::Unknown);
        assert_eq!(guess(&ev(&none, &[80, 554])), T::Camera);
        assert_eq!(guess(&ev(&none, &[62078])), T::Phone);
    }

    #[test]
    fn txt_model() {
        let mut t = std::collections::BTreeMap::new();
        t.insert(
            "product".to_string(),
            "(HP LaserJet Pro M404dn)".to_string(),
        );
        assert_eq!(
            model_from_txt(&t).as_deref(),
            Some("HP LaserJet Pro M404dn")
        );
        t.insert("model".to_string(), "Mac14,2".to_string());
        assert_eq!(model_from_txt(&t).as_deref(), Some("Mac14,2"));
        assert_eq!(model_from_txt(&Default::default()), None);
    }
}
