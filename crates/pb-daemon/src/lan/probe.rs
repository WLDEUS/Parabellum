//! What a LAN scan does on the system, behind [`LanSystem`] so the orchestration is tested on Linux with
//! scripted outputs.
//!
//! Passive scan: `ifconfig <if>`, `arp -an`, `ndp -an` (system caches, no packet sent).
//! Active scan, before reading the caches:
//! - one empty UDP datagram to port 9 (discard) of every address of the /24, at most
//!   [`SWEEP_PER_SECOND`] per second: the kernel resolves each address with ARP, so every device that
//!   answers ARP lands in the cache, whatever its firewall does with the datagram;
//! - one IPv6 all-nodes ping (`ping6 -c 2 -I <if> ff02::1`) for the NDP cache;
//! - Bonjour: `dns-sd -Z <type> local.` for a fixed list of service types, all at once, each stopped after
//!   [`MDNS_BROWSE`]; target hosts resolved through the system resolver (mDNSResponder).
//!
//! Every tool runs by absolute path with a cleared environment, `LANG`/`LC_ALL=C` and a timeout.

use super::parse::{self, IfaceInfo, MdnsService};
use super::store::Observation;
use async_trait::async_trait;
use pb_vpn::netprobe::{parse_arp, NetworkSnapshot};
use pb_vpn::sys::{CmdOutput, ARP, CMD_TIMEOUT, IFCONFIG};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

pub const NDP: &str = "/usr/sbin/ndp";
pub const PING6: &str = "/sbin/ping6";
pub const DNS_SD: &str = "/usr/bin/dns-sd";
/// Datagrams per second of the sweep.
pub const SWEEP_PER_SECOND: u32 = 64;
/// Lifetime of each `dns-sd -Z` browse.
pub const MDNS_BROWSE: Duration = Duration::from_millis(3500);
/// Bonjour hosts resolved per scan.
pub const MAX_MDNS_HOSTS: usize = 64;
/// Service types browsed during an active scan.
pub const MDNS_TYPES: &[&str] = &[
    "_airplay._tcp",
    "_raop._tcp",
    "_googlecast._tcp",
    "_companion-link._tcp",
    "_device-info._tcp",
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_scanner._tcp",
    "_hap._tcp",
    "_matter._tcp",
    "_hue._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_ssh._tcp",
    "_rfb._tcp",
    "_workstation._tcp",
    "_spotify-connect._tcp",
    "_sonos._tcp",
    "_amzn-wplay._tcp",
    "_androidtvremote2._tcp",
    "_rtsp._tcp",
    "_axis-video._tcp",
];
/// Checked by the on-demand port check (the 20 most common services of home devices).
pub const TOP_PORTS: [u16; 20] = [
    21, 22, 23, 25, 53, 80, 139, 443, 445, 515, 548, 554, 631, 3389, 5000, 5900, 8008, 8080, 8443,
    9100,
];
pub const PORT_TIMEOUT: Duration = Duration::from_millis(1500);
/// Captive-portal probe (Apple's own, answers `Success`).
pub const CAPTIVE_URL: &str = "https://captive.apple.com/hotspot-detect.html";

/// System access of the LAN scan.
#[async_trait]
pub trait LanSystem: Send + Sync + 'static {
    fn is_macos(&self) -> bool;
    /// The network the Mac is on (default route, router MAC, Wi-Fi name).
    async fn snapshot(&self) -> Option<NetworkSnapshot>;
    /// Run a tool to completion.
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String>;
    /// Run a tool that never exits by itself (`dns-sd`) for `duration`, then stop it; returns its stdout.
    async fn run_for(
        &self,
        program: &str,
        args: &[&str],
        duration: Duration,
    ) -> Result<String, String>;
    /// One empty UDP datagram to port 9 of each target, rate-limited.
    async fn udp_touch(&self, targets: &[Ipv4Addr], per_second: u32);
    /// Open TCP ports of `ip` among `ports`.
    async fn tcp_open(&self, ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<u16>;
    /// System resolver (`.local` names go to mDNSResponder).
    async fn resolve(&self, host: &str) -> Vec<IpAddr>;
    /// `true` when Apple's captive-portal probe does not answer `Success` (portal, or no Internet).
    async fn captive(&self) -> bool;
}

/// Production implementation.
pub struct RealLanSystem {
    sys: pb_vpn::sys::RealSystem,
}

impl Default for RealLanSystem {
    fn default() -> Self {
        Self {
            sys: pb_vpn::sys::RealSystem::new(),
        }
    }
}

const MAX_STREAM_OUTPUT: usize = 512 * 1024;

#[async_trait]
impl LanSystem for RealLanSystem {
    fn is_macos(&self) -> bool {
        cfg!(target_os = "macos")
    }

    async fn snapshot(&self) -> Option<NetworkSnapshot> {
        pb_vpn::netprobe::probe(&self.sys).await
    }

    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String> {
        use pb_vpn::sys::System;
        self.sys.run(program, args, timeout).await
    }

    async fn run_for(
        &self,
        program: &str,
        args: &[&str],
        duration: Duration,
    ) -> Result<String, String> {
        use tokio::io::AsyncReadExt;
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", pb_vpn::sys::TOOL_PATH_ENV)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("{program} : lancement impossible : {e}"))?;
        let mut stdout = child.stdout.take().ok_or("stdout absent")?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            match tokio::time::timeout_at(deadline, stdout.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if buf.len() < MAX_STREAM_OUTPUT {
                        buf.extend_from_slice(&chunk[..n.min(MAX_STREAM_OUTPUT - buf.len())]);
                    }
                }
                Ok(Err(_)) => break,
            }
        }
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    async fn udp_touch(&self, targets: &[Ipv4Addr], per_second: u32) {
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            return;
        };
        let gap = Duration::from_micros(1_000_000 / u64::from(per_second.max(1)));
        for t in targets {
            // Errors (EHOSTDOWN for addresses that recently failed ARP…) are expected.
            let _ = sock.send_to(&[], (*t, 9)).await;
            tokio::time::sleep(gap).await;
        }
    }

    async fn tcp_open(&self, ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<u16> {
        let tries = ports.iter().map(|p| async move {
            let ok = matches!(
                tokio::time::timeout(timeout, tokio::net::TcpStream::connect((ip, *p))).await,
                Ok(Ok(_))
            );
            ok.then_some(*p)
        });
        let mut v: Vec<u16> = futures::future::join_all(tries)
            .await
            .into_iter()
            .flatten()
            .collect();
        v.sort_unstable();
        v
    }

    async fn resolve(&self, host: &str) -> Vec<IpAddr> {
        use pb_vpn::sys::System;
        match tokio::time::timeout(Duration::from_secs(3), self.sys.resolve(host)).await {
            Ok(Ok(v)) => v,
            _ => vec![],
        }
    }

    async fn captive(&self) -> bool {
        use pb_vpn::sys::System;
        match self.sys.http_get(CAPTIVE_URL, Duration::from_secs(5)).await {
            Ok(body) => !body.contains("Success"),
            Err(_) => true,
        }
    }
}

/// Our side of the network.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub iface: IfaceInfo,
    pub subnet: Option<String>,
    pub observations: Vec<Observation>,
}

/// Interface names are passed to tools: letters and digits only.
pub fn valid_iface(i: &str) -> bool {
    !i.is_empty() && i.len() <= 16 && i.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Bonjour host names are passed to the resolver only.
fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.ends_with(".local")
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Run the scan of `snap`'s interface and build one observation per MAC address.
pub async fn collect(
    sys: &dyn LanSystem,
    snap: &NetworkSnapshot,
    active: bool,
    progress: &(dyn Fn(f32, &str) + Send + Sync),
) -> ScanResult {
    let iface_name = snap.interface.as_str();
    if !valid_iface(iface_name) {
        return ScanResult::default();
    }
    progress(0.05, "Lecture de l'interface réseau");
    let iface = match sys.run(IFCONFIG, &[iface_name], CMD_TIMEOUT).await {
        Ok(o) => parse::parse_ifconfig(&o.stdout),
        Err(_) => IfaceInfo::default(),
    };
    let subnet = iface
        .ipv4
        .zip(iface.prefix)
        .map(|(ip, p)| parse::subnet_string(ip, p));
    let mut mdns: Vec<MdnsService> = vec![];
    if active {
        if let (Some(ip), Some(prefix)) = (iface.ipv4, iface.prefix) {
            let targets = parse::sweep_targets(ip, prefix);
            progress(0.1, "Balayage léger du sous-réseau");
            // Bonjour browsing runs during the sweep.
            let browse = async {
                let runs = MDNS_TYPES.iter().map(|t| async move {
                    sys.run_for(DNS_SD, &["-Z", t, "local."], MDNS_BROWSE)
                        .await
                        .map(|o| parse::parse_dnssd_zone(&o))
                        .unwrap_or_default()
                });
                futures::future::join_all(runs).await.concat()
            };
            let sweep = async {
                sys.udp_touch(&targets, SWEEP_PER_SECOND).await;
                let _ = sys
                    .run(
                        PING6,
                        &["-c", "2", "-I", iface_name, "ff02::1"],
                        Duration::from_secs(5),
                    )
                    .await;
            };
            let (found, ()) = tokio::join!(browse, sweep);
            mdns = found;
            progress(0.7, "Attente des réponses");
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
    }
    progress(0.75, "Lecture des caches ARP et NDP");
    let arp: Vec<_> = match sys.run(ARP, &["-an"], CMD_TIMEOUT).await {
        Ok(o) => parse_arp(&o.stdout)
            .into_iter()
            .filter(|e| e.interface == iface_name)
            .collect(),
        Err(_) => vec![],
    };
    let ndp: Vec<_> = match sys.run(NDP, &["-an"], CMD_TIMEOUT).await {
        Ok(o) => parse::parse_ndp(&o.stdout)
            .into_iter()
            .filter(|e| e.interface == iface_name)
            .collect(),
        Err(_) => vec![],
    };
    let mut obs: BTreeMap<String, Observation> = BTreeMap::new();
    let mut by_ip: HashMap<IpAddr, String> = HashMap::new();
    for e in &arp {
        let o = obs.entry(e.mac.clone()).or_insert_with(|| Observation {
            mac: e.mac.clone(),
            ..Default::default()
        });
        // `arp -an` lists the subnet's addresses only; keep the first one per MAC.
        if o.ipv4.is_none() {
            o.ipv4 = Some(e.ip.to_string());
        }
        by_ip.insert(IpAddr::V4(e.ip), e.mac.clone());
    }
    for e in &ndp {
        let o = obs.entry(e.mac.clone()).or_insert_with(|| Observation {
            mac: e.mac.clone(),
            ..Default::default()
        });
        let s = e.ip.to_string();
        if !o.ipv6.contains(&s) {
            o.ipv6.push(s);
        }
        by_ip.insert(IpAddr::V6(e.ip), e.mac.clone());
    }
    if !mdns.is_empty() {
        progress(0.85, "Identification Bonjour");
        let hosts: Vec<String> = {
            let mut h: Vec<String> = mdns
                .iter()
                .filter_map(|s| s.host.clone())
                .filter(|h| valid_host(h))
                .collect();
            h.sort();
            h.dedup();
            h.truncate(MAX_MDNS_HOSTS);
            h
        };
        let resolved = futures::future::join_all(
            hosts
                .iter()
                .map(|h| async move { (h.clone(), sys.resolve(h).await) }),
        )
        .await;
        let host_mac: HashMap<String, String> = resolved
            .into_iter()
            .filter_map(|(h, ips)| {
                ips.iter()
                    .find_map(|ip| by_ip.get(ip).cloned())
                    .map(|m| (h, m))
            })
            .collect();
        for s in &mdns {
            let Some(mac) = s.host.as_ref().and_then(|h| host_mac.get(h)) else {
                continue;
            };
            let Some(o) = obs.get_mut(mac) else { continue };
            if !o.services.contains(&s.service_type) {
                o.services.push(s.service_type.clone());
            }
            if o.hostname.is_none() {
                o.hostname = s.host.clone();
            }
            let friendly = s
                .txt
                .get("fn")
                .filter(|v| !v.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| s.instance.clone());
            // Device-level names beat per-service ones (a printer's IPP name includes its serial).
            let better = o.mdns_name.is_none()
                || matches!(
                    s.service_type.as_str(),
                    "_companion-link._tcp" | "_airplay._tcp" | "_googlecast._tcp"
                );
            if better && !friendly.is_empty() {
                o.mdns_name = Some(
                    friendly
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(80)
                        .collect(),
                );
            }
            if o.model.is_none() {
                o.model = super::classify::model_from_txt(&s.txt);
            }
        }
    }
    let gw_mac = snap.gateway_mac.as_deref();
    for o in obs.values_mut() {
        o.is_gateway = Some(o.mac.as_str()) == gw_mac;
        o.is_self = iface.mac.as_deref() == Some(o.mac.as_str());
    }
    progress(0.95, "Mise à jour de l'inventaire");
    ScanResult {
        iface,
        subnet,
        observations: obs.into_values().collect(),
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;

    /// Scripted [`LanSystem`]: responses keyed by `program + first args`.
    #[derive(Default)]
    pub struct FakeLan {
        pub macos: bool,
        pub snap: Option<NetworkSnapshot>,
        pub outputs: Mutex<Vec<(String, Vec<String>, String)>>,
        pub calls: Mutex<Vec<String>>,
        pub touched: Mutex<Vec<Ipv4Addr>>,
        pub resolved: HashMap<String, Vec<IpAddr>>,
        pub open_ports: Vec<u16>,
        pub captive: bool,
    }

    impl FakeLan {
        pub fn respond(&self, program: &str, args: &[&str], out: &str) {
            self.outputs.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
                out.to_string(),
            ));
        }

        fn find(&self, program: &str, args: &[&str]) -> Option<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            self.outputs
                .lock()
                .unwrap()
                .iter()
                .find(|(p, a, _)| p == program && a.iter().zip(args).all(|(x, y)| x == y))
                .map(|(_, _, o)| o.clone())
        }

        pub fn count(&self, prefix: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with(prefix))
                .count()
        }
    }

    #[async_trait]
    impl LanSystem for FakeLan {
        fn is_macos(&self) -> bool {
            self.macos
        }
        async fn snapshot(&self) -> Option<NetworkSnapshot> {
            self.snap.clone()
        }
        async fn run(
            &self,
            program: &str,
            args: &[&str],
            _t: Duration,
        ) -> Result<CmdOutput, String> {
            self.find(program, args)
                .map(|stdout| CmdOutput {
                    status: Some(0),
                    stdout,
                    stderr: String::new(),
                })
                .ok_or_else(|| "absent".into())
        }
        async fn run_for(
            &self,
            program: &str,
            args: &[&str],
            _d: Duration,
        ) -> Result<String, String> {
            Ok(self.find(program, args).unwrap_or_default())
        }
        async fn udp_touch(&self, targets: &[Ipv4Addr], _p: u32) {
            self.touched.lock().unwrap().extend_from_slice(targets);
        }
        async fn tcp_open(&self, _ip: Ipv4Addr, ports: &[u16], _t: Duration) -> Vec<u16> {
            ports
                .iter()
                .copied()
                .filter(|p| self.open_ports.contains(p))
                .collect()
        }
        async fn resolve(&self, host: &str) -> Vec<IpAddr> {
            self.resolved.get(host).cloned().unwrap_or_default()
        }
        async fn captive(&self) -> bool {
            self.captive
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::fake::FakeLan;
    use super::*;
    use crate::lan::parse::fixtures::*;

    pub fn home_snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            interface: "en0".into(),
            gateway_ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            gateway_mac: Some("00:24:d4:a1:b2:c3".into()),
            ssid: Some("Livebox-1234".into()),
            is_wifi: true,
            ..Default::default()
        }
    }

    pub fn home_system() -> FakeLan {
        let mut f = FakeLan {
            macos: true,
            snap: Some(home_snapshot()),
            ..Default::default()
        };
        f.respond(IFCONFIG, &["en0"], IFCONFIG_EN0);
        f.respond(ARP, &["-an"], ARP_AN);
        f.respond(NDP, &["-an"], NDP_AN);
        f.respond(DNS_SD, &["-Z", "_airplay._tcp"], DNSSD_AIRPLAY);
        f.respond(DNS_SD, &["-Z", "_ipp._tcp"], DNSSD_IPP);
        f.resolved.insert(
            "Apple-TV.local".into(),
            vec!["192.168.1.30".parse().unwrap()],
        );
        f.resolved.insert(
            "MacBook-Pro-de-Camille.local".into(),
            vec!["fe80::4a1:9bff:fe3c:2211".parse().unwrap()],
        );
        f.resolved.insert(
            "HP7E1A2B.local".into(),
            vec!["192.168.1.77".parse().unwrap()],
        );
        f
    }

    #[tokio::test]
    async fn passive_scan_reads_caches_only() {
        let sys = home_system();
        let r = collect(&sys, &home_snapshot(), false, &|_, _| {}).await;
        assert!(sys.touched.lock().unwrap().is_empty());
        assert_eq!(sys.count(DNS_SD), 0);
        assert_eq!(sys.count(PING6), 0);
        assert_eq!(r.subnet.as_deref(), Some("192.168.1.0/24"));
        // 6 ARP entries on en0 (incomplete / broadcast / multicast / bridge100 skipped).
        assert_eq!(r.observations.len(), 6);
        let gw = r.observations.iter().find(|o| o.is_gateway).unwrap();
        assert_eq!(gw.ipv4.as_deref(), Some("192.168.1.1"));
        assert_eq!(gw.ipv6.len(), 2);
        let me = r.observations.iter().find(|o| o.is_self).unwrap();
        assert_eq!(me.mac, "3c:22:fb:01:02:03");
        assert!(r.observations.iter().all(|o| o.services.is_empty()));
    }

    #[tokio::test]
    async fn active_scan_sweeps_and_browses() {
        let sys = home_system();
        let steps = std::sync::Mutex::new(vec![]);
        let r = collect(&sys, &home_snapshot(), true, &|p, s| {
            steps.lock().unwrap().push((p, s.to_string()))
        })
        .await;
        assert_eq!(sys.touched.lock().unwrap().len(), 253);
        assert_eq!(sys.count(DNS_SD), MDNS_TYPES.len());
        assert_eq!(sys.count(PING6), 1);
        let tv = r
            .observations
            .iter()
            .find(|o| o.mac == "90:dd:5d:11:22:33")
            .unwrap();
        assert_eq!(tv.mdns_name.as_deref(), Some("Salon"));
        assert_eq!(tv.hostname.as_deref(), Some("Apple-TV.local"));
        assert_eq!(tv.model.as_deref(), Some("AppleTV11,1"));
        assert_eq!(tv.services, vec!["_airplay._tcp".to_string()]);
        // Resolved over IPv6 and mapped through the NDP cache.
        let mac = r
            .observations
            .iter()
            .find(|o| o.mac == "f0:18:98:aa:bb:cc")
            .unwrap();
        assert_eq!(mac.mdns_name.as_deref(), Some("MacBook Pro de Camille"));
        let printer = r
            .observations
            .iter()
            .find(|o| o.mac == "30:5a:3a:44:55:66")
            .unwrap();
        assert_eq!(printer.model.as_deref(), Some("HP LaserJet Pro M404dn"));
        let s = steps.lock().unwrap();
        assert!(s.windows(2).all(|w| w[0].0 <= w[1].0));
    }

    #[tokio::test]
    async fn rejects_odd_interfaces() {
        let sys = home_system();
        let mut snap = home_snapshot();
        snap.interface = "en0;rm".into();
        assert!(collect(&sys, &snap, true, &|_, _| {})
            .await
            .observations
            .is_empty());
        assert!(
            valid_host("Apple-TV.local") && !valid_host("evil.com") && !valid_host("a b.local")
        );
    }
}
