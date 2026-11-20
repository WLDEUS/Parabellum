import Foundation

/// Where to open the administration page of the current network's router.
///
/// The URL never comes from what a device announces about itself (a name or a Bonjour record can be
/// spoofed): a Freebox gets Free's fixed local address, anything else gets the gateway's private IPv4.
public struct RouterAdmin: Sendable, Hashable {
    public let url: URL
    /// Button label.
    public let title: String
    public let isFreebox: Bool

    /// Freebox OS on the local network (every Freebox model, Neo included; answered by the box itself).
    public static let freeboxURL = URL(string: "http://mafreebox.freebox.fr/")!

    /// Admin page of `device`, which must be the gateway of the current network.
    public static func forGateway(_ device: LanDevice) -> RouterAdmin? {
        guard device.isGateway else { return nil }
        if isFreebox(device) {
            return RouterAdmin(url: freeboxURL, title: "Ouvrir Freebox OS", isFreebox: true)
        }
        guard let ip = device.ipv4, isPrivateIPv4(ip) else { return nil }
        // HTTPS only when the router clearly serves it and not plain HTTP (self-signed otherwise).
        let https = device.openPorts.contains(443) && !device.openPorts.contains(80)
        guard let url = URL(string: "\(https ? "https" : "http")://\(ip)/") else { return nil }
        return RouterAdmin(url: url, title: "Ouvrir la configuration du routeur", isFreebox: false)
    }

    /// Free's boxes: vendor from the MAC prefix (`Freebox SAS`), or the name the box gives itself.
    public static func isFreebox(_ device: LanDevice) -> Bool {
        [device.vendor, device.hostname, device.mdnsName, device.model]
            .compactMap { $0 }
            .contains { TextFold.fold($0).contains("freebox") }
    }

    /// Dotted-quad in 10/8, 172.16/12 or 192.168/16, nothing else (no host names, no ports).
    public static func isPrivateIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [Int] = []
        for p in parts {
            guard (1...3).contains(p.count), p.allSatisfy(\.isASCIIDigit), let v = Int(p), v <= 255 else { return false }
            octets.append(v)
        }
        switch (octets[0], octets[1]) {
        case (10, _): return true
        case (172, 16...31): return true
        case (192, 168): return true
        default: return false
        }
    }
}

private extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
