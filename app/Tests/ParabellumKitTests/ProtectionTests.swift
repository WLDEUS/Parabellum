import Foundation
import ParabellumKit
import XCTest

/// VPN, behaviour guard and privacy payloads emitted by the Rust daemon (`gen_fixtures.rs`).
final class ProtectionTests: XCTestCase {
    // MARK: VPN

    func testVpnStatus() throws {
        let status = try Fixtures.decode(VpnStatus.self, from: "vpn_status.json")
        XCTAssertEqual(status.mode, .untrustedNetworks)
        XCTAssertEqual(status.backend, .singBox)
        XCTAssertEqual(status.state, .connected)
        XCTAssertTrue(status.wanted)
        XCTAssertEqual(status.manualOverride, true)
        XCTAssertEqual(status.profile?.protocolName, "vless")
        XCTAssertEqual(status.profile?.port, 443)
        XCTAssertEqual(status.profile?.transport, "reality")
        XCTAssertEqual(status.interface, "utun5")
        XCTAssertEqual(status.killSwitch, .armed)
        XCTAssertFalse(status.isBlocking)
        XCTAssertEqual(status.network?.current, true)
        XCTAssertEqual(status.network?.id, "gw:00:24:d4:a1:b2:c3")
        let leak = try XCTUnwrap(status.lastLeakTest)
        XCTAssertFalse(leak.ok)
        XCTAssertEqual(leak.checks.count, 2)
        XCTAssertEqual(leak.checks[1].id, "ipv6")
        XCTAssertFalse(leak.checks[1].ok)
        XCTAssertEqual(leak.dnsServers, ["127.0.0.1"])
        XCTAssertNil(leak.publicIpv6)
        XCTAssertTrue(status.engineInstalled)
    }

    func testVpnStatusDefaultOmitsOptionals() throws {
        let status = try Fixtures.decode(VpnStatus.self, from: "vpn_status_default.json")
        XCTAssertEqual(status.mode, .off)
        XCTAssertEqual(status.state, .disconnected)
        XCTAssertEqual(status.killSwitch, .off)
        XCTAssertNil(status.profile)
        XCTAssertNil(status.manualOverride)
        XCTAssertNil(status.lastLeakTest)
        XCTAssertFalse(status.engineInstalled)
    }

    func testNetworksAndServices() throws {
        let networks = try Fixtures.decode([NetworkInfo].self, from: "networks.json")
        XCTAssertEqual(networks.count, 2)
        XCTAssertTrue(networks[0].trusted)
        XCTAssertEqual(networks[0].security, "WPA2 Personal")
        XCTAssertFalse(networks[1].trusted)
        XCTAssertNil(networks[1].gatewayIp)
        let services = try Fixtures.decode([ExternalVpnService].self, from: "vpn_services.json")
        XCTAssertEqual(services.first?.name, "Shadowrocket")
        XCTAssertEqual(services.first?.state, .disconnected)
    }

    // MARK: Guard

    func testGuardStatusAndSnapshots() throws {
        let status = try Fixtures.decode(GuardStatus.self, from: "guard_status.json")
        XCTAssertTrue(status.stealerDetection)
        XCTAssertEqual(status.canaries.count, 1)
        XCTAssertEqual(status.suspended.first?.pid, 4242)
        XCTAssertEqual(status.suspended.first?.alertId, 31)
        XCTAssertEqual(status.detections7d, 2)
        let snapshots = try Fixtures.decode([SnapshotInfo].self, from: "snapshots.json")
        XCTAssertEqual(snapshots.count, 2)
        XCTAssertTrue(snapshots[0].ours)
        XCTAssertNotNil(snapshots[0].createdDate)
        XCTAssertNil(snapshots[1].createdAt)
    }

    func testBehaviorAlert() throws {
        let alert = try Fixtures.decode(SecurityAlert.self, from: "behavior_alert.json")
        XCTAssertEqual(alert.kind, .behavior)
        XCTAssertEqual(alert.processPid, 4242)
        XCTAssertEqual(alert.processPath, "/private/tmp/locker")
        XCTAssertEqual(alert.networkId, "gw:00:24:d4:a1:b2:c3")
        XCTAssertEqual(alert.knownActions, [.killProcess, .resumeProcess, .trustNetwork])
        XCTAssertTrue(AlertAction.killProcess.isDestructive)
        // Older alerts carry none of the new fields.
        let old = try Fixtures.decode([SecurityAlert].self, from: "alerts.json")
        XCTAssertNil(old.first?.processPid)
        XCTAssertNil(old.first?.networkId)
    }

    // MARK: Privacy

    func testIdentityAndBrokers() throws {
        let identity = try Fixtures.decode(IdentityProfile.self, from: "identity.json")
        XCTAssertTrue(identity.isMasked)
        XCTAssertTrue(identity.isComplete)
        XCTAssertEqual(identity.country, "FR")
        let partial = try JSONDecoder().decode(IdentityProfile.self, from: Data(#"{"full_name":"A B"}"#.utf8))
        XCTAssertEqual(partial.fullName, "A B")
        XCTAssertFalse(partial.isComplete)
        let brokers = try Fixtures.decode([BrokerInfo].self, from: "brokers.json")
        XCTAssertEqual(brokers.first?.region, "global")
        XCTAssertEqual(PrivacyLabels.region("eu"), "Europe")
    }

    func testRemovalRequestsAndSummary() throws {
        let requests = try Fixtures.decode([RemovalRequest].self, from: "removal_requests.json")
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0].status, .sent)
        XCTAssertTrue(requests[0].canDraft)
        XCTAssertFalse(requests[0].isOverdue(now: Date(unixSeconds: 1_793_000_000)))
        XCTAssertTrue(requests[0].isOverdue(now: Date(unixSeconds: 1_800_000_000)))
        XCTAssertEqual(requests[1].status, .needsForm)
        XCTAssertFalse(requests[1].canDraft)
        XCTAssertEqual(requests[1].optOutUrl, "https://example.com/opt-out")
        let summary = try Fixtures.decode(RemovalSummary.self, from: "removal_summary.json")
        XCTAssertEqual(summary.total, 120)
        XCTAssertEqual(summary.needsAction, 4)
        XCTAssertEqual(summary.nextSendAt, 1_793_050_000)
        XCTAssertEqual(RemovalStatus(rawValue: "draft_ready"), .draftReady)
    }

    func testMailDraftEml() throws {
        let draft = try Fixtures.decode(MailDraft.self, from: "mail_draft.json")
        let eml = String(decoding: draft.emlData(), as: UTF8.self)
        XCTAssertTrue(eml.hasPrefix("X-Unsent: 1\r\nTo: privacy@acxiom.example\r\nSubject: =?UTF-8?B?"))
        XCTAssertTrue(eml.contains("Content-Transfer-Encoding: base64\r\n\r\n"))
        let parts = eml.components(separatedBy: "\r\n\r\n")
        XCTAssertEqual(parts.count, 2)
        let encoded = parts[1].replacingOccurrences(of: "\r\n", with: "")
        let body = String(decoding: try XCTUnwrap(Data(base64Encoded: encoded)), as: UTF8.self)
        XCTAssertEqual(body, draft.body.replacingOccurrences(of: "\n", with: "\r\n"))
        XCTAssertTrue(parts[1].split(separator: "\r\n").allSatisfy { $0.count <= 76 })
        XCTAssertEqual(MailDraft.fileName(brokerName: "Acxiom / FR", requestId: "2f1c8a4e-0000"), "Acxiom---FR-2f1c8a4e.eml")
        XCTAssertEqual(MailDraft.fileName(brokerName: "///", requestId: "abc"), "demande-abc.eml")
    }

    func testComplaintBreachesAliases() throws {
        let complaint = try Fixtures.decode(ComplaintDraft.self, from: "complaint.json")
        XCTAssertEqual(complaint.authority, "CNIL")
        let breaches = try Fixtures.decode([BreachFinding].self, from: "breaches.json")
        XCTAssertTrue(breaches[0].new)
        XCTAssertTrue(breaches[0].exposesPasswords)
        let aliases = try Fixtures.decode([EmailAlias].self, from: "aliases.json")
        XCTAssertEqual(aliases[0].provider, .addy)
        XCTAssertTrue(aliases[0].active)
    }

    // MARK: Requests

    func testNewRequestsClassification() {
        XCTAssertFalse(Request.vpnConnect.requiresAdmin)
        XCTAssertTrue(Request.vpnConnect.isMutating)
        XCTAssertTrue(Request.vpnDisconnect.requiresAdmin)
        XCTAssertTrue(Request.vpnImportProfile(profile: "ss://x").requiresAdmin)
        XCTAssertFalse(Request.vpnStatus.isMutating)
        XCTAssertTrue(Request.vpnLeakTest.isMutating)
        XCTAssertTrue(Request.setNetworkTrust(networkId: "gw:00:11:22:33:44:55", trusted: true).requiresAdmin)
        XCTAssertFalse(Request.setNetworkTrust(networkId: "gw:00:11:22:33:44:55", trusted: false).requiresAdmin)
        XCTAssertFalse(Request.privacyGetProfile().requiresAdmin)
        XCTAssertFalse(Request.privacyGetProfile().isMutating)
        XCTAssertTrue(Request.privacyGetProfile(reveal: true).requiresAdmin)
        XCTAssertTrue(Request.privacyGetProfile(reveal: true).isMutating)
        XCTAssertTrue(Request.privacyDraft(requestId: "r").requiresAdmin)
        XCTAssertFalse(Request.privacyUpdateRequest(requestId: "r", status: .sent).requiresAdmin)
        XCTAssertFalse(Request.aliasCreate(label: "x").requiresAdmin)
        XCTAssertTrue(Request.resolveAlert(alertId: 1, action: .resumeProcess).requiresAdmin)
        XCTAssertTrue(Request.resolveAlert(alertId: 1, action: .trustNetwork).requiresAdmin)
        XCTAssertFalse(Request.resolveAlert(alertId: 1, action: .killProcess).requiresAdmin)
    }

    func testOptionalRequestFieldsOmitted() throws {
        let start = try JSONValue(data: Request.privacyStartRemoval().encode(id: 1))
        XCTAssertNil(start["broker_ids"])
        let update = try JSONValue(data: Request.privacyUpdateRequest(requestId: "r", status: .sent).encode(id: 2))
        XCTAssertNil(update["note"])
        XCTAssertEqual(update["status"], .string("sent"))
        let profile = try JSONValue(data: Request.privacyGetProfile().encode(id: 3))
        XCTAssertEqual(profile["reveal"], .bool(false))
    }

    // MARK: Config

    func testProtectionConfigDefaults() throws {
        let config = try Fixtures.decode(Config.self, from: "config.json")
        XCTAssertEqual(config.vpn, VpnConfig())
        XCTAssertEqual(config.behaviorGuard, GuardConfig())
        XCTAssertEqual(config.networkGuard, NetworkGuardConfig())
        XCTAssertEqual(config.dataRemoval, DataRemovalConfig())
        XCTAssertEqual(config.breach, BreachConfig())
        XCTAssertEqual(config.aliases, AliasConfig())
        XCTAssertEqual(config.aliases.provider, .disabled)
        let encoded = try JSONValue(encoding: config)
        XCTAssertEqual(encoded["vpn"]?["external_service"], .null)
        XCTAssertEqual(encoded["data_removal"]?["smtp_password"], .null)
        XCTAssertEqual(encoded["breach"]?["hibp_api_key"], .null)
        XCTAssertEqual(encoded["aliases"]?["api_key"], .null)
        XCTAssertEqual(encoded["aliases"]?["provider"], .string("none"))
        XCTAssertEqual(encoded["guard"]?["snapshot_interval_minutes"], .int(60))
    }

    func testProtectionValidationMirrorsRust() {
        var config = Config()
        XCTAssertEqual(config.protectionValidationErrors(), [])
        config.vpn.trustedNetworks = ["gw:aa:bb:cc:dd:ee:ff"]
        config.vpn.externalServerAddresses = ["vpn.example.com", "203.0.113.7", "2001:db8::1"]
        config.behaviorGuard.trustedTeamIds = ["2BUA8C4S2C"]
        config.dataRemoval.sendMode = .smtp
        config.dataRemoval.smtpHost = "smtp.gmail.com"
        config.dataRemoval.fromAddress = "q@example.com"
        config.breach.emails = ["q.m+tag@sub.example.fr"]
        XCTAssertEqual(config.protectionValidationErrors(), [])

        config.vpn.trustedNetworks = ["gw:AA:bb:cc:dd:ee:ff"]
        config.vpn.externalServerAddresses = ["https://x"]
        config.behaviorGuard.snapshotIntervalMinutes = 5
        config.behaviorGuard.trustedTeamIds = ["nope"]
        config.networkGuard.pollSeconds = 1
        config.dataRemoval.regions = ["eu", "mars"]
        config.dataRemoval.smtpHost = ""
        config.breach.emails = ["not an email"]
        config.aliases.baseUrl = "http://addy.local"
        XCTAssertEqual(config.protectionValidationErrors().count, 9)
        XCTAssertEqual(config.validationErrors().count, 9)
    }

    func testSyntaxHelpers() {
        XCTAssertTrue(ConfigSyntax.isEmail("q.m+tag@sub.example.fr"))
        XCTAssertFalse(ConfigSyntax.isEmail("q@localhost"))
        XCTAssertFalse(ConfigSyntax.isEmail("a b@example.com"))
        XCTAssertFalse(ConfigSyntax.isEmail("<x@example.com>"))
        XCTAssertTrue(ConfigSyntax.isHostOrIp("smtp.gmail.com"))
        XCTAssertTrue(ConfigSyntax.isHostOrIp("::1"))
        XCTAssertFalse(ConfigSyntax.isHostOrIp("a..b"))
        XCTAssertTrue(ConfigSyntax.isTeamId("EQHXZ8M8AV"))
        XCTAssertFalse(ConfigSyntax.isTeamId("eqhxz8m8av"))
        XCTAssertTrue(ConfigSyntax.isNetworkId("gw:00:11:22:aa:bb:cc"))
        XCTAssertFalse(ConfigSyntax.isNetworkId("gw:00:11:22:aa:bb"))
    }

    // MARK: Local tools

    func testPwnedPasswordsHashing() {
        XCTAssertEqual(PwnedPasswords.sha1Hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        let response = "003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n"
        XCTAssertEqual(PwnedPasswords.count(suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8", in: response), 9_545_824)
        XCTAssertEqual(PwnedPasswords.count(suffix: "1e4c9b93f3f0682250b6cf8331b7ee68fd8", in: response), 9_545_824)
        XCTAssertEqual(PwnedPasswords.count(suffix: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", in: response), 0)
    }

    func testCliOutputsDecode() throws {
        let clean = #"[{"input":"/Users/q/a.jpg","output":"/Users/q/a.clean.jpg","removed":["GPS","EXIF (appareil, date)"],"method":"native","error":null},{"input":"/etc/hostname","output":null,"removed":[],"method":"native","error":null}]"#
        let reports = try JSONDecoder().decode([CleanReport].self, from: Data(clean.utf8))
        XCTAssertEqual(reports.count, 2)
        XCTAssertEqual(reports[0].removed.first, "GPS")
        XCTAssertNil(reports[1].output)
        let leaked = #"[{"name":"Exemple","url":"https://exemple.fr","username":"q","count":12}]"#
        let entries = try JSONDecoder().decode([LeakedPasswordEntry].self, from: Data(leaked.utf8))
        XCTAssertEqual(entries.first?.count, 12)
    }
}
