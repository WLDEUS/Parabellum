import Foundation
import ParabellumKit
import XCTest

final class SearchTests: XCTestCase {
    private func doc(_ kind: String, _ key: String, _ title: String, _ subtitle: String = "", date: Int = 0, _ fields: [String: String] = [:]) -> SearchDocument {
        SearchDocument(kind: kind, key: key, title: title, subtitle: subtitle, date: Date(timeIntervalSince1970: TimeInterval(date)), fields: fields)
    }

    private var index: SearchIndex {
        SearchIndex([
            doc("request", "1", "Acxiom", "Envoyée", date: 30, ["statut": "Envoyée", "reponse": "Accusé de réception, réponse sous 30 jours."]),
            doc("request", "2", "Société Générale Data", "En file d'attente", date: 20, ["statut": "En file d'attente"]),
            doc("broker", "acxiom", "Acxiom", "marketing · International", ["site": "https://www.acxiom.com"]),
            doc("breach", "b", "ExampleShop", "c.m@example.com", date: 10, ["donnees": "Email addresses, Passwords"]),
        ], kindAliases: ["request": ["demande"], "breach": ["fuite"]])
    }

    func testFoldingAndTokens() {
        XCTAssertEqual(TextFold.fold("Réf. ÉLYSÉE"), "ref. elysee")
        XCTAssertEqual(TextFold.tokens("Accusé de réception, d'attente"), ["accuse", "de", "reception", "d", "attente"])
    }

    func testDamerauDistance() {
        XCTAssertEqual(TextFold.distance("acxiom", "acxiom", limit: 2), 0)
        XCTAssertEqual(TextFold.distance("axciom", "acxiom", limit: 2), 1) // transposition
        XCTAssertEqual(TextFold.distance("acxiom", "acxion", limit: 2), 1)
        XCTAssertNil(TextFold.distance("acxiom", "oracle", limit: 2))
        XCTAssertEqual(TextFold.allowedEdits("ab"), 0)
        XCTAssertEqual(TextFold.allowedEdits("abcd"), 1)
        XCTAssertEqual(TextFold.allowedEdits("abcdef"), 2)
    }

    func testExactPrefixFuzzyAndAccents() {
        XCTAssertEqual(index.search("acxiom").first?.document.title, "Acxiom")
        XCTAssertEqual(index.search("acx").count, 2)
        XCTAssertEqual(Set(index.search("axciom").map(\.document.key)), ["1", "acxiom"])
        XCTAssertEqual(index.search("societe").first?.document.key, "2")
        XCTAssertTrue(index.search("zzzz").isEmpty)
        XCTAssertTrue(index.search("   ").isEmpty)
    }

    func testAllTermsMustMatchAndRanking() {
        let hits = index.search("acxiom reception")
        XCTAssertEqual(hits.map(\.document.key), ["1"])
        XCTAssertEqual(hits.first?.snippet?.field, "reponse")
        XCTAssertTrue(hits.first?.matchedWords.contains("reception") == true)
        // Title match beats a field match.
        XCTAssertGreaterThan(index.search("acxiom")[0].score, index.search("passwords")[0].score)
    }

    func testFiltersPhrasesExclusions() {
        XCTAssertEqual(index.search("statut:attente").map(\.document.key), ["2"])
        XCTAssertEqual(index.search("type:fuite").map(\.document.key), ["b"])
        XCTAssertEqual(index.search("type:demande").map(\.document.key), ["1", "2"]) // filters only: newest first
        XCTAssertEqual(index.search("acxiom -marketing").map(\.document.key), ["1"])
        XCTAssertEqual(index.search("\"accuse de reception\"").map(\.document.key), ["1"])
        XCTAssertTrue(index.search("statut:refusee").isEmpty)
        XCTAssertTrue(index.search("inconnu:x").isEmpty)
    }

    func testHighlightRanges() {
        let text = "Accusé de réception reçu"
        let ranges = TextFold.ranges(in: text, matching: ["reception", "accuse"])
        XCTAssertEqual(ranges.map { String(text[$0]) }, ["Accusé", "réception"])
    }

    func testPrivacyDocumentsFromDaemonPayloads() throws {
        let requests = try Fixtures.decode([RemovalRequest].self, from: "removal_requests.json")
        let brokers = try Fixtures.decode([BrokerInfo].self, from: "brokers.json")
        let breaches = try Fixtures.decode([BreachFinding].self, from: "breaches.json")
        let aliases = try Fixtures.decode([EmailAlias].self, from: "aliases.json")
        let idx = PrivacySearch.index(requests: requests, brokers: brokers, breaches: breaches, aliases: aliases)
        XCTAssertEqual(idx.count, 5)
        XCTAssertEqual(PrivacySearch.reference(requestId: "2f1c8a4e-0000-4000-8000-000000000002"), "PB-2f1c8a4e")
        XCTAssertEqual(idx.search("PB-2f1c8a4e").count, 2) // both requests share the prefix in this fixture
        XCTAssertEqual(idx.search("type:fuite password").first?.document.title, "ExampleShop")
        XCTAssertEqual(idx.search("boutique").first?.document.kind, PrivacySearch.Kind.alias.rawValue)
        XCTAssertEqual(idx.search("statut:formulaire").map(\.document.kind), [PrivacySearch.Kind.request.rawValue])
        XCTAssertEqual(Set(idx.search("type:courtier").map(\.document.key)), ["acxiom"])
    }
}

final class RouterAdminTests: XCTestCase {
    private func gateway(_ json: String) throws -> LanDevice {
        let base = """
        {"mac":"aa:bb:cc:00:00:01","ipv6":[],"private_mac":false,"device_type":"router","services":[],
         "first_seen":1,"last_seen":2,"online":true,"trusted":false,"baseline":true,"is_gateway":true,"is_self":false,
        """
        return try JSONDecoder().decode(LanDevice.self, from: Data((base + json + "}").utf8))
    }

    func testFreeboxFromFixture() throws {
        let status = try Fixtures.decode(LanStatus.self, from: "lan_status.json")
        let gw = try XCTUnwrap(status.network?.devices.first { $0.isGateway })
        let admin = try XCTUnwrap(RouterAdmin.forGateway(gw))
        XCTAssertTrue(admin.isFreebox)
        XCTAssertEqual(admin.url.absoluteString, "http://mafreebox.freebox.fr/")
    }

    func testGenericRouterUsesPrivateGatewayIP() throws {
        let http = try XCTUnwrap(RouterAdmin.forGateway(gateway(#""ipv4":"192.168.1.254","open_ports":[80,443]"#)))
        XCTAssertEqual(http.url.absoluteString, "http://192.168.1.254/")
        XCTAssertFalse(http.isFreebox)
        let https = try XCTUnwrap(RouterAdmin.forGateway(gateway(#""ipv4":"10.0.0.1","open_ports":[443]"#)))
        XCTAssertEqual(https.url.absoluteString, "https://10.0.0.1/")
        // A device calling itself "freebox" still gets Free's fixed address, never something it announced.
        let named = try XCTUnwrap(RouterAdmin.forGateway(gateway(#""ipv4":"192.168.0.1","open_ports":[],"hostname":"Freebox-Server.local""#)))
        XCTAssertEqual(named.url, RouterAdmin.freeboxURL)
        XCTAssertNil(RouterAdmin.forGateway(try gateway(#""ipv4":"8.8.8.8","open_ports":[]"#)))
    }

    func testPrivateIPv4() {
        for ip in ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1"] {
            XCTAssertTrue(RouterAdmin.isPrivateIPv4(ip), ip)
        }
        for ip in ["172.32.0.1", "8.8.8.8", "192.168.1", "192.168.1.1:8080", "192.168.1.256", "evil.example", "192.168.01.1x"] {
            XCTAssertFalse(RouterAdmin.isPrivateIPv4(ip), ip)
        }
    }
}
