import Foundation
import ParabellumKit
import XCTest

/// Intelligence payloads emitted by the Rust daemon (`gen_fixtures.rs`).
final class IntelligenceTests: XCTestCase {
    func testIntelligenceStatus() throws {
        let s = try Fixtures.decode(IntelligenceStatus.self, from: "intel_status.json")
        XCTAssertTrue(s.behavior.enabled)
        XCTAssertFalse(s.behavior.learning)
        XCTAssertEqual(s.behavior.learningProgress, 1.0, accuracy: 1e-9)
        XCTAssertEqual(s.behavior.profiles, 412)
        XCTAssertEqual(s.behavior.anomalies7d, 3)
        XCTAssertNotNil(s.behavior.learningUntilDate)
        let a = try XCTUnwrap(s.behavior.recentAnomalies.first)
        XCTAssertEqual(a.kind, .interpreter)
        XCTAssertEqual(a.alertId, 42)
        XCTAssertFalse(a.markedNormal)
        XCTAssertEqual(a.score, 0.9, accuracy: 1e-6)
        XCTAssertTrue(s.domains.dnsActive && s.domains.modelLoaded)
        XCTAssertFalse(s.domains.blockEnabled)
        XCTAssertEqual(s.domains.scored24h, 640)
        let f = try XCTUnwrap(s.domains.topFlagged.first)
        XCTAssertEqual(f.registrable, "secure-login.xyz")
        XCTAssertEqual(f.alertId, 41)
        XCTAssertEqual(f.hits, 3)
        XCTAssertEqual(s.models.map(\.id), ["domain", "behavior"])
        XCTAssertEqual(s.models[0].metrics["auc"] ?? 0, 0.995, accuracy: 1e-9)
        XCTAssertNil(s.models[1].version)
    }

    func testDefaultStatusAndVerdicts() throws {
        let s = try Fixtures.decode(IntelligenceStatus.self, from: "intel_status_default.json")
        XCTAssertTrue(s.behavior.recentAnomalies.isEmpty)
        XCTAssertNil(s.behavior.learningStartedAt)
        XCTAssertTrue(s.models.isEmpty)
        let v = try Fixtures.decode(DomainVerdictInfo.self, from: "domain_verdict.json")
        XCTAssertTrue(v.flagged)
        XCTAssertEqual(v.source, "model")
        XCTAssertEqual(v.reasons.count, 1)
        let skipped = try Fixtures.decode(DomainVerdictInfo.self, from: "domain_verdict_skipped.json")
        XCTAssertNil(skipped.score)
        XCTAssertEqual(skipped.skipped, "nom local")
    }

    func testConfigSectionAndClassification() throws {
        let config = try Fixtures.decode(Config.self, from: "config.json")
        XCTAssertTrue(config.intelligence.domainModel)
        XCTAssertFalse(config.intelligence.blockMlDomains)
        XCTAssertEqual(config.intelligence.learningDays, 7)
        XCTAssertEqual(config.intelligence.anomalyThreshold, 0.75, accuracy: 1e-6)
        XCTAssertTrue(config.validationErrors().isEmpty)
        var bad = config
        bad.intelligence.learningDays = 0
        bad.intelligence.domainAllowlist = ["Example.com"]
        XCTAssertEqual(bad.intelligence.validationErrors().count, 2)
        // Round trip keeps the section.
        let data = try JSONEncoder().encode(config)
        let back = try JSONDecoder().decode(Config.self, from: data)
        XCTAssertEqual(back.intelligence, config.intelligence)

        XCTAssertFalse(Request.intelStatus.isMutating)
        XCTAssertFalse(Request.intelScoreDomain(domain: "a.b").isMutating)
        XCTAssertTrue(Request.intelAllowDomain(domain: "a.b").requiresAdmin)
        XCTAssertTrue(Request.intelMarkNormal(anomalyId: "x").requiresAdmin)
        XCTAssertTrue(Request.intelResetBaseline.requiresAdmin)
        XCTAssertTrue(Request.resolveAlert(alertId: 1, action: .allowDomain).requiresAdmin)
        XCTAssertTrue(Request.resolveAlert(alertId: 1, action: .markNormal).requiresAdmin)
        XCTAssertEqual(AlertAction.markNormal.label, "C'est normal")
    }
}
