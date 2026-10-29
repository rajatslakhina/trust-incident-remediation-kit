import Foundation
@testable import TrustRemediation
import XCTest

final class GateTests: XCTestCase {
    private func verified(_ manifest: SecurityManifest) throws -> VerifiedManifest {
        let keys = try Fixture.keys()
        return try keys.verifier.verify(keys.signer.sign(manifest)).get()
    }

    private func decisions(_ status: ManifestStatus, build: String = "4.1.0",
                           upgrade: UpgradeRequirement = .notNeeded) -> [String: GateDecision] {
        let result = CapabilityGate.evaluate(catalog: Fixture.catalog, build: Fixture.version(build),
                                             status: status, upgrade: upgrade)
        return Dictionary(uniqueKeysWithValues: result.decisions.map { ($0.capability, $0) })
    }

    func testNoManifestUsesCompiledInPostureByTrustPath() {
        let d = decisions(.absent)
        XCTAssertEqual(d["partnerSync"]?.state, .degraded, "embedded trust store: OS block can't reach it")
        XCTAssertEqual(d["partnerSync"]?.cause, .noVerifiedManifest)
        XCTAssertEqual(d["photoBackup"]?.state, .full)
    }

    func testRulesMatchOnlyAffectedBuilds() throws {
        let manifest = try verified(Fixture.manifest(version: 1, rules: [
            CapabilityRule(id: "ca-1", capability: "partnerSync", action: .disable,
                           affectedBuilds: [Fixture.range(nil, "4.2.0")], reason: "embedded root"),
        ]))
        XCTAssertEqual(decisions(.fresh(manifest), build: "4.1.9")["partnerSync"]?.state, .disabled)
        XCTAssertEqual(decisions(.fresh(manifest), build: "4.2.0")["partnerSync"]?.state, .full)
        XCTAssertEqual(decisions(.fresh(manifest), build: "4.2.0")["partnerSync"]?.cause, .noRestriction)
    }

    func testMostSevereRuleWinsWithDeterministicTieBreak() throws {
        let rules = [
            CapabilityRule(id: "b-degrade", capability: "partnerSync", action: .degrade, reason: "b"),
            CapabilityRule(id: "z-disable", capability: "partnerSync", action: .disable, reason: "z"),
            CapabilityRule(id: "a-disable", capability: "partnerSync", action: .disable, reason: "a"),
        ]
        let d = decisions(.fresh(try verified(Fixture.manifest(version: 1, rules: rules))))
        XCTAssertEqual(d["partnerSync"]?.cause, .rule(id: "a-disable", reason: "a"))
    }

    func testDecisionIsIndependentOfRuleOrderForEveryPermutation() throws {
        let rules = [
            CapabilityRule(id: "r3", capability: "partnerSync", action: .degrade, reason: ""),
            CapabilityRule(id: "r1", capability: "partnerSync", action: .disable,
                           affectedBuilds: [Fixture.range("5.0.0", nil)], reason: "not this build"),
            CapabilityRule(id: "r2", capability: "partnerSync", action: .disable,
                           affectedBuilds: [Fixture.range("4.0.0", "4.2.0")], reason: ""),
            CapabilityRule(id: "r0", capability: "partnerSync", action: .degrade, reason: ""),
        ]
        XCTAssertTrue(OrderIndependence.holds(for: rules, resolve: CapabilityGateResolvers.real))
    }

    func testStaleManifestNeverLoosensAndFallsBackForEmbeddedPaths() throws {
        let manifest = try verified(Fixture.manifest(version: 1, rules: [
            CapabilityRule(id: "r", capability: "photoBackup", action: .disable, reason: "x"),
        ]))
        let d = decisions(.stale(manifest))
        XCTAssertEqual(d["photoBackup"]?.state, .disabled, "rule still in force when stale")
        XCTAssertEqual(d["partnerSync"]?.state, .degraded)
        XCTAssertEqual(d["partnerSync"]?.cause, .staleManifest)
        XCTAssertEqual(decisions(.fresh(manifest))["partnerSync"]?.state, .full)
    }

    func testRequiredUpgradeDisablesOnlyBlockedCapabilities() throws {
        let manifest = try verified(Fixture.manifest(version: 1))
        let target = Fixture.version("4.2.0")
        let d = decisions(.fresh(manifest), upgrade: .required(target: target))
        XCTAssertEqual(d["partnerSync"]?.state, .disabled)
        XCTAssertEqual(d["partnerSync"]?.cause, .upgradeRequired(target: target))
        XCTAssertEqual(d["photoBackup"]?.state, .full, "local-first features keep working: don't brick")
        let soft = decisions(.fresh(manifest), upgrade: .recommended(target: target, enforcedFrom: nil))
        XCTAssertEqual(soft["partnerSync"]?.state, .full)
    }

    func testUnknownCapabilitiesAreReportedNotFatal() throws {
        let manifest = try verified(Fixture.manifest(version: 1, rules: [
            CapabilityRule(id: "future", capability: "notInThisBuild", action: .disable, reason: ""),
        ]))
        let result = CapabilityGate.evaluate(catalog: Fixture.catalog, build: Fixture.version("4.1.0"),
                                             status: .fresh(manifest), upgrade: .notNeeded)
        XCTAssertEqual(result.unknownCapabilityRuleIDs, ["future"])
        XCTAssertEqual(result.decisions.count, 2)
    }

    func testEmptyCatalogYieldsNoDecisions() throws {
        let empty = try XCTUnwrap(CapabilityCatalog([]))
        let result = CapabilityGate.evaluate(catalog: empty, build: Fixture.version("1"), status: .absent,
                                             upgrade: .notNeeded)
        XCTAssertTrue(result.decisions.isEmpty)
        XCTAssertNil(CapabilityCatalog([Fixture.catalog.capabilities[0], Fixture.catalog.capabilities[0]]))
    }

    func testStagedUpgradeEnforcement() {
        let policy = MinimumVersionPolicy(recommended: Fixture.version("4.1.5"), required: Fixture.version("4.2.0"),
                                          requiredFrom: Fixture.t0.addingTimeInterval(3 * Fixture.day), reason: "")
        let build = Fixture.version("4.1.0")
        XCTAssertEqual(UpgradeRequirement.evaluate(policy, build: build, trustedNow: Fixture.t0),
                       .recommended(target: Fixture.version("4.2.0"), enforcedFrom: policy.requiredFrom))
        XCTAssertEqual(UpgradeRequirement.evaluate(policy, build: build,
                                                   trustedNow: Fixture.t0.addingTimeInterval(3 * Fixture.day)),
                       .required(target: Fixture.version("4.2.0")), "deadline is inclusive")
        XCTAssertEqual(UpgradeRequirement.evaluate(policy, build: Fixture.version("4.1.7"), trustedNow: Fixture.t0),
                       .recommended(target: Fixture.version("4.2.0"), enforcedFrom: policy.requiredFrom))
        XCTAssertEqual(UpgradeRequirement.evaluate(policy, build: Fixture.version("4.2.0"), trustedNow: .distantFuture),
                       .notNeeded)
        let softOnly = MinimumVersionPolicy(recommended: Fixture.version("4.2.0"), reason: "")
        XCTAssertEqual(UpgradeRequirement.evaluate(softOnly, build: build, trustedNow: Fixture.t0),
                       .recommended(target: Fixture.version("4.2.0"), enforcedFrom: nil))
        XCTAssertEqual(UpgradeRequirement.evaluate(nil, build: build, trustedNow: Fixture.t0), .notNeeded)
    }
}

/// A resolver under test: given rules, return the decision for `partnerSync` on 4.1.0.
enum CapabilityGateResolvers {
    static let build = Fixture.version("4.1.0")

    static func descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor(id: "partnerSync", displayName: "", trustPath: .systemTrust)
    }

    static func real(_ rules: [CapabilityRule]) -> GateDecision {
        CapabilityGate.decide(descriptor(), build: build, rules: rules, status: .absent, upgrade: .notNeeded)
    }

    /// Deliberately broken: "first matching rule wins", the natural naive implementation.
    static func firstMatchWins(_ rules: [CapabilityRule]) -> GateDecision {
        guard let first = rules.first(where: { $0.capability == "partnerSync" && $0.applies(to: build) }) else {
            return GateDecision(capability: "partnerSync", state: .full, cause: .noRestriction)
        }
        return GateDecision(capability: "partnerSync", state: CapabilityState(first.action),
                            cause: .rule(id: first.id, reason: first.reason))
    }
}

/// Property: the decision is the same for every ordering of the manifest's rules.
enum OrderIndependence {
    static func holds(for rules: [CapabilityRule], resolve: ([CapabilityRule]) -> GateDecision) -> Bool {
        guard let first = rules.permutations().first else { return true }
        let expected = resolve(first)
        return rules.permutations().allSatisfy { resolve($0) == expected }
    }
}

extension Array {
    /// All orderings (Heap's algorithm). Callers keep arrays small (n! growth).
    func permutations() -> [[Element]] {
        guard count <= 7 else { return [self] }
        var result: [[Element]] = []
        var items = self
        func generate(_ k: Int) {
            if k <= 1 {
                result.append(items)
                return
            }
            generate(k - 1)
            for i in 0..<(k - 1) {
                items.swapAt(k % 2 == 0 ? i : 0, k - 1)
                generate(k - 1)
            }
        }
        generate(count)
        return result
    }
}

final class UpgradeStrictnessTests: XCTestCase {
    func testStrictestCombinesRequirements() {
        let v42 = Fixture.version("4.2.0"), v43 = Fixture.version("4.3.0")
        let early = Fixture.t0, late = Fixture.t0.addingTimeInterval(Fixture.day)
        XCTAssertEqual(UpgradeRequirement.strictest([]), .notNeeded)
        XCTAssertEqual(UpgradeRequirement.strictest([.notNeeded, .recommended(target: v42, enforcedFrom: late)]),
                       .recommended(target: v42, enforcedFrom: late))
        XCTAssertEqual(UpgradeRequirement.strictest([.recommended(target: v43, enforcedFrom: late),
                                                     .recommended(target: v42, enforcedFrom: early)]),
                       .recommended(target: v43, enforcedFrom: late), "a deadline stays with its own target")
        XCTAssertEqual(UpgradeRequirement.strictest([.recommended(target: v42, enforcedFrom: late),
                                                     .recommended(target: v42, enforcedFrom: early)]),
                       .recommended(target: v42, enforcedFrom: early))
        XCTAssertEqual(UpgradeRequirement.strictest([.recommended(target: v43, enforcedFrom: nil), .required(target: v42)]),
                       .required(target: v42))
        XCTAssertEqual(UpgradeRequirement.strictest([.required(target: v42), .required(target: v43)]),
                       .required(target: v43))
    }
}
