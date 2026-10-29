import Foundation
@testable import TrustRemediation
import XCTest

/// Every property the README claims is checked by a reusable check, and each check is
/// shown to *fail* against a deliberately broken implementation. A check that passes
/// against broken code is not evidence of anything.
final class MutationTests: XCTestCase {
    // MARK: Order independence of rule resolution

    func testOrderIndependenceCheckCatchesFirstMatchWins() {
        let rules = [
            CapabilityRule(id: "r1", capability: "partnerSync", action: .degrade, reason: ""),
            CapabilityRule(id: "r2", capability: "partnerSync", action: .disable, reason: ""),
        ]
        XCTAssertTrue(OrderIndependence.holds(for: rules, resolve: CapabilityGateResolvers.real))
        XCTAssertFalse(OrderIndependence.holds(for: rules, resolve: CapabilityGateResolvers.firstMatchWins))
    }

    // MARK: Anti-rollback

    /// Property: after a newer manifest is applied, a validly signed older one is not.
    static func rejectsRollback(signer: ManifestSigner, apply: (SignedManifestEnvelope) -> Bool) throws -> Bool {
        let old = try signer.sign(Fixture.manifest(version: 1))
        let new = try signer.sign(Fixture.manifest(version: 2))
        guard apply(old), apply(new) else { return false }
        return !apply(old)
    }

    func testRollbackCheckCatchesSignatureOnlyAcceptance() throws {
        let keys = try Fixture.keys()
        var ledger = ManifestLedger(verifier: keys.verifier, persistence: InMemoryLedgerPersistence())
        XCTAssertTrue(try Self.rejectsRollback(signer: keys.signer) { envelope in
            if case .applied = ledger.accept(envelope, uptime: 1, wallClock: Fixture.t0) { return true }
            return false
        })
        // Broken: checks the signature, forgets the floor.
        XCTAssertFalse(try Self.rejectsRollback(signer: keys.signer) { envelope in
            (try? keys.verifier.verify(envelope).get()) != nil
        })
    }

    // MARK: Wall-clock rollback after reboot

    /// Property: after a reboot, winding the wall clock back can't put trusted time
    /// before the last signed-anchored time that was persisted.
    static func wallClockRollbackIsFloored(now: (TrustedTimeline, TimeInterval, Date) -> Date) -> Bool {
        var timeline = TrustedTimeline()
        timeline.anchor(toSigned: Fixture.t0, uptime: 100, wallClock: Fixture.t0)
        _ = timeline.advanceHighWater(uptime: 100 + 5 * Fixture.day, wallClock: Fixture.t0)
        let rebooted = TrustedTimeline(highWater: timeline.highWater)
        let observed = now(rebooted, 10, Fixture.t0.addingTimeInterval(-40 * Fixture.day))
        return observed >= Fixture.t0.addingTimeInterval(5 * Fixture.day)
    }

    func testClockFloorCheckCatchesATimelineThatTrustsTheWallClock() {
        XCTAssertTrue(Self.wallClockRollbackIsFloored { timeline, uptime, wall in
            timeline.now(uptime: uptime, wallClock: wall).date
        })
        XCTAssertFalse(Self.wallClockRollbackIsFloored { _, _, wall in wall })
    }

    // MARK: Single-flight

    /// Property: N concurrent refreshes cause exactly one fetch.
    static func coalesces(callers: Int, transport: GatedTransport,
                          arrived: @escaping @Sendable () async -> Int,
                          refresh: @escaping @Sendable () async -> Void) async -> Bool {
        let group = Task {
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<callers { group.addTask { await refresh() } }
            }
        }
        // Release only when every caller has arrived, so the result can't depend on timing.
        _ = await Wait.until { await arrived() >= callers }
        transport.release()
        await group.value
        return transport.callCount == 1
    }

    func testSingleFlightCheckCatchesAPassThroughRefresher() async throws {
        let keys = try Fixture.keys()
        let envelope = try keys.signer.sign(Fixture.manifest(version: 1))

        let realTransport = GatedTransport(envelope: envelope)
        let clock = TestClock()
        let coordinator = RemediationCoordinator(
            catalog: Fixture.catalog, build: Fixture.version("4.1.0"), verifier: keys.verifier,
            persistence: InMemoryLedgerPersistence(), transport: realTransport, uptime: clock, wallClock: clock)
        let realHolds = await Self.coalesces(callers: 10, transport: realTransport,
                                             arrived: { await coordinator.refreshCalls }) {
            _ = await coordinator.refresh()
        }
        XCTAssertTrue(realHolds)

        // Broken: every caller goes straight to the network.
        let brokenTransport = GatedTransport(envelope: envelope)
        let brokenHolds = await Self.coalesces(callers: 10, transport: brokenTransport,
                                               arrived: { brokenTransport.callCount }) {
            _ = try? await brokenTransport.fetchManifest()
        }
        XCTAssertFalse(brokenHolds)
    }

    // MARK: Equivocation

    /// Property: whichever of two same-version copies arrives first, the stricter
    /// reading is enforced afterwards.
    static func enforcesStricterCopy(signer: ManifestSigner,
                                     makeSubject: () -> (apply: (SignedManifestEnvelope) -> Void,
                                                         disablesPartnerSync: () -> Bool)) throws -> Bool {
        let strict = try signer.sign(Fixture.manifest(version: 5, rules: [
            CapabilityRule(id: "r", capability: "partnerSync", action: .disable, reason: ""),
        ]))
        let lax = try signer.sign(Fixture.manifest(version: 5))
        for order in [[strict, lax], [lax, strict]] {
            let subject = makeSubject()
            order.forEach(subject.apply)
            if !subject.disablesPartnerSync() { return false }
        }
        return true
    }

    func testEquivocationCheckCatchesFirstSeenWins() throws {
        let keys = try Fixture.keys()
        XCTAssertTrue(try Self.enforcesStricterCopy(signer: keys.signer) {
            final class Box { var ledger: ManifestLedger; init(_ l: ManifestLedger) { ledger = l } }
            let box = Box(ManifestLedger(verifier: keys.verifier, persistence: InMemoryLedgerPersistence()))
            return ({ _ = box.ledger.accept($0, uptime: 1, wallClock: Fixture.t0) },
                    { box.ledger.effectiveRules.contains { $0.capability == "partnerSync" && $0.action == .disable } })
        })
        // Broken: first verified copy at a version wins; later copies are ignored.
        XCTAssertFalse(try Self.enforcesStricterCopy(signer: keys.signer) {
            final class Box { var rules: [CapabilityRule]? }
            let box = Box()
            return ({ envelope in
                if box.rules == nil, let verified = try? keys.verifier.verify(envelope).get() {
                    box.rules = verified.manifest.rules
                }
            }, { box.rules?.contains { $0.action == .disable } ?? false })
        })
    }
}
