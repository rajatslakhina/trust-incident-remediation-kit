import Foundation
@testable import TrustRemediation
import XCTest

final class LedgerTests: XCTestCase {
    private var keys: Fixture.Keys!  // Set in setUpWithError before every test.
    private var store: InMemoryLedgerPersistence!  // Set in setUpWithError before every test.
    private let clock = TestClock()

    override func setUpWithError() throws {
        keys = try Fixture.keys()
        store = InMemoryLedgerPersistence()
    }

    private func ledger() -> ManifestLedger { ManifestLedger(verifier: keys.verifier, persistence: store) }

    private func accept(_ ledger: inout ManifestLedger, _ manifest: SecurityManifest) throws -> AcceptOutcome {
        ledger.accept(try keys.signer.sign(manifest), uptime: clock.uptime(), wallClock: clock.now())
    }

    func testNewerManifestAppliesAndPersistsFloorBeforeReturning() throws {
        var ledger = ledger()
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 4)), .applied(version: 4, durable: true))
        XCTAssertEqual(store.snapshot?.versionFloor, 4)
        XCTAssertEqual(ledger.current?.manifest.version, 4)
    }

    func testRollbackIsRejectedInMemoryAndAcrossRelaunch() throws {
        var first = ledger()
        let old = try keys.signer.sign(Fixture.manifest(version: 2))
        _ = first.accept(old, uptime: clock.uptime(), wallClock: clock.now())
        _ = try accept(&first, Fixture.manifest(version: 5))
        XCTAssertEqual(first.accept(old, uptime: clock.uptime(), wallClock: clock.now()),
                       .rejected(.rollback(offered: 2, floor: 5)))

        var relaunched = ledger()
        XCTAssertEqual(relaunched.versionFloor, 5)
        XCTAssertEqual(relaunched.current?.manifest.version, 5, "last known good restored")
        XCTAssertEqual(relaunched.accept(old, uptime: clock.uptime(), wallClock: clock.now()),
                       .rejected(.rollback(offered: 2, floor: 5)))
    }

    func testIdenticalRedeliveryIsUnchanged() throws {
        var ledger = ledger()
        let envelope = try keys.signer.sign(Fixture.manifest(version: 3))
        _ = ledger.accept(envelope, uptime: clock.uptime(), wallClock: clock.now())
        let saves = store.saveCount
        XCTAssertEqual(ledger.accept(envelope, uptime: clock.uptime(), wallClock: clock.now()), .unchanged(version: 3))
        XCTAssertEqual(store.saveCount, saves, "no write for a no-op")
    }

    func testEquivocationEnforcesTheUnionOfBothCopiesWhicheverArrivesFirst() throws {
        let strict = Fixture.manifest(version: 7, rules: [
            CapabilityRule(id: "r", capability: "partnerSync", action: .disable, reason: "CA"),
        ])
        let lax = Fixture.manifest(version: 7) // same version, no rules
        for order in [[strict, lax], [lax, strict]] {
            store = InMemoryLedgerPersistence()
            var ledger = ledger()
            XCTAssertEqual(try accept(&ledger, order[0]), .applied(version: 7, durable: true))
            XCTAssertEqual(try accept(&ledger, order[1]), .rejected(.equivocation(version: 7)))
            XCTAssertEqual(ledger.current?.manifest, order[0], "the second copy does not replace the first")
            XCTAssertEqual(ledger.effectiveRules.map(\.action), [.disable], "strict reading enforced either way")
            XCTAssertEqual(ledger.equivocatedVersions, [7])
            XCTAssertEqual(store.snapshot?.equivocatedVersions, [7], "persisted for incident response")

            let relaunched = self.ledger()
            XCTAssertEqual(relaunched.effectiveRules.map(\.action), [.disable], "fork survives relaunch")
        }
    }

    func testANewerVersionClearsEquivocationRestrictions() throws {
        var ledger = ledger()
        _ = try accept(&ledger, Fixture.manifest(version: 7))
        _ = try accept(&ledger, Fixture.manifest(version: 7, rules: [
            CapabilityRule(id: "r", capability: "partnerSync", action: .disable, reason: ""),
        ]))
        XCTAssertEqual(ledger.forks.count, 1)
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 8)), .applied(version: 8, durable: true))
        XCTAssertTrue(ledger.forks.isEmpty, "equivocation is reported, not a permanent lockout")
        XCTAssertTrue(ledger.effectiveRules.isEmpty)
    }

    func testForksAtOneVersionAreBounded() throws {
        var ledger = ledger()
        _ = try accept(&ledger, Fixture.manifest(version: 1))
        for hours in 1...10 {
            _ = try accept(&ledger, Fixture.manifest(version: 1, lifetime: TimeInterval(hours) * 3600))
        }
        XCTAssertEqual(ledger.forks.count, ManifestLedger.maxForksAtFloor)
    }

    func testEquivocationHistoryIsBounded() throws {
        var ledger = ledger()
        for version in UInt64(1)...40 {
            _ = try accept(&ledger, Fixture.manifest(version: version * 2, rules: []))
            _ = try accept(&ledger, Fixture.manifest(version: version * 2, lifetime: Fixture.day))
        }
        XCTAssertEqual(ledger.equivocatedVersions.count, ManifestLedger.maxRecordedEquivocations)
        XCTAssertEqual(ledger.equivocatedVersions.last, 80)
    }

    func testExpiryUsesSignedTimeNotTheWallClock() throws {
        var ledger = ledger()
        // A phone whose clock is a year fast can still accept a fresh manifest.
        clock.setWall(Fixture.t0.addingTimeInterval(365 * Fixture.day))
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 1)), .applied(version: 1, durable: true))
        XCTAssertEqual(ledger.trustedNow(uptime: clock.uptime(), wallClock: clock.now()).date, Fixture.t0,
                       "anchored to signed issuedAt, not the fast wall clock")

        // Once anchored, signed time + uptime decides expiry.
        clock.advance(10 * Fixture.day)
        let expiredOnArrival = Fixture.manifest(version: 2, issuedAt: Fixture.t0, lifetime: 7 * Fixture.day)
        XCTAssertEqual(try accept(&ledger, expiredOnArrival), .rejected(.expired(version: 2)))
    }

    func testUnanchoredExpiryFallsBackToTheHighWaterMark() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 1, issuedAt: Fixture.t0.addingTimeInterval(20 * Fixture.day)))
        // Relaunch after reboot: no anchor, but the persisted high-water says day 20.
        clock.reboot()
        clock.setWall(Fixture.t0) // and the wall clock was set back
        var relaunched = ledger()
        let stale = Fixture.manifest(version: 2, issuedAt: Fixture.t0, lifetime: 7 * Fixture.day)
        XCTAssertEqual(try accept(&relaunched, stale), .rejected(.expired(version: 2)))
    }

    func testStaleManifestKeepsItsRestrictions() throws {
        var ledger = ledger()
        _ = try accept(&ledger, Fixture.manifest(version: 1, lifetime: 2 * Fixture.day))
        XCTAssertEqual(ledger.status(uptime: clock.uptime(), wallClock: clock.now()).isFresh, true)
        clock.advance(3 * Fixture.day)
        let status = ledger.status(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertEqual(status.isFresh, false)
        XCTAssertEqual(status.manifest?.manifest.version, 1, "stale is not dropped")
    }

    func testWallClockRollbackCannotUnstaleWhileAnchored() throws {
        var ledger = ledger()
        _ = try accept(&ledger, Fixture.manifest(version: 1, lifetime: 2 * Fixture.day))
        clock.advance(3 * Fixture.day)
        clock.setWall(Fixture.t0) // user winds the clock back three days
        XCTAssertEqual(ledger.status(uptime: clock.uptime(), wallClock: clock.now()).isFresh, false)
    }

    func testWallClockRollbackAfterRebootIsFlooredAtHighWater() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 1, lifetime: 2 * Fixture.day))
        clock.advance(3 * Fixture.day)
        first.noteTime(uptime: clock.uptime(), wallClock: clock.now()) // high-water = day 3, persisted
        clock.reboot()
        clock.setWall(Fixture.t0) // back to day 0
        let relaunched = ledger()
        let now = relaunched.trustedNow(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertEqual(now.basis, .flooredWallClock)
        XCTAssertEqual(now.date, Fixture.t0.addingTimeInterval(3 * Fixture.day))
        XCTAssertEqual(relaunched.status(uptime: clock.uptime(), wallClock: clock.now()).isFresh, false)
    }

    func testFastWallClockIsNeverPersistedAsHighWater() throws {
        var ledger = ledger()
        clock.setWall(Fixture.t0.addingTimeInterval(365 * Fixture.day))
        ledger.noteTime(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertNil(store.snapshot?.timeHighWater, "unanchored wall time must not become a floor")
        XCTAssertNil(ledger.timeline.highWater)
    }

    func testHighWaterWritesAreThrottled() throws {
        var ledger = ledger()
        _ = try accept(&ledger, Fixture.manifest(version: 1))
        let base = store.saveCount
        for _ in 0..<50 {
            clock.advance(60)
            ledger.noteTime(uptime: clock.uptime(), wallClock: clock.now())
        }
        XCTAssertEqual(store.saveCount, base, "50 minutes of reads: no high-water write yet")
        clock.advance(ManifestLedger.highWaterPersistInterval)
        ledger.noteTime(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertEqual(store.saveCount, base + 1)
    }

    func testUnreadableStorageIsNeverOverwritten() throws {
        let original = PersistedLedgerState(versionFloor: 9, floorDigest: Data([1]), lastKnownGood: nil,
                                            timeHighWater: nil, equivocatedVersions: [])
        store = InMemoryLedgerPersistence(initial: original)
        store.failLoads(with: TestError())
        var ledger = ledger()
        XCTAssertEqual(ledger.storage, .unreadable(String(describing: TestError())))
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 1)), .restrictionsOnly(version: 1),
                       "with no readable floor, a manifest can only add restrictions")
        store.failLoads(with: nil)
        XCTAssertEqual(store.snapshot, original, "floor v9 survived")
        XCTAssertEqual(store.saveCount, 0)
    }

    func testWriteFailureStillAppliesAndHealsOnNextWrite() throws {
        var ledger = ledger()
        store.failSaves(with: TestError())
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 1)), .applied(version: 1, durable: false))
        XCTAssertEqual(ledger.current?.manifest.version, 1)
        guard case .writeFailing = ledger.storage else { return XCTFail("expected writeFailing") }
        store.failSaves(with: nil)
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 2)), .applied(version: 2, durable: true))
        XCTAssertEqual(ledger.storage, .healthy)
        XCTAssertEqual(store.snapshot?.versionFloor, 2)
    }

    func testRotatedOutKeyKeepsRestrictionsButNotTrust() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 6, rules: [
            CapabilityRule(id: "r", capability: "partnerSync", action: .disable, reason: ""),
        ]))
        // The next app version pins only a new key.
        let newKeys = try Fixture.keys(id: "k2")
        var relaunched = ManifestLedger(verifier: newKeys.verifier, persistence: store)
        XCTAssertNil(relaunched.current, "not verifiable any more, so not treated as current")
        XCTAssertEqual(relaunched.discardedOnLoad, .unknownKey("k1"))
        XCTAssertEqual(relaunched.versionFloor, 6)
        XCTAssertEqual(relaunched.effectiveRules.map(\.id), ["retained/r"], "an OFF switch stays off")

        // A newer manifest under the new key replaces the retained restrictions.
        let next = try newKeys.signer.sign(Fixture.manifest(version: 7, keyID: "k2"))
        XCTAssertEqual(relaunched.accept(next, uptime: clock.uptime(), wallClock: clock.now()),
                       .applied(version: 7, durable: true))
        XCTAssertTrue(relaunched.effectiveRules.isEmpty)
    }

    private static let disableSync = [CapabilityRule(id: "r", capability: "partnerSync", action: .disable, reason: "")]

    func testRaisedCompiledInFloorKeepsStoredRestrictions() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 3, rules: Self.disableSync))
        let bumped = TrustFloor(earliestTrustedTime: nil, minimumManifestVersion: 10)
        var relaunched = ManifestLedger(verifier: keys.verifier, persistence: store, floor: bumped)
        XCTAssertNil(relaunched.current)
        XCTAssertEqual(relaunched.effectiveRules.map(\.id), ["retained/r"], "an app update must not reopen a switch")
        XCTAssertEqual(try accept(&relaunched, Fixture.manifest(version: 9)), .rejected(.rollback(offered: 9, floor: 10)))
    }

    func testRetainedRestrictionsArePersistedAndSurviveTheNextRelaunch() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 6, rules: Self.disableSync))
        // New binary pins only k2: v6 becomes retained, current is nil, floorDigest is set.
        let k2 = try Fixture.keys(id: "k2")
        var second = ManifestLedger(verifier: k2.verifier, persistence: store)
        XCTAssertNil(second.current)
        // A k2-signed v6 with other content is an equivocation; this forces a write
        // while `current == nil` and `retained` is non-empty.
        let fork = try k2.signer.sign(Fixture.manifest(version: 6, keyID: "k2", rules: [
            CapabilityRule(id: "f", capability: "photoBackup", action: .degrade, reason: ""),
        ]))
        XCTAssertEqual(second.accept(fork, uptime: clock.uptime(), wallClock: clock.now()),
                       .rejected(.equivocation(version: 6)))
        XCTAssertEqual(Set(second.effectiveRules.map(\.id)), ["retained/r", "retained/f"],
                       "an equivocating copy with nothing applied is kept as restrictions")
        XCTAssertEqual(store.snapshot?.retainedRestrictions?.count, 2, "written to disk")
        XCTAssertNil(store.snapshot?.lastKnownGood)

        let third = ManifestLedger(verifier: k2.verifier, persistence: store)
        XCTAssertEqual(Set(third.effectiveRules.map(\.id)), ["retained/r", "retained/f"])
    }

    func testUnreadableStorageCannotBeUsedToLiftRestrictions() throws {
        store = InMemoryLedgerPersistence()
        store.failLoads(with: TestError())
        var ledger = ledger()
        // A replayed, validly signed, unexpired all-clear...
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 1)), .restrictionsOnly(version: 1))
        XCTAssertEqual(ledger.status(uptime: clock.uptime(), wallClock: clock.now()), .absent,
                       "...does not become current, so the fallback posture stays")
        // ...while a restricting manifest still takes effect.
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 2, rules: Self.disableSync)),
                       .restrictionsOnly(version: 2))
        XCTAssertEqual(ledger.effectiveRules.map(\.id), ["retained/r"])
    }

    func testImplausibleVersionJumpIsRejected() throws {
        var ledger = ledger()
        _ = try accept(&ledger, Fixture.manifest(version: 5))
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: UInt64.max)),
                       .rejected(.implausibleVersionJump(offered: UInt64.max, floor: 5)))
        XCTAssertEqual(try accept(&ledger, Fixture.manifest(version: 5 + ManifestLedger.maxVersionStep)),
                       .applied(version: 5 + ManifestLedger.maxVersionStep, durable: true), "the boundary is inclusive")
        XCTAssertEqual(ledger.versionFloor, 5 + ManifestLedger.maxVersionStep)
    }

    func testCrossedDeadlineIsLatchedAcrossRelaunchWithoutANewAnchor() throws {
        let policy = MinimumVersionPolicy(required: Fixture.version("9"),
                                          requiredFrom: Fixture.t0.addingTimeInterval(3 * Fixture.day), reason: "")
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 1, minimumVersion: policy))
        // Relaunch: no anchor this boot. Time passes on the (floored) wall clock only.
        clock.reboot()
        var second = ledger()
        clock.advance(4 * Fixture.day)
        second.noteTime(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertTrue(second.hasCrossed(policy.requiredFrom ?? .distantFuture))
        // Relaunch again with the wall clock wound back to day 1.
        clock.reboot()
        clock.setWall(Fixture.t0.addingTimeInterval(Fixture.day))
        let third = ledger()
        XCTAssertTrue(third.hasCrossed(policy.requiredFrom ?? .distantFuture), "the latch survived on disk")
    }

    func testTighterLimitsInANewBinaryKeepStoredRestrictions() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 3, rules: Self.disableSync + [
            CapabilityRule(id: "r2", capability: "photoBackup", action: .degrade, reason: ""),
        ]))
        let strict = try Fixture.keys(limits: .init(maxRules: 1))
        let relaunched = ManifestLedger(
            verifier: ManifestVerifier(trustedKeys: keys.verifier.trustedKeys, limits: strict.verifier.limits),
            persistence: store)
        XCTAssertEqual(relaunched.discardedOnLoad, .tooManyRules(2))
        XCTAssertEqual(relaunched.effectiveRules.count, 2)
    }

    func testKeyRotationKeepsEquivocatingCopiesRestrictions() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 6))
        _ = try accept(&first, Fixture.manifest(version: 6, rules: Self.disableSync)) // fork
        XCTAssertEqual(first.effectiveRules.map(\.id), ["fork@v6/r"])
        let relaunched = ManifestLedger(verifier: try Fixture.keys(id: "k2").verifier, persistence: store)
        XCTAssertEqual(relaunched.effectiveRules.map(\.action), [.disable])
    }

    func testFreshInstallRejectsAnOldManifestBelowTheCompiledInFloor() throws {
        // No storage at all, so no rollback floor; a replay of last year's manifest
        // must still not read as fresh.
        let floor = TrustFloor(earliestTrustedTime: Fixture.t0)
        var fresh = ManifestLedger(verifier: keys.verifier, persistence: store, floor: floor)
        let lastYear = Fixture.manifest(version: 1, issuedAt: Fixture.t0.addingTimeInterval(-365 * Fixture.day))
        XCTAssertEqual(try accept(&fresh, lastYear), .rejected(.expired(version: 1)))
        XCTAssertNil(fresh.current)
        XCTAssertEqual(try accept(&fresh, Fixture.manifest(version: 2)), .applied(version: 2, durable: true))
    }

    func testCompiledInVersionFloorOverridesOlderStorage() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 3))
        var relaunched = ManifestLedger(verifier: keys.verifier, persistence: store,
                                        floor: TrustFloor(earliestTrustedTime: nil, minimumManifestVersion: 10))
        XCTAssertNil(relaunched.current, "stored v3 is older than the binary's floor")
        XCTAssertEqual(try accept(&relaunched, Fixture.manifest(version: 9)), .rejected(.rollback(offered: 9, floor: 10)))
        XCTAssertEqual(try accept(&relaunched, Fixture.manifest(version: 10)), .applied(version: 10, durable: true))
    }

    func testCrossingADeadlinePersistsTheHighWaterImmediately() throws {
        var ledger = ledger()
        // The deadline here is the manifest's own expiry (no version policy, so the
        // separate requiredFrom latch can't be what triggers the write).
        _ = try accept(&ledger, Fixture.manifest(version: 1, lifetime: 1800))
        let base = store.saveCount
        clock.advance(1700)
        ledger.noteTime(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertEqual(store.saveCount, base, "before the deadline: throttled")
        clock.advance(200) // crosses expiresAt, still < 1 hour since the last write
        ledger.noteTime(uptime: clock.uptime(), wallClock: clock.now())
        XCTAssertEqual(store.saveCount, base + 1, "deadline crossed: written now, so a relaunch can't step back")
    }

    func testDroppedStoredManifestIsReadoptedWhenTheSameBytesArrive() throws {
        var first = ledger()
        let envelope = try keys.signer.sign(Fixture.manifest(version: 6))
        _ = first.accept(envelope, uptime: clock.uptime(), wallClock: clock.now())
        var state = try XCTUnwrap(store.snapshot)
        state.lastKnownGood = nil // e.g. partially restored backup
        store = InMemoryLedgerPersistence(initial: state)
        var relaunched = ledger()
        XCTAssertNil(relaunched.current)
        XCTAssertEqual(relaunched.accept(envelope, uptime: clock.uptime(), wallClock: clock.now()),
                       .applied(version: 6, durable: true))
        XCTAssertEqual(relaunched.current?.manifest.version, 6)
    }

    func testStoredManifestThatDoesNotMatchTheFloorIsDiscarded() throws {
        var first = ledger()
        _ = try accept(&first, Fixture.manifest(version: 6))
        var state = try XCTUnwrap(store.snapshot)
        // Disk now holds a validly signed but *older* envelope next to floor v6.
        state.lastKnownGood = try keys.signer.sign(Fixture.manifest(version: 2))
        store = InMemoryLedgerPersistence(initial: state)
        let relaunched = ledger()
        XCTAssertNil(relaunched.current)
        XCTAssertEqual(relaunched.versionFloor, 6)
    }

    func testFileStorageRoundTripsAndTreatsCorruptionAsUnreadable() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("ledger.json")
        let file = FileLedgerPersistence(url: url)
        XCTAssertNil(try file.load())
        var ledger = ManifestLedger(verifier: keys.verifier, persistence: file)
        _ = ledger.accept(try keys.signer.sign(Fixture.manifest(version: 3)), uptime: 1, wallClock: Fixture.t0)
        XCTAssertEqual(try file.load()?.versionFloor, 3)

        try Data("{ truncated".utf8).write(to: url)
        let corrupted = ManifestLedger(verifier: keys.verifier, persistence: file)
        guard case .unreadable = corrupted.storage else { return XCTFail("corrupt file must be unreadable") }
        XCTAssertEqual(corrupted.versionFloor, 0)
    }
}

extension ManifestStatus {
    var isFresh: Bool? {
        switch self {
        case .absent: return nil
        case .fresh: return true
        case .stale: return false
        }
    }
}
