import Foundation
@testable import TrustRemediation
import XCTest

/// A transport that parks every fetch until the test opens it.
final class GatedTransport: ManifestTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var open = false
    private var envelope: SignedManifestEnvelope?
    private var failure: Error?

    init(envelope: SignedManifestEnvelope?) {
        self.envelope = envelope
    }

    var callCount: Int { lock.lock(); defer { lock.unlock() }; return calls }

    func serve(_ envelope: SignedManifestEnvelope?, failure: Error? = nil) {
        lock.lock(); defer { lock.unlock() }
        self.envelope = envelope
        self.failure = failure
    }

    func release() {
        lock.lock()
        open = true
        let pending = waiters
        waiters = []
        lock.unlock()
        pending.forEach { $0.resume() }
    }

    func fetchManifest() async throws -> SignedManifestEnvelope {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            calls += 1
            if open {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
        return try currentResult()
    }

    private func currentResult() throws -> SignedManifestEnvelope {
        lock.lock(); defer { lock.unlock() }
        if let failure { throw failure }
        guard let envelope else { throw TestError() }
        return envelope
    }
}

enum Wait {
    static func until(timeout: TimeInterval = 10, _ condition: () async -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while await !condition() {
            if Date() > deadline { return false }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return true
    }
}

final class CoordinatorTests: XCTestCase {
    private func makeCoordinator(_ transport: ManifestTransport, keys: Fixture.Keys,
                                 store: InMemoryLedgerPersistence = InMemoryLedgerPersistence(),
                                 clock: TestClock = TestClock(), build: String = "4.1.0") -> RemediationCoordinator {
        RemediationCoordinator(catalog: Fixture.catalog, build: Fixture.version(build), verifier: keys.verifier,
                               persistence: store, transport: transport, uptime: clock, wallClock: clock)
    }

    func testConcurrentRefreshesCoalesceIntoOneFetch() async throws {
        let keys = try Fixture.keys()
        let transport = GatedTransport(envelope: try keys.signer.sign(Fixture.manifest(version: 1)))
        let coordinator = makeCoordinator(transport, keys: keys)
        let outcomes = Task {
            await withTaskGroup(of: RefreshOutcome.self) { group in
                for _ in 0..<25 { group.addTask { await coordinator.refresh() } }
                return await group.reduce(into: [RefreshOutcome]()) { $0.append($1) }
            }
        }
        // Release only once every caller has entered `refresh()` (and so has joined).
        let allJoined = await Wait.until { await coordinator.refreshCalls == 25 }
        XCTAssertTrue(allJoined)
        transport.release()
        let results = await outcomes.value
        XCTAssertEqual(transport.callCount, 1, "one network fetch for 25 concurrent callers")
        let started = await coordinator.refreshesStarted
        XCTAssertEqual(started, 1)
        XCTAssertEqual(results.count, 25)
        XCTAssertTrue(results.allSatisfy { $0 == .accepted(.applied(version: 1, durable: true)) })
    }

    func testRefreshAfterCompletionFetchesAgain() async throws {
        let keys = try Fixture.keys()
        let transport = GatedTransport(envelope: try keys.signer.sign(Fixture.manifest(version: 1)))
        transport.release()
        let coordinator = makeCoordinator(transport, keys: keys)
        _ = await coordinator.refresh()
        transport.serve(try keys.signer.sign(Fixture.manifest(version: 2)))
        let second = await coordinator.refresh()
        XCTAssertEqual(second, .accepted(.applied(version: 2, durable: true)))
        XCTAssertEqual(transport.callCount, 2)
    }

    func testTransportFailureKeepsLastKnownGoodPolicy() async throws {
        let keys = try Fixture.keys()
        let restrictive = Fixture.manifest(version: 1, rules: [
            CapabilityRule(id: "r", capability: "partnerSync", action: .disable,
                           affectedBuilds: [Fixture.range(nil, "4.2.0")], reason: "CA"),
        ])
        let transport = GatedTransport(envelope: try keys.signer.sign(restrictive))
        transport.release()
        let coordinator = makeCoordinator(transport, keys: keys)
        _ = await coordinator.refresh()
        transport.serve(nil, failure: TestError())
        guard case .transportFailed = await coordinator.refresh() else { return XCTFail("expected failure") }
        let snapshot = await coordinator.snapshot()
        XCTAssertEqual(snapshot.decision(for: "partnerSync")?.state, .disabled)
    }

    func testLatchedDeadlineSurvivesRelaunchWithTheClockWoundBack() async throws {
        let keys = try Fixture.keys()
        let clock = TestClock()
        let store = InMemoryLedgerPersistence()
        let envelope = try keys.signer.sign(Fixture.manifest(version: 1, minimumVersion: MinimumVersionPolicy(
            required: Fixture.version("4.2.0"), requiredFrom: Fixture.t0.addingTimeInterval(3 * Fixture.day), reason: "")))
        let transport = GatedTransport(envelope: envelope)
        transport.release()
        _ = await makeCoordinator(transport, keys: keys, store: store, clock: clock).refresh()
        clock.reboot()
        let second = makeCoordinator(transport, keys: keys, store: store, clock: clock)
        let unchanged = await second.refresh()
        XCTAssertEqual(unchanged, .accepted(.unchanged(version: 1)), "no new anchor this session")
        clock.advance(4 * Fixture.day)
        var snapshot = await second.snapshot()
        XCTAssertEqual(snapshot.upgrade, .required(target: Fixture.version("4.2.0")))
        clock.reboot()
        clock.setWall(Fixture.t0.addingTimeInterval(Fixture.day))
        let third = makeCoordinator(transport, keys: keys, store: store, clock: clock)
        _ = await third.refresh()
        snapshot = await third.snapshot()
        XCTAssertEqual(snapshot.upgrade, .required(target: Fixture.version("4.2.0")))
        XCTAssertEqual(snapshot.decision(for: "partnerSync")?.state, .disabled)
    }

    func testSnapshotEndToEndAcrossTheEnforcementDeadline() async throws {
        let keys = try Fixture.keys()
        let clock = TestClock()
        let manifest = Fixture.manifest(version: 1, minimumVersion: MinimumVersionPolicy(
            recommended: Fixture.version("4.2.0"), required: Fixture.version("4.2.0"),
            requiredFrom: Fixture.t0.addingTimeInterval(3 * Fixture.day), reason: "CA"))
        let transport = GatedTransport(envelope: try keys.signer.sign(manifest))
        transport.release()
        let coordinator = makeCoordinator(transport, keys: keys, clock: clock)
        _ = await coordinator.refresh()
        var snapshot = await coordinator.snapshot()
        XCTAssertEqual(snapshot.decision(for: "partnerSync")?.state, .full)
        guard case .recommended = snapshot.upgrade else { return XCTFail("expected recommended") }

        clock.setWall(Fixture.t0.addingTimeInterval(-30 * Fixture.day)) // clock games don't delay it
        clock.advance(3 * Fixture.day)
        snapshot = await coordinator.snapshot()
        XCTAssertEqual(snapshot.upgrade, .required(target: Fixture.version("4.2.0")))
        XCTAssertEqual(snapshot.decision(for: "partnerSync")?.state, .disabled)
        XCTAssertEqual(snapshot.decision(for: "photoBackup")?.state, .full)
        XCTAssertEqual(snapshot.timeBasis, .signedAnchor)
    }

    func testIngestAppliesOutOfBandEnvelopes() async throws {
        let keys = try Fixture.keys()
        let coordinator = makeCoordinator(GatedTransport(envelope: nil), keys: keys)
        let outcome = await coordinator.ingest(try keys.signer.sign(Fixture.manifest(version: 4)))
        XCTAssertEqual(outcome, .applied(version: 4, durable: true))
        let floor = await coordinator.snapshot().versionFloor
        XCTAssertEqual(floor, 4)
    }
}
