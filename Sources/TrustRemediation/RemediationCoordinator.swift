import Foundation

/// Fetches the current signed manifest. The transport is untrusted by design: it may
/// run over the very TLS path the incident compromised, which is why nothing it
/// returns is used until the signature verifies.
public protocol ManifestTransport: Sendable {
    func fetchManifest() async throws -> SignedManifestEnvelope
}

public enum RefreshOutcome: Equatable, Sendable {
    case accepted(AcceptOutcome)
    case transportFailed(String)
}

/// Everything the app (and its UI) needs to enforce policy right now.
public struct RemediationSnapshot: Equatable, Sendable {
    public let build: BuildVersion
    public let status: ManifestStatus
    public let trustedNow: Date
    public let timeBasis: TimeBasis
    public let upgrade: UpgradeRequirement
    public let decisions: [GateDecision]
    public let unknownCapabilityRuleIDs: [String]
    public let versionFloor: UInt64
    public let equivocatedVersions: [UInt64]
    public let storage: StorageHealth
    /// How many stored manifests this binary can't treat as current still
    /// contribute restrictions (kept until a newer manifest is applied).
    public let retainedRestrictionCount: Int

    public func decision(for capability: String) -> GateDecision? {
        decisions.first { $0.capability == capability }
    }
}

/// Owns the ledger, serialises access to it, and coalesces refreshes.
///
/// Reentrancy: the only suspension point is the network fetch. Everything that reads
/// and then writes the ledger (`accept`) runs synchronously after the fetch returns,
/// inside one actor turn, so interleaved refreshes can't both pass the rollback check.
public actor RemediationCoordinator {
    public let catalog: CapabilityCatalog
    public let build: BuildVersion
    private var ledger: ManifestLedger
    private let transport: ManifestTransport
    private let uptime: UptimeSource
    private let wallClock: WallClock
    private var inFlight: Task<RefreshOutcome, Never>?
    public private(set) var refreshesStarted = 0
    /// Every call to `refresh()`, including ones that joined an in-flight fetch.
    public private(set) var refreshCalls = 0

    public init(catalog: CapabilityCatalog, build: BuildVersion, verifier: ManifestVerifier,
                persistence: LedgerPersistence, transport: ManifestTransport,
                floor: TrustFloor = .none,
                uptime: UptimeSource = SystemUptime(), wallClock: WallClock = SystemWallClock()) {
        self.catalog = catalog
        self.build = build
        self.ledger = ManifestLedger(verifier: verifier, persistence: persistence, floor: floor)
        self.transport = transport
        self.uptime = uptime
        self.wallClock = wallClock
    }

    /// Single-flight: callers that arrive while a fetch is running join it instead of
    /// starting another. A fleet-wide incident push wakes every app at once; without
    /// coalescing, each foreground/background trigger would multiply origin load.
    public func refresh() async -> RefreshOutcome {
        refreshCalls = Saturating.add(refreshCalls, 1)
        if let inFlight { return await inFlight.value }
        refreshesStarted = Saturating.add(refreshesStarted, 1)
        let task = Task { await self.performRefresh() }
        inFlight = task
        return await task.value
    }

    private func performRefresh() async -> RefreshOutcome {
        let result: Result<SignedManifestEnvelope, Error>
        do {
            result = .success(try await transport.fetchManifest())
        } catch {
            result = .failure(error)
        }
        // Back on the actor. From here to the return there is no `await`, so the
        // check-and-commit in `accept` is atomic with respect to other callers.
        inFlight = nil
        switch result {
        case .failure(let error):
            return .transportFailed(String(describing: error))
        case .success(let envelope):
            let outcome = ledger.accept(envelope, uptime: uptime.uptime(), wallClock: wallClock.now())
            return .accepted(outcome)
        }
    }

    /// Accepts an envelope that arrived another way (silent push, bundled fallback).
    public func ingest(_ envelope: SignedManifestEnvelope) -> AcceptOutcome {
        ledger.accept(envelope, uptime: uptime.uptime(), wallClock: wallClock.now())
    }

    public func snapshot() -> RemediationSnapshot {
        let up = uptime.uptime()
        let wall = wallClock.now()
        ledger.noteTime(uptime: up, wallClock: wall)
        let now = ledger.trustedNow(uptime: up, wallClock: wall)
        let status = ledger.status(uptime: up, wallClock: wall)
        let upgrade = UpgradeRequirement.strictest(ledger.effectiveVersionPolicies.map { policy in
            // A latched deadline stays crossed even if the clock was wound back since.
            var effectiveNow = now.date
            if let deadline = policy.requiredFrom, ledger.hasCrossed(deadline) {
                effectiveNow = max(effectiveNow, deadline)
            }
            return UpgradeRequirement.evaluate(policy, build: build, trustedNow: effectiveNow)
        })
        let gate = CapabilityGate.evaluate(catalog: catalog, build: build, status: status,
                                           upgrade: upgrade, rules: ledger.effectiveRules)
        return RemediationSnapshot(
            build: build, status: status, trustedNow: now.date, timeBasis: now.basis,
            upgrade: upgrade, decisions: gate.decisions,
            unknownCapabilityRuleIDs: gate.unknownCapabilityRuleIDs,
            versionFloor: ledger.versionFloor, equivocatedVersions: ledger.equivocatedVersions,
            storage: ledger.storage,
            retainedRestrictionCount: ledger.retained.count)
    }
}
