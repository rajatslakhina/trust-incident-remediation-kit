import Foundation

/// What the ledger keeps on disk between launches.
public struct PersistedLedgerState: Codable, Sendable, Equatable {
    /// Highest manifest version ever accepted. Never decreases.
    public var versionFloor: UInt64
    /// Digest of the manifest accepted at `versionFloor`.
    public var floorDigest: Data?
    /// The last known good envelope, re-verified on every load.
    public var lastKnownGood: SignedManifestEnvelope?
    /// Highest signed-anchored time ever observed (see `TrustedTimeline`).
    public var timeHighWater: Date?
    /// Versions at which two different signed payloads were seen. Bounded.
    public var equivocatedVersions: [UInt64]
    /// Other validly signed payloads seen at `versionFloor`. Their restrictions are
    /// enforced alongside the floor manifest's. Optional for forward compatibility.
    public var forksAtFloor: [SignedManifestEnvelope]?
    /// Stored manifests this binary can no longer treat as current (retired key,
    /// tighter limits, newer schema, below the compiled-in floor) whose restrictions
    /// are still being enforced until a newer manifest is applied.
    public var retainedRestrictions: [SignedManifestEnvelope]?
    /// Hard-enforcement deadlines (`requiredFrom`) trusted time has already passed.
    /// A restrict-only latch, so a relaunch with the wall clock wound back can't step
    /// back over a deadline even when no new signed anchor arrived since.
    public var crossedDeadlines: [Date]?

    public static let empty = PersistedLedgerState(
        versionFloor: 0, floorDigest: nil, lastKnownGood: nil,
        timeHighWater: nil, equivocatedVersions: [], forksAtFloor: nil)

    public init(versionFloor: UInt64, floorDigest: Data?, lastKnownGood: SignedManifestEnvelope?,
                timeHighWater: Date?, equivocatedVersions: [UInt64],
                forksAtFloor: [SignedManifestEnvelope]? = nil) {
        self.versionFloor = versionFloor
        self.floorDigest = floorDigest
        self.lastKnownGood = lastKnownGood
        self.timeHighWater = timeHighWater
        self.equivocatedVersions = equivocatedVersions
        self.forksAtFloor = forksAtFloor
        self.retainedRestrictions = nil
        self.crossedDeadlines = nil
    }
}

/// Synchronous on purpose: the ledger checks the floor and commits the new one with
/// no suspension point in between, so two concurrent fetches can never both pass the
/// rollback check against the same old floor (actor reentrancy).
public protocol LedgerPersistence: Sendable {
    /// `nil` when nothing was ever written. Throws when something exists but can't be read.
    func load() throws -> PersistedLedgerState?
    func save(_ state: PersistedLedgerState) throws
}

public enum StorageHealth: Equatable, Sendable {
    case healthy
    /// The stored state exists but could not be read. The ledger runs in memory and
    /// never writes, because overwriting state it could not read would erase the
    /// rollback floor it exists to protect.
    case unreadable(String)
    /// Writes are failing. Accepted manifests still apply in memory.
    case writeFailing(String)
}

public enum RejectionReason: Equatable, Sendable {
    case verification(VerificationFailure)
    case rollback(offered: UInt64, floor: UInt64)
    /// Same version, different signed bytes: the signing pipeline is compromised or
    /// broken. The new copy does not replace the applied one; instead the *union* of
    /// both copies' restrictions is enforced from now on, so whichever copy arrived
    /// first, the stricter reading wins.
    case equivocation(version: UInt64)
    case expired(version: UInt64)
    /// The version jumped further past the floor than `ManifestLedger.maxVersionStep`.
    /// One manifest at `UInt64.max` would otherwise freeze the floor for good, so no
    /// later manifest (even under a rotated key) could ever restrict again.
    case implausibleVersionJump(offered: UInt64, floor: UInt64)
}

public enum AcceptOutcome: Equatable, Sendable {
    /// `durable == false` means the manifest applies now but the floor didn't reach
    /// disk. Availability of a security fix beats durability; the next successful
    /// write catches up.
    case applied(version: UInt64, durable: Bool)
    case unchanged(version: UInt64)
    /// Storage is unreadable, so there is no rollback floor to check against. The
    /// manifest verified, but it is enforced only as *extra restrictions* on top of
    /// the compiled-in fallback posture: without a floor, a replayed older all-clear
    /// must not be able to lift anything.
    case restrictionsOnly(version: UInt64)
    case rejected(RejectionReason)
}

/// Compiled into each release: the binary refuses to trust anything older than the
/// moment it was built. Without this, a fresh install (or wiped storage) has no
/// floor at all, and a network attacker could serve a validly signed manifest from a
/// year ago and have it read as fresh.
public struct TrustFloor: Sendable, Equatable {
    /// Typically the build date. Seeds the trusted-time high-water mark.
    public let earliestTrustedTime: Date?
    /// Typically the manifest version current when the binary was cut.
    public let minimumManifestVersion: UInt64

    public init(earliestTrustedTime: Date?, minimumManifestVersion: UInt64 = 0) {
        self.earliestTrustedTime = earliestTrustedTime
        self.minimumManifestVersion = minimumManifestVersion
    }

    public static let none = TrustFloor(earliestTrustedTime: nil)
}

public enum ManifestStatus: Equatable, Sendable {
    /// No verified manifest: never fetched, or the stored one was dropped.
    case absent
    case fresh(VerifiedManifest)
    /// Expired, but its restrictions stay in force. Time passing never loosens policy.
    case stale(VerifiedManifest)

    public var manifest: VerifiedManifest? {
        switch self {
        case .absent: return nil
        case .fresh(let verified), .stale(let verified): return verified
        }
    }
}

/// The anti-rollback, anti-equivocation store for signed manifests.
///
/// A value type with synchronous persistence so its invariants can be tested without
/// concurrency, and so its owner (`RemediationCoordinator`) gets atomic
/// check-then-commit for free.
public struct ManifestLedger: Sendable {
    public static let maxRecordedEquivocations = 16
    public static let maxForksAtFloor = 4
    /// High-water writes are throttled so a UI that reads every second doesn't write
    /// every second, except when time crosses a policy deadline (see `noteTime`).
    public static let highWaterPersistInterval: TimeInterval = 3600

    private let verifier: ManifestVerifier
    private let persistence: LedgerPersistence
    private let canWrite: Bool

    public private(set) var current: VerifiedManifest?
    /// Other signed copies seen at the current version (equivocation).
    public private(set) var forks: [VerifiedManifest]
    /// Restriction-only manifests carried over from storage. See `init`.
    public private(set) var retained: [SecurityManifest]
    private var retainedEnvelopes: [SignedManifestEnvelope]
    public static let maxRetained = 8
    public static let maxVersionStep: UInt64 = 1_000_000
    public static let maxCrossedDeadlines = 16
    public private(set) var crossedDeadlines: [Date]
    public private(set) var versionFloor: UInt64
    private var floorDigest: Data?
    public private(set) var equivocatedVersions: [UInt64]
    public private(set) var timeline: TrustedTimeline
    public private(set) var storage: StorageHealth
    /// Why a persisted last-known-good was dropped at load, if it was.
    public private(set) var discardedOnLoad: VerificationFailure?
    private var persistedHighWater: Date?

    public init(verifier: ManifestVerifier, persistence: LedgerPersistence, floor: TrustFloor = .none) {
        self.verifier = verifier
        self.persistence = persistence
        let state: PersistedLedgerState
        do {
            state = try persistence.load() ?? .empty
            canWrite = true
            storage = .healthy
        } catch {
            state = .empty
            canWrite = false
            storage = .unreadable(String(describing: error))
        }
        equivocatedVersions = Array(state.equivocatedVersions.suffix(Self.maxRecordedEquivocations))
        var highWater = state.timeHighWater
        if let built = floor.earliestTrustedTime, highWater.map({ $0 < built }) ?? true {
            highWater = built
        }
        timeline = TrustedTimeline(highWater: highWater)
        persistedHighWater = state.timeHighWater
        current = nil
        forks = []
        retained = []
        retainedEnvelopes = []
        discardedOnLoad = nil
        crossedDeadlines = Array((state.crossedDeadlines ?? []).suffix(Self.maxCrossedDeadlines))

        // Anything stored that can't become `current` is not discarded: its
        // *restrictions* stay in force (never its permissions) until a newer manifest
        // is applied. Otherwise a routine app update (key rotation, tighter limits,
        // schema bump, raised compiled-in floor) would silently turn an OFF switch
        // back on, and a hostile network could keep it on by blocking the next fetch.
        // Retention is restrict-only, so the worst a tampered file can do is add
        // restrictions, which needs write access to the app container anyway.
        var leftovers = state.retainedRestrictions ?? []
        let belowCompiledFloor = floor.minimumManifestVersion > state.versionFloor
        if belowCompiledFloor {
            versionFloor = floor.minimumManifestVersion
            floorDigest = nil
        } else {
            versionFloor = state.versionFloor
            floorDigest = state.floorDigest
        }

        if let envelope = state.lastKnownGood {
            if belowCompiledFloor {
                leftovers.append(envelope)
            } else {
                switch verifier.verify(envelope) {
                case .success(let verified)
                    where verified.manifest.version == versionFloor && verified.digest == floorDigest:
                    current = verified
                case .success:
                    // Validly signed but not the manifest the floor was set from.
                    discardedOnLoad = .malformedPayload
                    leftovers.append(envelope)
                case .failure(let failure):
                    discardedOnLoad = failure
                    leftovers.append(envelope)
                }
            }
        }
        for envelope in state.forksAtFloor ?? [] {
            if current != nil, forks.count < Self.maxForksAtFloor,
               case .success(let fork) = verifier.verify(envelope),
               fork.manifest.version == versionFloor, fork.digest != floorDigest {
                forks.append(fork)
            } else {
                leftovers.append(envelope)
            }
        }
        for envelope in leftovers where retained.count < Self.maxRetained {
            guard envelope.payload.count <= verifier.limits.maxPayloadBytes,
                  let manifest = try? ManifestCoding.decoder().decode(SecurityManifest.self, from: envelope.payload),
                  !retainedEnvelopes.contains(envelope)
            else { continue }
            retained.append(manifest)
            retainedEnvelopes.append(envelope)
        }
    }

    public func trustedNow(uptime: TimeInterval, wallClock: Date) -> (date: Date, basis: TimeBasis) {
        timeline.now(uptime: uptime, wallClock: wallClock)
    }

    public func status(uptime: TimeInterval, wallClock: Date) -> ManifestStatus {
        guard let current else { return .absent }
        let now = timeline.now(uptime: uptime, wallClock: wallClock).date
        return now >= current.manifest.expiresAt ? .stale(current) : .fresh(current)
    }

    /// Every rule in force: the applied manifest's, plus any equivocating copies' and
    /// any retained from storage this binary can't treat as current. Restrictions only ever accumulate here.
    public var effectiveRules: [CapabilityRule] {
        var rules = current?.manifest.rules ?? []
        for fork in forks {
            rules += fork.manifest.rules.map { rule in
                CapabilityRule(id: "fork@v\(fork.manifest.version)/\(rule.id)", capability: rule.capability,
                               action: rule.action, affectedBuilds: rule.affectedBuilds, reason: rule.reason)
            }
        }
        for kept in retained {
            rules += kept.rules.map { rule in
                CapabilityRule(id: "retained/\(rule.id)", capability: rule.capability, action: rule.action,
                               affectedBuilds: rule.affectedBuilds, reason: rule.reason)
            }
        }
        return rules
    }

    /// Every minimum-version policy in force (see `effectiveRules`).
    public var effectiveVersionPolicies: [MinimumVersionPolicy] {
        ([current?.manifest] + forks.map(\.manifest) + retained.map { Optional($0) })
            .compactMap { $0?.minimumVersion }
    }

    public mutating func accept(_ envelope: SignedManifestEnvelope,
                                uptime: TimeInterval, wallClock: Date) -> AcceptOutcome {
        let verified: VerifiedManifest
        switch verifier.verify(envelope) {
        case .failure(let failure): return .rejected(.verification(failure))
        case .success(let value): verified = value
        }
        let manifest = verified.manifest

        if manifest.version < versionFloor {
            return .rejected(.rollback(offered: manifest.version, floor: versionFloor))
        }
        let (ceiling, overflow) = versionFloor.addingReportingOverflow(Self.maxVersionStep)
        if !overflow, manifest.version > ceiling {
            return .rejected(.implausibleVersionJump(offered: manifest.version, floor: versionFloor))
        }
        if manifest.version == versionFloor, let floorDigest {
            guard floorDigest == verified.digest else {
                recordEquivocation(manifest.version)
                if current != nil {
                    if !forks.contains(where: { $0.digest == verified.digest }), forks.count < Self.maxForksAtFloor {
                        forks.append(verified)
                    }
                } else {
                    // No applied copy (it was dropped at load): keep this one's restrictions.
                    retain(verified)
                }
                _ = persist()
                return .rejected(.equivocation(version: manifest.version))
            }
            if current != nil { return .unchanged(version: manifest.version) }
            // The floor manifest itself, after its stored copy was dropped at load:
            // re-adopt it through the normal commit path below.
        }

        // Expiry is judged only on signed evidence: anchored time this boot, else the
        // high-water mark (which the compiled-in TrustFloor seeds, so a fresh install
        // has evidence too). An unanchored wall clock is never allowed to reject a
        // manifest: a phone whose clock is a year fast would otherwise be unable to
        // accept the fix that tells it to stop.
        let now = timeline.now(uptime: uptime, wallClock: wallClock)
        let evidence: Date? = now.basis == .signedAnchor ? now.date : timeline.highWater
        if let evidence, evidence >= manifest.expiresAt {
            return .rejected(.expired(version: manifest.version))
        }

        guard canWrite else {
            // Unreadable storage: no trustworthy floor, so restrictions only.
            retain(verified)
            return .restrictionsOnly(version: manifest.version)
        }

        current = verified
        forks = []
        retained = []
        retainedEnvelopes = []
        crossedDeadlines = []
        versionFloor = manifest.version
        floorDigest = verified.digest
        timeline.anchor(toSigned: manifest.issuedAt, uptime: uptime, wallClock: wallClock)
        let durable = persist()
        return .applied(version: manifest.version, durable: durable)
    }

    /// Records hard-enforcement deadlines that trusted time (on any basis) has passed.
    /// A fast wall clock can only latch a deadline early, which restricts; the latch
    /// clears when a newer manifest is applied.
    private mutating func latchDeadlines(now: Date) -> Bool {
        var changed = false
        for deadline in effectiveVersionPolicies.compactMap(\.requiredFrom)
        where deadline <= now && !crossedDeadlines.contains(deadline) {
            crossedDeadlines.append(deadline)
            changed = true
        }
        if crossedDeadlines.count > Self.maxCrossedDeadlines {
            crossedDeadlines.removeFirst(crossedDeadlines.count - Self.maxCrossedDeadlines)
        }
        return changed
    }

    public func hasCrossed(_ deadline: Date) -> Bool { crossedDeadlines.contains(deadline) }

    private mutating func retain(_ verified: VerifiedManifest) {
        guard retained.count < Self.maxRetained, !retainedEnvelopes.contains(verified.envelope) else { return }
        retained.append(verified.manifest)
        retainedEnvelopes.append(verified.envelope)
    }

    /// Called on reads. Persists the high-water mark at most once per interval, or
    /// immediately when it has just crossed a deadline (manifest expiry or hard
    /// enforcement), so a relaunch with the clock wound back can't step back over it.
    public mutating func noteTime(uptime: TimeInterval, wallClock: Date) {
        let latched = latchDeadlines(now: timeline.now(uptime: uptime, wallClock: wallClock).date)
        var highWaterDue = false
        if timeline.advanceHighWater(uptime: uptime, wallClock: wallClock), let mark = timeline.highWater {
            if let persistedHighWater {
                let crossedDeadline = deadlines.contains { persistedHighWater < $0 && $0 <= mark }
                highWaterDue = crossedDeadline
                    || mark.timeIntervalSince(persistedHighWater) >= Self.highWaterPersistInterval
            } else {
                highWaterDue = true
            }
        }
        if latched || highWaterDue { _ = persist() }
    }

    private var deadlines: [Date] {
        var result: [Date] = []
        if let current { result.append(current.manifest.expiresAt) }
        result += effectiveVersionPolicies.compactMap(\.requiredFrom)
        return result
    }

    private mutating func recordEquivocation(_ version: UInt64) {
        guard !equivocatedVersions.contains(version) else { return }
        equivocatedVersions.append(version)
        if equivocatedVersions.count > Self.maxRecordedEquivocations {
            equivocatedVersions.removeFirst(equivocatedVersions.count - Self.maxRecordedEquivocations)
        }
    }

    private mutating func persist() -> Bool {
        guard canWrite else { return false }
        var state = PersistedLedgerState(
            versionFloor: versionFloor,
            floorDigest: floorDigest,
            lastKnownGood: current?.envelope,
            timeHighWater: timeline.highWater,
            equivocatedVersions: equivocatedVersions,
            forksAtFloor: forks.isEmpty ? nil : forks.map(\.envelope))
        state.retainedRestrictions = retainedEnvelopes.isEmpty ? nil : retainedEnvelopes
        state.crossedDeadlines = crossedDeadlines.isEmpty ? nil : crossedDeadlines
        do {
            try persistence.save(state)
            storage = .healthy
            persistedHighWater = timeline.highWater
            return true
        } catch {
            storage = .writeFailing(String(describing: error))
            return false
        }
    }
}
