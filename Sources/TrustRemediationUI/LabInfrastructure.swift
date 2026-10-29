import Foundation
import TrustRemediation

/// Server time, device uptime and the device wall clock, moved independently.
final class LabClock: UptimeSource, WallClock, @unchecked Sendable {
    // @unchecked: all mutable state is guarded by `lock`.
    private let lock = NSLock()
    private let epoch: Date
    private var elapsed: TimeInterval = 0
    private var uptimeValue: TimeInterval = 120
    private var wallOffset: TimeInterval = 0

    init(epoch: Date) {
        self.epoch = epoch
    }

    var serverNow: Date {
        lock.lock()
        defer { lock.unlock() }
        return epoch.addingTimeInterval(elapsed)
    }

    func uptime() -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return uptimeValue
    }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return epoch.addingTimeInterval(elapsed + wallOffset)
    }

    func advance(by interval: TimeInterval) {
        guard interval.isFinite, interval > 0 else { return }
        lock.lock()
        defer { lock.unlock() }
        elapsed += interval
        uptimeValue += interval
    }

    func shiftWallClock(by interval: TimeInterval) {
        guard interval.isFinite else { return }
        lock.lock()
        defer { lock.unlock() }
        wallOffset += interval
    }

    /// Uptime restarts near zero; server time and the wall clock carry on.
    func reboot() {
        lock.lock()
        defer { lock.unlock() }
        uptimeValue = 30
    }
}

struct LabTransportError: Error, CustomStringConvertible {
    var description: String { "network unreachable" }
}

/// An in-process manifest service that signs real Ed25519 envelopes, plus a hostile
/// network that can replay, tamper with or equivocate them on the next fetch.
final class LabServer: @unchecked Sendable {
    // @unchecked: all mutable state is guarded by `lock`.
    private enum Override { case none, replay(SignedManifestEnvelope), tamper, equivocate }

    private let lock = NSLock()
    private let signer: ManifestSigner
    private let clock: LabClock
    private let lifetime: TimeInterval
    private var version: UInt64 = 0
    private var rules: [CapabilityRule] = []
    private var minimumVersion: MinimumVersionPolicy?
    private var advisories: [AdvisoryNote] = []
    private var history: [SignedManifestEnvelope] = []
    private var latestIssuedAt: Date?
    private var override: Override = .none
    private var offline = false
    private var incident = false
    static let maxHistory = 32
    /// A live service re-signs its current policy daily so clients stay fresh.
    static let reissueInterval: TimeInterval = 86_400

    init(signer: ManifestSigner, clock: LabClock, lifetime: TimeInterval) {
        self.signer = signer
        self.clock = clock
        self.lifetime = lifetime
        lock.lock()
        signLocked()
        lock.unlock()
    }

    var isOffline: Bool {
        get { lock.lock(); defer { lock.unlock() }; return offline }
        set { lock.lock(); defer { lock.unlock() }; offline = newValue }
    }

    var hasDeclaredIncident: Bool {
        lock.lock()
        defer { lock.unlock() }
        return incident
    }

    func publish(rules: [CapabilityRule], minimumVersion: MinimumVersionPolicy?, advisories: [AdvisoryNote]) {
        lock.lock()
        defer { lock.unlock() }
        self.rules = rules
        self.minimumVersion = minimumVersion
        self.advisories = advisories
        incident = !rules.isEmpty || minimumVersion != nil
        signLocked()
    }

    /// Returns `false` when there is no older manifest to replay.
    func armReplayOfOldest() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard history.count >= 2, let oldest = history.first else { return false }
        override = .replay(oldest)
        return true
    }

    func armTamper() {
        lock.lock()
        defer { lock.unlock() }
        override = .tamper
    }

    func armEquivocation() {
        lock.lock()
        defer { lock.unlock() }
        override = .equivocate
    }

    func fetch() throws -> SignedManifestEnvelope {
        lock.lock()
        defer { lock.unlock() }
        guard !offline else { throw LabTransportError() }
        if let issued = latestIssuedAt, clock.serverNow.timeIntervalSince(issued) >= Self.reissueInterval {
            signLocked()
        }
        guard let latest = history.last else { throw LabTransportError() }
        let pending = override
        override = .none
        switch pending {
        case .none:
            return latest
        case .replay(let old):
            return old
        case .tamper:
            var payload = latest.payload
            guard !payload.isEmpty else { return latest }
            let index = payload.startIndex + payload.count / 2
            payload[index] ^= 0x01
            return SignedManifestEnvelope(keyID: latest.keyID, payload: payload, signature: latest.signature)
        case .equivocate:
            // Same version, different content, validly signed: a split-view attack or
            // a signing pipeline that lost its sequence.
            let forked = SecurityManifest(
                version: version, keyID: signer.keyID, issuedAt: clock.serverNow,
                expiresAt: clock.serverNow.addingTimeInterval(lifetime), rules: [],
                minimumVersion: nil, advisories: [AdvisoryNote(id: "FORK", title: "Forked view")])
            return (try? signer.sign(forked)) ?? latest
        }
    }

    /// Caller holds `lock`.
    private func signLocked() {
        let now = clock.serverNow
        let manifest = SecurityManifest(
            version: version &+ 1, keyID: signer.keyID, issuedAt: now,
            expiresAt: now.addingTimeInterval(lifetime), rules: rules,
            minimumVersion: minimumVersion, advisories: advisories)
        guard let envelope = try? signer.sign(manifest) else { return }
        version &+= 1
        latestIssuedAt = now
        history.append(envelope)
        if history.count > Self.maxHistory { history.removeFirst(history.count - Self.maxHistory) }
    }
}

struct LabTransport: ManifestTransport {
    let server: LabServer

    func fetchManifest() async throws -> SignedManifestEnvelope {
        try server.fetch()
    }
}
