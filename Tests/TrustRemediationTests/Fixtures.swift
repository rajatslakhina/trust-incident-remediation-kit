import Foundation
@testable import TrustRemediation
import XCTest

enum Fixture {
    static let t0 = Date(timeIntervalSince1970: 1_793_232_000)
    static let day: TimeInterval = 86_400

    // A malformed fixture is a bug in the test itself, so it stops the run loudly.
    static func version(_ string: String) -> BuildVersion {
        guard let parsed = BuildVersion(string) else { preconditionFailure("bad fixture version \(string)") }
        return parsed
    }

    static func range(_ introduced: String?, _ fixed: String?) -> VersionRange {
        guard let range = VersionRange(introduced: introduced.map { version($0) }, fixed: fixed.map { version($0) })
        else { preconditionFailure("empty fixture range") }
        return range
    }

    struct Keys {
        let signer: ManifestSigner
        let trusted: TrustedKey
        let verifier: ManifestVerifier
    }

    static func keys(id: String = "k1", limits: ManifestVerifier.Limits = .init()) throws -> Keys {
        let pair = try XCTUnwrap(ManifestSigner.generate(keyID: id))
        let set = try XCTUnwrap(TrustedKeySet([pair.trusted]))
        return Keys(signer: pair.signer, trusted: pair.trusted, verifier: ManifestVerifier(trustedKeys: set, limits: limits))
    }

    static func manifest(version: UInt64, keyID: String = "k1", issuedAt: Date = t0,
                         lifetime: TimeInterval = 7 * day, rules: [CapabilityRule] = [],
                         minimumVersion: MinimumVersionPolicy? = nil) -> SecurityManifest {
        SecurityManifest(version: version, keyID: keyID, issuedAt: issuedAt,
                         expiresAt: issuedAt.addingTimeInterval(lifetime), rules: rules,
                         minimumVersion: minimumVersion)
    }

    static let catalog: CapabilityCatalog = {
        guard let catalog = CapabilityCatalog([
            CapabilityDescriptor(id: "partnerSync", displayName: "Partner sync", trustPath: .embeddedTrustStore),
            CapabilityDescriptor(id: "photoBackup", displayName: "Photo backup", trustPath: .systemTrust),
        ]) else { preconditionFailure("fixture catalog has duplicate ids") }
        return catalog
    }()
}

/// Uptime and wall clock under test control.
final class TestClock: UptimeSource, WallClock, @unchecked Sendable {
    private let lock = NSLock()
    private var up: TimeInterval
    private var wall: Date

    init(uptime: TimeInterval = 1_000, wall: Date = Fixture.t0) {
        up = uptime
        self.wall = wall
    }

    func uptime() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return up }
    func now() -> Date { lock.lock(); defer { lock.unlock() }; return wall }

    func advance(_ seconds: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        up += seconds
        wall = wall.addingTimeInterval(seconds)
    }

    func setWall(_ date: Date) { lock.lock(); defer { lock.unlock() }; wall = date }
    func reboot(uptime: TimeInterval = 10) { lock.lock(); defer { lock.unlock() }; up = uptime }
}

struct TestError: Error, Equatable {}
