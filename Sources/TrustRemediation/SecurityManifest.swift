import Foundation

/// The signed, out-of-band remediation policy a fleet receives during a trust incident.
///
/// It can only *restrict*: rules degrade or disable a capability the binary already
/// ships, and the version policy can only ask for a newer build. There is deliberately
/// no "enable" action. Turning on behaviour the binary did not ship enabled is a
/// binary release (and an App Review question under Guideline 2.5.19), not a
/// manifest push — which also means a stolen signing key can switch features off,
/// but can never switch hidden ones on.
public struct SecurityManifest: Codable, Sendable, Equatable {
    public static let supportedSchemaVersion = 1

    public let schemaVersion: Int
    /// Strictly increasing. The client keeps a durable floor and refuses anything lower.
    public let version: UInt64
    /// Must equal the envelope's key id, so a payload signed for one key cannot be
    /// re-wrapped under another.
    public let keyID: String
    /// Signed server time. The only clock the client treats as authoritative.
    public let issuedAt: Date
    public let expiresAt: Date
    public let rules: [CapabilityRule]
    public let minimumVersion: MinimumVersionPolicy?
    public let advisories: [AdvisoryNote]

    public init(
        schemaVersion: Int = SecurityManifest.supportedSchemaVersion,
        version: UInt64,
        keyID: String,
        issuedAt: Date,
        expiresAt: Date,
        rules: [CapabilityRule],
        minimumVersion: MinimumVersionPolicy? = nil,
        advisories: [AdvisoryNote] = []
    ) {
        self.schemaVersion = schemaVersion
        self.version = version
        self.keyID = keyID
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.rules = rules
        self.minimumVersion = minimumVersion
        self.advisories = advisories
    }
}

/// How hard a rule restricts a capability. Ordered by severity.
public enum RuleAction: String, Codable, Sendable, Comparable, CaseIterable {
    /// Keep the feature, but route around the untrusted path (e.g. local-only mode).
    case degrade
    /// Turn the network path off entirely.
    case disable

    var severity: Int {
        switch self {
        case .degrade: return 1
        case .disable: return 2
        }
    }

    public static func < (lhs: RuleAction, rhs: RuleAction) -> Bool { lhs.severity < rhs.severity }
}

public struct CapabilityRule: Codable, Sendable, Equatable {
    /// Stable id; also the deterministic tie-breaker between equally severe rules.
    public let id: String
    public let capability: String
    public let action: RuleAction
    /// Builds the rule applies to. Empty means every build.
    public let affectedBuilds: [VersionRange]
    public let reason: String

    public init(id: String, capability: String, action: RuleAction,
                affectedBuilds: [VersionRange] = [], reason: String) {
        self.id = id
        self.capability = capability
        self.action = action
        self.affectedBuilds = affectedBuilds
        self.reason = reason
    }

    public func applies(to build: BuildVersion) -> Bool {
        affectedBuilds.isEmpty || affectedBuilds.contains { $0.contains(build) }
    }
}

/// Staged minimum-version enforcement: recommend first, require from a signed date.
public struct MinimumVersionPolicy: Codable, Sendable, Equatable {
    public let recommended: BuildVersion?
    public let required: BuildVersion?
    /// When `required` starts being enforced. `nil` means immediately.
    public let requiredFrom: Date?
    public let reason: String

    public init(recommended: BuildVersion? = nil, required: BuildVersion? = nil,
                requiredFrom: Date? = nil, reason: String) {
        self.recommended = recommended
        self.required = required
        self.requiredFrom = requiredFrom
        self.reason = reason
    }
}

public struct AdvisoryNote: Codable, Sendable, Equatable {
    public let id: String
    public let title: String

    public init(id: String, title: String) {
        self.id = id
        self.title = title
    }
}

/// The wire format: the exact signed bytes plus the signature over them.
///
/// The signature covers `payload` byte-for-byte; the client never re-encodes JSON
/// before verifying. Canonical-JSON schemes are a classic source of
/// "verified one document, used another" bugs, and Foundation's encoder makes no
/// canonical-form promise across OS versions.
public struct SignedManifestEnvelope: Codable, Sendable, Equatable {
    public let keyID: String
    public let payload: Data
    public let signature: Data

    public init(keyID: String, payload: Data, signature: Data) {
        self.keyID = keyID
        self.payload = payload
        self.signature = signature
    }
}

enum ManifestCoding {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
