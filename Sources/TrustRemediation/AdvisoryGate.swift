import Foundation

/// One dependency pin from `Package.resolved`.
public struct ResolvedPin: Sendable, Equatable {
    /// Lower-cased package identity.
    public let identity: String
    /// `nil` for branch or bare-revision pins.
    public let version: BuildVersion?
    public let revision: String?
}

public enum PackageResolvedError: Error, Equatable, Sendable {
    case malformed
    case unsupportedFormat(Int)
}

/// Reads `Package.resolved` formats 1, 2 and 3.
public enum PackageResolvedParser {
    private struct V1: Decodable {
        struct Object: Decodable { let pins: [Pin] }
        struct Pin: Decodable { let package: String; let repositoryURL: String; let state: State }
        let version: Int
        let object: Object
    }
    private struct V2: Decodable {
        struct Pin: Decodable { let identity: String; let state: State }
        let version: Int
        let pins: [Pin]
    }
    private struct State: Decodable {
        let version: String?
        let revision: String?
        let branch: String?
    }
    private struct Header: Decodable { let version: Int }

    public static func parse(_ data: Data) throws -> [ResolvedPin] {
        let decoder = JSONDecoder()
        guard let header = try? decoder.decode(Header.self, from: data) else {
            throw PackageResolvedError.malformed
        }
        switch header.version {
        case 1:
            guard let file = try? decoder.decode(V1.self, from: data) else { throw PackageResolvedError.malformed }
            // v1 `package` is the manifest *name* ("Firebase"); advisories are keyed by
            // SwiftPM identity ("firebase-ios-sdk"), which v2+ store and v1 does not.
            // Derive it from the URL the way SwiftPM does, or v1 files fail open.
            return file.object.pins.map { pin(identity: identity(fromURL: $0.repositoryURL), state: $0.state) }
        case 2, 3:
            guard let file = try? decoder.decode(V2.self, from: data) else { throw PackageResolvedError.malformed }
            return file.pins.map { pin(identity: $0.identity, state: $0.state) }
        default:
            throw PackageResolvedError.unsupportedFormat(header.version)
        }
    }

    /// SwiftPM's identity rule for remote packages: last path component, minus `.git`.
    static func identity(fromURL url: String) -> String {
        var trimmed = url
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        var last = trimmed.split(whereSeparator: { $0 == "/" || $0 == ":" }).last.map(String.init) ?? trimmed
        if let suffix = last.range(of: ".git", options: [.caseInsensitive, .anchored, .backwards]) {
            last.removeSubrange(suffix)
        }
        return last
    }

    private static func pin(identity: String, state: State) -> ResolvedPin {
        ResolvedPin(identity: identity.lowercased(),
                    version: state.version.flatMap(BuildVersion.init),
                    revision: state.revision)
    }
}

public enum AdvisorySeverity: String, Codable, Sendable, Comparable, CaseIterable {
    case low, moderate, high, critical

    var rank: Int {
        switch self {
        case .low: return 0
        case .moderate: return 1
        case .high: return 2
        case .critical: return 3
        }
    }

    public static func < (lhs: AdvisorySeverity, rhs: AdvisorySeverity) -> Bool { lhs.rank < rhs.rank }
}

/// A feed entry, e.g. "Firestore embeds the compromised root before 12.19.3".
public struct PackageAdvisory: Codable, Sendable, Equatable {
    public let id: String
    public let package: String
    /// Affected versions. Empty means *every* version, the same convention as
    /// `CapabilityRule.affectedBuilds`, so a feed entry missing its ranges fails closed.
    public let affected: [VersionRange]
    public let severity: AdvisorySeverity
    public let summary: String

    public init(id: String, package: String, affected: [VersionRange],
                severity: AdvisorySeverity, summary: String) {
        self.id = id
        self.package = package
        self.affected = affected
        self.severity = severity
        self.summary = summary
    }
}

public struct AdvisoryFinding: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case affected(version: BuildVersion)
        /// A branch or revision pin for a package with an open advisory. The gate
        /// can't prove it is safe, so it counts as affected (fail closed).
        case unassessable
    }

    public let advisoryID: String
    public let package: String
    public let kind: Kind
    public let severity: AdvisorySeverity
}

/// The CI half: fail the build when a resolved dependency is covered by an advisory.
/// This is what stops the *next* release from shipping the bad trust store while the
/// manifest handles the builds already in the field.
public enum AdvisoryGate {
    public struct Verdict: Sendable, Equatable {
        public let findings: [AdvisoryFinding]
        public let failingFindings: [AdvisoryFinding]
        public var passed: Bool { failingFindings.isEmpty }
    }

    public static func evaluate(pins: [ResolvedPin], advisories: [PackageAdvisory],
                                failAt threshold: AdvisorySeverity) -> Verdict {
        var findings: [AdvisoryFinding] = []
        for advisory in advisories {
            let package = advisory.package.lowercased()
            for pin in pins where pin.identity == package {
                if let version = pin.version {
                    guard advisory.affected.isEmpty || advisory.affected.contains(where: { $0.contains(version) })
                    else { continue }
                    findings.append(.init(advisoryID: advisory.id, package: package,
                                          kind: .affected(version: version), severity: advisory.severity))
                } else {
                    findings.append(.init(advisoryID: advisory.id, package: package,
                                          kind: .unassessable, severity: advisory.severity))
                }
            }
        }
        findings.sort { lhs, rhs in
            lhs.severity != rhs.severity ? lhs.severity > rhs.severity : lhs.advisoryID < rhs.advisoryID
        }
        return Verdict(findings: findings, failingFindings: findings.filter { $0.severity >= threshold })
    }
}
