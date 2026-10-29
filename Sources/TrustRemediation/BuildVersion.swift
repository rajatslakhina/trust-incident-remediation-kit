import Foundation

/// A `major.minor.patch` app or package version.
///
/// Parsing never traps: each component must be 1–9 ASCII digits, so the value always
/// fits a 32-bit `Int`, and anything else (`"4.x"`, `"-1"`, `"99999999999999999999"`)
/// is rejected rather than coerced.
public struct BuildVersion: Hashable, Comparable, Sendable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int

    /// Nine digits keeps every component below 1_000_000_000 < Int32.max.
    static let maxComponentDigits = 9

    public init?(major: Int, minor: Int = 0, patch: Int = 0) {
        let ceiling = Self.componentCeiling
        guard (0...ceiling).contains(major),
              (0...ceiling).contains(minor),
              (0...ceiling).contains(patch) else { return nil }
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    public init?(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count) else { return nil }
        var values: [Int] = []
        for part in parts {
            guard !part.isEmpty,
                  part.count <= Self.maxComponentDigits,
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let value = Int(part) else { return nil }
            values.append(value)
        }
        // `values.count` is 1...3 here; index access is guarded by the count checks.
        let major = values[0]
        let minor = values.count > 1 ? values[1] : 0
        let patch = values.count > 2 ? values[2] : 0
        self.init(major: major, minor: minor, patch: patch)
    }

    static var componentCeiling: Int {
        // 999_999_999, or Int.max on a hypothetical platform where Int is narrower.
        min(999_999_999, Int.max)
    }

    public var description: String { "\(major).\(minor).\(patch)" }

    public static func < (lhs: BuildVersion, rhs: BuildVersion) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }
}

extension BuildVersion: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let parsed = BuildVersion(raw) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "Not a major.minor.patch version: \(raw)")
        }
        self = parsed
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// A half-open range of affected versions: `introduced <= v < fixed`.
///
/// `nil` bounds mean "since the beginning" and "not fixed yet". An empty range
/// (`fixed <= introduced`) is rejected at construction and at decode time, because a
/// rule that silently matches nothing is how a kill switch fails to fire.
public struct VersionRange: Hashable, Sendable {
    public let introduced: BuildVersion?
    public let fixed: BuildVersion?

    public init?(introduced: BuildVersion? = nil, fixed: BuildVersion? = nil) {
        if let introduced, let fixed, fixed <= introduced { return nil }
        self.introduced = introduced
        self.fixed = fixed
    }

    public func contains(_ version: BuildVersion) -> Bool {
        if let introduced, version < introduced { return false }
        if let fixed, version >= fixed { return false }
        return true
    }
}

extension VersionRange: Codable {
    private enum CodingKeys: String, CodingKey { case introduced, fixed }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let introduced = try container.decodeIfPresent(BuildVersion.self, forKey: .introduced)
        let fixed = try container.decodeIfPresent(BuildVersion.self, forKey: .fixed)
        guard let range = VersionRange(introduced: introduced, fixed: fixed) else {
            throw DecodingError.dataCorruptedError(
                forKey: .fixed, in: container, debugDescription: "Empty version range")
        }
        self = range
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(introduced, forKey: .introduced)
        try container.encodeIfPresent(fixed, forKey: .fixed)
    }
}
