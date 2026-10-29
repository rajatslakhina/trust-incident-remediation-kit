import Foundation

/// Which trust store a capability's network path relies on.
public enum TrustPath: String, Sendable, Codable, Equatable {
    /// URLSession with the OS trust store (optionally pinned). An OS-level distrust,
    /// like Apple blocking a compromised root, reaches it without an app update.
    case systemTrust
    /// A third-party SDK that ships its own root bundle (gRPC/BoringSSL stacks, some
    /// analytics and sync SDKs). The OS block does not reach it; only a new binary or
    /// this manifest can.
    case embeddedTrustStore
}

public enum CapabilityState: Int, Sendable, Comparable, CaseIterable {
    case full = 0
    case degraded = 1
    case disabled = 2

    public static func < (lhs: CapabilityState, rhs: CapabilityState) -> Bool { lhs.rawValue < rhs.rawValue }

    init(_ action: RuleAction) {
        switch action {
        case .degrade: self = .degraded
        case .disable: self = .disabled
        }
    }
}

/// A capability the binary ships, declared at compile time by the app.
public struct CapabilityDescriptor: Sendable, Equatable, Identifiable {
    public let id: String
    public let displayName: String
    public let trustPath: TrustPath
    /// State when there is no fresh verified manifest (never fetched, or stale).
    public let unverifiedFallback: CapabilityState
    /// Whether a *required* upgrade switches this capability off. Hard enforcement
    /// disables network paths; it does not brick the app's local data.
    public let blockedWhenUpgradeRequired: Bool

    /// Defaults follow the trust path: a path the OS can't protect runs degraded until
    /// a fresh manifest vouches for it; a system-trust path runs fully.
    public init(id: String, displayName: String, trustPath: TrustPath,
                unverifiedFallback: CapabilityState? = nil,
                blockedWhenUpgradeRequired: Bool? = nil) {
        self.id = id
        self.displayName = displayName
        self.trustPath = trustPath
        self.unverifiedFallback = unverifiedFallback ?? (trustPath == .embeddedTrustStore ? .degraded : .full)
        self.blockedWhenUpgradeRequired = blockedWhenUpgradeRequired ?? (trustPath == .embeddedTrustStore)
    }
}

/// The compiled-in list of gateable capabilities.
public struct CapabilityCatalog: Sendable, Equatable {
    public let capabilities: [CapabilityDescriptor]

    /// `nil` on duplicate ids.
    public init?(_ capabilities: [CapabilityDescriptor]) {
        guard Set(capabilities.map(\.id)).count == capabilities.count else { return nil }
        self.capabilities = capabilities
    }

    public func contains(_ id: String) -> Bool { capabilities.contains { $0.id == id } }
}

public enum DecisionCause: Equatable, Sendable {
    case noRestriction
    case rule(id: String, reason: String)
    case noVerifiedManifest
    case staleManifest
    case upgradeRequired(target: BuildVersion)
}

public struct GateDecision: Equatable, Sendable, Identifiable {
    public let capability: String
    public let state: CapabilityState
    public let cause: DecisionCause
    public var id: String { capability }
}

public enum UpgradeRequirement: Equatable, Sendable {
    case notNeeded
    case recommended(target: BuildVersion, enforcedFrom: Date?)
    case required(target: BuildVersion)

    /// Staged soft → hard enforcement, judged against *trusted* time.
    public static func evaluate(_ policy: MinimumVersionPolicy?, build: BuildVersion,
                                trustedNow: Date) -> UpgradeRequirement {
        guard let policy else { return .notNeeded }
        if let required = policy.required, build < required {
            if let from = policy.requiredFrom, trustedNow < from {
                return .recommended(target: required, enforcedFrom: from)
            }
            return .required(target: required)
        }
        if let recommended = policy.recommended, build < recommended {
            return .recommended(target: recommended, enforcedFrom: nil)
        }
        return .notNeeded
    }

    /// The stricter of several requirements, for display: required beats recommended
    /// beats none; between two of the same kind, the higher target wins (with its own
    /// deadline), and for the same target the earlier deadline wins. A recommendation
    /// for a higher target than a requirement is not shown.
    public static func strictest(_ requirements: [UpgradeRequirement]) -> UpgradeRequirement {
        requirements.reduce(.notNeeded) { stricter($0, $1) }
    }

    static func stricter(_ a: UpgradeRequirement, _ b: UpgradeRequirement) -> UpgradeRequirement {
        switch (a, b) {
        case (.notNeeded, _): return b
        case (_, .notNeeded): return a
        case (.required(let x), .required(let y)): return .required(target: max(x, y))
        case (.required, .recommended): return a
        case (.recommended, .required): return b
        case (.recommended(let x, let dx), .recommended(let y, let dy)):
            // A deadline belongs to its own target, so never pair one policy's
            // deadline with another's target.
            if x != y { return x > y ? a : b }
            switch (dx, dy) {
            case (nil, _): return b
            case (_, nil): return a
            case (let d1?, let d2?): return d1 <= d2 ? a : b
            }
        }
    }
}

/// Pure policy evaluation: catalog × build × manifest status → one decision per
/// capability. No I/O and no clock, so it is exhaustively testable.
public enum CapabilityGate {
    public struct Result: Equatable, Sendable {
        public let decisions: [GateDecision]
        /// Rules naming a capability this binary doesn't ship. Reported, never fatal:
        /// one manifest serves every build in the field, old and new.
        public let unknownCapabilityRuleIDs: [String]
    }

    /// - Parameter rules: the rules in force; defaults to the status's manifest rules.
    ///   `RemediationCoordinator` passes `ManifestLedger.effectiveRules`, which also
    ///   carries restrictions from equivocating copies and retired-key manifests.
    public static func evaluate(catalog: CapabilityCatalog, build: BuildVersion,
                                status: ManifestStatus, upgrade: UpgradeRequirement,
                                rules explicitRules: [CapabilityRule]? = nil) -> Result {
        let rules = explicitRules ?? status.manifest?.manifest.rules ?? []
        let decisions = catalog.capabilities.map { descriptor in
            decide(descriptor, build: build, rules: rules, status: status, upgrade: upgrade)
        }
        let unknown = rules.filter { !catalog.contains($0.capability) }.map(\.id).sorted()
        return Result(decisions: decisions, unknownCapabilityRuleIDs: unknown)
    }

    static func decide(_ descriptor: CapabilityDescriptor, build: BuildVersion,
                       rules: [CapabilityRule], status: ManifestStatus,
                       upgrade: UpgradeRequirement) -> GateDecision {
        var state = CapabilityState.full
        var cause = DecisionCause.noRestriction

        func tighten(to candidate: CapabilityState, because reason: DecisionCause) {
            if candidate > state {
                state = candidate
                cause = reason
            }
        }

        // 1. The most severe matching rule; equal severity → lowest rule id, so the
        //    answer never depends on the order rules appear in the manifest.
        let matching = rules
            .filter { $0.capability == descriptor.id && $0.applies(to: build) }
            .sorted { lhs, rhs in
                lhs.action != rhs.action ? lhs.action > rhs.action : lhs.id < rhs.id
            }
        if let strongest = matching.first {
            tighten(to: CapabilityState(strongest.action),
                    because: .rule(id: strongest.id, reason: strongest.reason))
        }

        // 2. Without a fresh manifest, fall back to the compiled-in posture.
        switch status {
        case .absent: tighten(to: descriptor.unverifiedFallback, because: .noVerifiedManifest)
        case .stale: tighten(to: descriptor.unverifiedFallback, because: .staleManifest)
        case .fresh: break
        }

        // 3. Hard upgrade enforcement.
        if case .required(let target) = upgrade, descriptor.blockedWhenUpgradeRequired {
            tighten(to: .disabled, because: .upgradeRequired(target: target))
        }

        return GateDecision(capability: descriptor.id, state: state, cause: cause)
    }
}
