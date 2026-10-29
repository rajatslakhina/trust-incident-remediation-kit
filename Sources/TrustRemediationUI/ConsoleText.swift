import Foundation
import TrustRemediation

/// Plain-text rendering, kept free of SwiftUI state so it stays trivially correct.
public enum ConsoleText {
    public static func status(_ status: ManifestStatus?) -> String {
        switch status {
        case .absent?, nil: return "None verified"
        case .fresh(let verified)?: return "v\(verified.manifest.version) · fresh"
        case .stale(let verified)?: return "v\(verified.manifest.version) · stale (kept)"
        }
    }

    public static func basis(_ basis: TimeBasis?) -> String {
        switch basis {
        case .signedAnchor?: return "Signed anchor"
        case .flooredWallClock?: return "Wall clock (floored)"
        case nil: return "—"
        }
    }

    public static func upgrade(_ upgrade: UpgradeRequirement) -> String {
        switch upgrade {
        case .notNeeded: return "No upgrade needed"
        case .recommended(let target, let from?):
            return "Update to \(target) recommended — required from \(RemediationLab.format(from))"
        case .recommended(let target, nil): return "Update to \(target) recommended"
        case .required(let target): return "Update to \(target) required"
        }
    }

    public static func isRequired(_ upgrade: UpgradeRequirement) -> Bool {
        if case .required = upgrade { return true }
        return false
    }

    public static func cause(_ cause: DecisionCause) -> String {
        switch cause {
        case .noRestriction: return "No restriction"
        case .rule(let id, let reason): return "\(id): \(reason)"
        case .noVerifiedManifest: return "No verified manifest yet"
        case .staleManifest: return "Manifest expired; holding the safe posture"
        case .upgradeRequired(let target): return "Blocked until \(target)"
        }
    }

    public static func state(_ state: CapabilityState) -> String {
        switch state {
        case .full: return "FULL"
        case .degraded: return "DEGRADED"
        case .disabled: return "OFF"
        }
    }

    public static func percent(_ basisPoints: Int?) -> String {
        guard let basisPoints else { return "—" }
        let whole = basisPoints / 100
        let fraction = basisPoints % 100
        return "\(whole).\(fraction < 10 ? "0" : "")\(fraction)%"
    }

    public static func exposureMark(_ exposed: Bool?) -> String {
        switch exposed {
        case true?: return " · exposed"
        case false?: return ""
        case nil: return " · withheld"
        }
    }
}
