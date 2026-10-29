import Foundation
import TrustRemediation

/// The demo's incident script, supplied by the app.
public struct LabScenario: Sendable {
    public let catalog: CapabilityCatalog
    public let vulnerableBuild: BuildVersion
    public let fixedBuild: BuildVersion
    /// Rules the "server" publishes when the incident is declared.
    public let incidentRules: [CapabilityRule]
    /// Days between the incident manifest and hard enforcement of `fixedBuild`.
    public let hardEnforcementAfterDays: Int
    /// Simulated installed base at the start of the incident.
    public let initialFleet: [InstallCohort]
    /// k for the exposure dashboard.
    public let minimumCohortSize: Int

    public init(catalog: CapabilityCatalog, vulnerableBuild: BuildVersion, fixedBuild: BuildVersion,
                incidentRules: [CapabilityRule], hardEnforcementAfterDays: Int,
                initialFleet: [InstallCohort], minimumCohortSize: Int) {
        self.catalog = catalog
        self.vulnerableBuild = vulnerableBuild
        self.fixedBuild = fixedBuild
        self.incidentRules = incidentRules
        self.hardEnforcementAfterDays = hardEnforcementAfterDays
        self.initialFleet = initialFleet
        self.minimumCohortSize = minimumCohortSize
    }
}

/// Declared in script order: the first nine run the incident top to bottom; the
/// last three are free play.
public enum LabAction: String, CaseIterable, Sendable, Identifiable {
    case declareIncident
    case replayOldManifest
    case tamperInTransit
    case equivocate
    case advanceEightDays
    case setPhoneClockBackTenDays
    case rebootDevice
    case installFixedBuild
    case allClear
    case refresh
    case advanceOneDay
    case toggleNetwork

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .declareIncident: return "Declare incident"
        case .refresh: return "Refresh manifest"
        case .advanceOneDay: return "+1 day"
        case .advanceEightDays: return "+8 days offline"
        case .replayOldManifest: return "Replay old manifest"
        case .tamperInTransit: return "Tamper in transit"
        case .equivocate: return "Equivocating signer"
        case .toggleNetwork: return "Toggle network"
        case .setPhoneClockBackTenDays: return "Phone clock −10 days"
        case .rebootDevice: return "Reboot device"
        case .installFixedBuild: return "Install fixed build"
        case .allClear: return "Publish all-clear"
        }
    }
}

public struct LabLogEntry: Identifiable, Equatable, Sendable {
    public enum Tone: Sendable, Equatable { case info, good, warning, bad }
    public let id: Int
    public let title: String
    public let detail: String
    public let tone: Tone
}

/// A deterministic, in-process trust incident: a signing "server", a controllable
/// clock, a hostile network, a simulated fleet, and a real `RemediationCoordinator`
/// in the middle. Platform-agnostic so the Linux test job drives the same script the
/// SwiftUI console does.
@MainActor
public final class RemediationLab {
    public nonisolated static let maxLogEntries = 60
    public nonisolated static let manifestLifetimeDays = 7

    public let scenario: LabScenario
    public private(set) var build: BuildVersion
    public private(set) var snapshot: RemediationSnapshot?
    public private(set) var exposure: ExposureReport
    public private(set) var log: [LabLogEntry] = []
    public var isNetworkOnline: Bool { !server.isOffline }
    public var serverNow: Date { clock.serverNow }

    private let clock: LabClock
    private let server: LabServer
    private let persistence = InMemoryLedgerPersistence()
    private let verifier: ManifestVerifier
    private var coordinator: RemediationCoordinator
    private var fleet: [InstallCohort]
    /// "This binary was built the day before the demo starts."
    private let floor: TrustFloor
    private var nextLogID = 0
    public private(set) var isRunning = false

    /// `nil` only if key generation fails, which a real CSPRNG does not do.
    public init?(scenario: LabScenario, epoch: Date = Date(timeIntervalSince1970: 1_793_232_000)) {
        guard let keys = ManifestSigner.generate(keyID: "demo-2026-10"),
              let keySet = TrustedKeySet([keys.trusted]) else { return nil }
        self.scenario = scenario
        self.build = scenario.vulnerableBuild
        self.fleet = scenario.initialFleet
        self.clock = LabClock(epoch: epoch)
        self.floor = TrustFloor(earliestTrustedTime: epoch.addingTimeInterval(-86_400))
        self.server = LabServer(signer: keys.signer, clock: clock,
                                lifetime: TimeInterval(Self.manifestLifetimeDays * 86_400))
        self.verifier = ManifestVerifier(trustedKeys: keySet)
        self.coordinator = RemediationCoordinator(
            catalog: scenario.catalog, build: scenario.vulnerableBuild, verifier: verifier,
            persistence: persistence, transport: LabTransport(server: server), floor: floor,
            uptime: clock, wallClock: clock)
        self.exposure = ExposureAnalyzer.report(
            cohorts: scenario.initialFleet, vulnerable: [], minimumCohortSize: scenario.minimumCohortSize)
    }

    /// First launch: fetch the baseline (no-incident) manifest.
    public func start() async {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        append("App launched", "Build \(build), no manifest on disk yet.", .info)
        await refresh()
    }

    /// Actions are serialized: a call that arrives while another is suspended is
    /// dropped (and logged). Without this, a reboot could swap the coordinator while a
    /// refresh on the old one is mid-flight, and the old ledger could persist a floor
    /// the new one never loaded.
    public func run(_ action: LabAction) async {
        guard !isRunning else {
            append("\(action.title) ignored", "Another action is still running.", .info)
            return
        }
        isRunning = true
        defer { isRunning = false }
        let needsNetwork: Set<LabAction> = [.replayOldManifest, .tamperInTransit, .equivocate]
        if needsNetwork.contains(action), !isNetworkOnline {
            append("\(action.title) needs the network", "Turn the network back on first.", .info)
            return
        }
        switch action {
        case .declareIncident:
            server.publish(rules: scenario.incidentRules, minimumVersion: MinimumVersionPolicy(
                recommended: scenario.fixedBuild, required: scenario.fixedBuild,
                requiredFrom: clock.serverNow.addingTimeInterval(
                    TimeInterval(max(scenario.hardEnforcementAfterDays, 0)) * 86_400),
                reason: "Embedded trust store includes a compromised CA"),
                advisories: [AdvisoryNote(id: "LAB-CA-2026-10", title: "Compromised intermediate CAs")])
            append("Incident declared", "Server now signs a restricting manifest.", .warning)
            await refresh()
        case .refresh:
            await refresh()
        case .advanceOneDay:
            advance(days: 1)
            await refresh()
        case .advanceEightDays:
            let wasOnline = isNetworkOnline
            server.isOffline = true
            advance(days: 8)
            append("8 days pass offline", "No fetch succeeds; the manifest ages.", .info)
            await reload()
            server.isOffline = !wasOnline
        case .replayOldManifest:
            if server.armReplayOfOldest() {
                append("Network replays the oldest signed manifest", "Validly signed, but old.", .warning)
            } else {
                append("Nothing to replay yet", "Only one manifest has been signed.", .info)
            }
            await refresh()
        case .tamperInTransit:
            server.armTamper()
            append("A byte is flipped in transit", "Signature no longer matches.", .warning)
            await refresh()
        case .equivocate:
            // Sync to the server's latest first, so the fork lands on the client's floor.
            await refresh()
            server.armEquivocation()
            append("Signer issues a second, different manifest at the same version", "", .warning)
            await refresh()
        case .toggleNetwork:
            server.isOffline.toggle()
            append(server.isOffline ? "Network down" : "Network up", "", .info)
            await reload()
        case .setPhoneClockBackTenDays:
            clock.shiftWallClock(by: -10 * 86_400)
            append("User sets the phone clock back 10 days", "Trusted time ignores the wall clock while anchored.", .info)
            await reload()
        case .rebootDevice:
            await relaunch(reboot: true, message: "Device rebooted (uptime reset; no signed anchor this boot)")
        case .installFixedBuild:
            build = scenario.fixedBuild
            await relaunch(reboot: false, message: "Updated to \(build)")
            await refresh()
        case .allClear:
            server.publish(rules: [], minimumVersion: nil,
                           advisories: [AdvisoryNote(id: "LAB-CA-2026-10", title: "Resolved")])
            append("All-clear published", "A newer manifest lifts the restrictions.", .good)
            await refresh()
        }
        recomputeExposure()
    }

    // MARK: - Internals

    private func advance(days: Int) {
        let safeDays = max(days, 0)
        clock.advance(by: TimeInterval(safeDays) * 86_400)
        // Simulated adoption: 30% of each exposed cohort upgrades per day once a fix ships.
        if server.hasDeclaredIncident {
            for _ in 0..<safeDays { moveFleetToFixedBuild(fraction: 3, of: 10) }
        }
        append("+\(safeDays) day\(safeDays == 1 ? "" : "s")", "Server time \(Self.format(clock.serverNow)).", .info)
    }

    private func refresh() async {
        let outcome = await coordinator.refresh()
        switch outcome {
        case .transportFailed:
            append("Fetch failed", "Offline. Last known good policy stays in force.", .warning)
        case .accepted(let accept):
            switch accept {
            case .applied(let version, let durable):
                append("Applied manifest v\(version)", durable ? "Floor persisted." : "Applied in memory only.", .good)
            case .unchanged(let version):
                append("Manifest v\(version) unchanged", "", .info)
            case .restrictionsOnly(let version):
                append("v\(version) enforced as restrictions only", "Storage unreadable: nothing can be lifted.", .warning)
            case .rejected(let reason):
                append("Rejected", Self.describe(reason), .bad)
            }
        }
        await reload()
    }

    private func reload() async {
        snapshot = await coordinator.snapshot()
    }

    private func relaunch(reboot: Bool, message: String) async {
        if reboot { clock.reboot() }
        coordinator = RemediationCoordinator(
            catalog: scenario.catalog, build: build, verifier: verifier, persistence: persistence,
            transport: LabTransport(server: server), floor: floor, uptime: clock, wallClock: clock)
        append(message, "Ledger reloaded from storage; floor v\(persistence.snapshot?.versionFloor ?? 0).", .info)
        await reload()
    }

    /// Moves `numerator/denominator` of every exposed cohort onto the fixed build.
    private func moveFleetToFixedBuild(fraction numerator: Int, of denominator: Int) {
        guard denominator > 0, numerator > 0 else { return }
        let n = min(numerator, denominator)
        var moved = 0
        fleet = fleet.map { cohort in
            guard cohort.build < scenario.fixedBuild, cohort.activeInstalls > 0 else { return cohort }
            // installs * n / d, split so the multiply can't overflow for small d;
            // n <= d keeps share <= activeInstalls.
            let installs = cohort.activeInstalls
            let share = installs / denominator * n + (installs % denominator) * n / denominator
            moved = Self.addSaturating(moved, share)
            return InstallCohort(build: cohort.build, activeInstalls: installs - share)
        }
        guard moved > 0 else { return }
        if let index = fleet.firstIndex(where: { $0.build == scenario.fixedBuild }) {
            let existing = fleet[index]
            fleet[index] = InstallCohort(build: existing.build,
                                         activeInstalls: Self.addSaturating(existing.activeInstalls, moved))
        } else {
            fleet.append(InstallCohort(build: scenario.fixedBuild, activeInstalls: moved))
        }
    }

    static func addSaturating(_ a: Int, _ b: Int) -> Int {
        let (sum, overflow) = a.addingReportingOverflow(b)
        return overflow ? (b > 0 ? Int.max : Int.min) : sum
    }

    private func recomputeExposure() {
        let vulnerable = server.hasDeclaredIncident
            ? [VersionRange(introduced: nil, fixed: scenario.fixedBuild)].compactMap { $0 }
            : []
        exposure = ExposureAnalyzer.report(cohorts: fleet, vulnerable: vulnerable,
                                           minimumCohortSize: scenario.minimumCohortSize)
    }

    private func append(_ title: String, _ detail: String, _ tone: LabLogEntry.Tone) {
        log.insert(LabLogEntry(id: nextLogID, title: title, detail: detail, tone: tone), at: 0)
        nextLogID &+= 1
        if log.count > Self.maxLogEntries { log.removeLast(log.count - Self.maxLogEntries) }
    }

    nonisolated static func describe(_ reason: RejectionReason) -> String {
        switch reason {
        case .verification(let failure): return "Verification failed: \(failure)"
        case .rollback(let offered, let floor): return "Rollback: offered v\(offered), floor is v\(floor)"
        case .equivocation(let version): return "Equivocation at v\(version): both copies' restrictions now enforced"
        case .expired(let version): return "v\(version) already expired by signed time"
        case .implausibleVersionJump(let offered, let floor):
            return "Version jump v\(floor) → v\(offered) is implausible"
        }
    }

    nonisolated static func format(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter.string(from: date)
    }
}
