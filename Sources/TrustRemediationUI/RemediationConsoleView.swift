#if canImport(SwiftUI)
import Observation
import SwiftUI
import TrustRemediation

/// Main-actor view model that mirrors `RemediationLab` into observable state.
@MainActor
@Observable
public final class RemediationConsoleModel {
    public private(set) var snapshot: RemediationSnapshot?
    public private(set) var log: [LabLogEntry] = []
    public private(set) var exposure: ExposureReport?
    public private(set) var build: BuildVersion?
    public private(set) var isNetworkOnline = true
    public private(set) var isBusy = false
    @ObservationIgnored private let lab: RemediationLab?
    @ObservationIgnored private var started = false

    public init(scenario: LabScenario) {
        lab = RemediationLab(scenario: scenario)
        build = lab?.build
    }

    public var isAvailable: Bool { lab != nil }

    public func start() async {
        guard let lab, !started else { return }
        started = true
        isBusy = true
        await lab.start()
        sync(from: lab)
        isBusy = false
    }

    public func perform(_ action: LabAction) async {
        guard let lab, !isBusy else { return }
        isBusy = true
        await lab.run(action)
        sync(from: lab)
        isBusy = false
    }

    private func sync(from lab: RemediationLab) {
        snapshot = lab.snapshot
        log = lab.log
        exposure = lab.exposure
        build = lab.build
        isNetworkOnline = lab.isNetworkOnline
    }
}

/// A console that runs a whole trust incident against the real coordinator:
/// declare it, attack the channel, age the manifest, reboot, ship the fix.
public struct RemediationConsoleView: View {
    /// Owned by the caller (the App), so SwiftUI re-initialising this view never
    /// builds a second lab, key pair and coordinator.
    private let model: RemediationConsoleModel

    public init(model: RemediationConsoleModel) {
        self.model = model
    }

    public var body: some View {
        NavigationStack {
            List {
                if !model.isAvailable {
                    Text("Could not create the demo signing key.")
                        .foregroundStyle(.red)
                }
                policySection
                capabilitiesSection
                exposureSection
                actionsSection
                logSection
            }
            .navigationTitle("Trust Incident")
            .task { await model.start() }
        }
    }

    // MARK: Sections

    private var policySection: some View {
        Section("Policy") {
            LabeledContent("App build", value: model.build.map { "\($0)" } ?? "—")
            LabeledContent("Manifest", value: ConsoleText.status(model.snapshot?.status))
            LabeledContent("Rollback floor", value: model.snapshot.map { "v\($0.versionFloor)" } ?? "—")
            LabeledContent("Trusted time", value: ConsoleText.basis(model.snapshot?.timeBasis))
            LabeledContent("Network", value: model.isNetworkOnline ? "Online" : "Offline")
            if let upgrade = model.snapshot?.upgrade, upgrade != .notNeeded {
                Label(ConsoleText.upgrade(upgrade), systemImage: "arrow.down.app")
                    .foregroundStyle(ConsoleText.isRequired(upgrade) ? .red : .orange)
            }
            if let equivocated = model.snapshot?.equivocatedVersions, !equivocated.isEmpty {
                Label("Equivocation seen at v\(equivocated.map(String.init).joined(separator: ", v"))",
                      systemImage: "exclamationmark.octagon")
                    .foregroundStyle(.red)
            }
        }
    }

    private var capabilitiesSection: some View {
        Section("Capabilities") {
            if let decisions = model.snapshot?.decisions, !decisions.isEmpty {
                ForEach(decisions) { decision in
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(displayName(for: decision.capability)).font(.body)
                            Text(ConsoleText.cause(decision.cause))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(ConsoleText.state(decision.state))
                            .font(.caption.bold())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(ConsoleColors.color(decision.state).opacity(0.18), in: Capsule())
                            .foregroundStyle(ConsoleColors.color(decision.state))
                    }
                }
            } else {
                Text("Waiting for the first evaluation…").foregroundStyle(.secondary)
            }
        }
    }

    private var exposureSection: some View {
        Section("Fleet exposure") {
            if let exposure = model.exposure {
                LabeledContent("Exposed installs",
                               value: "\(exposure.exposedActive) of \(exposure.totalActive)")
                LabeledContent("Exposed share", value: ConsoleText.percent(exposure.exposedBasisPoints))
                ForEach(Array(exposure.buckets.enumerated()), id: \.offset) { _, bucket in
                    LabeledContent(bucket.build.map { "Build \($0)" } ?? "Other (small cohorts)",
                                   value: "\(bucket.activeInstalls)\(ConsoleText.exposureMark(bucket.exposed))")
                }
            }
        }
    }

    private var actionsSection: some View {
        Section("Simulate") {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 8)], spacing: 8) {
                ForEach(LabAction.allCases) { action in
                    Button(action.title) {
                        Task { await model.perform(action) }
                    }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
                    .disabled(model.isBusy)
                }
            }
            .padding(.vertical, 4)
        }
    }

    private var logSection: some View {
        Section("Event log") {
            ForEach(model.log) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.title).font(.callout).foregroundStyle(ConsoleColors.color(entry.tone))
                    if !entry.detail.isEmpty {
                        Text(entry.detail).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func displayName(for capability: String) -> String {
        model.catalogNames[capability] ?? capability
    }
}

extension RemediationConsoleModel {
    var catalogNames: [String: String] {
        guard let lab else { return [:] }
        return Dictionary(lab.scenario.catalog.capabilities.map { ($0.id, $0.displayName) },
                          uniquingKeysWith: { first, _ in first })
    }
}

/// Colours for the console; text lives in `ConsoleText` (platform-agnostic, tested on Linux).
enum ConsoleColors {
    static func color(_ state: CapabilityState) -> Color {
        switch state {
        case .full: return .green
        case .degraded: return .orange
        case .disabled: return .red
        }
    }

    static func color(_ tone: LabLogEntry.Tone) -> Color {
        switch tone {
        case .info: return .primary
        case .good: return .green
        case .warning: return .orange
        case .bad: return .red
        }
    }
}
#endif
