import Foundation
import TrustRemediation
@testable import TrustRemediationUI
import XCTest

/// Drives the exact script the demo console's buttons run, and checks that each
/// headline interaction visibly changes what the console shows.
@MainActor
enum LabScripts {
    static func scenario() throws -> LabScenario {
        let catalog = try XCTUnwrap(CapabilityCatalog([
            CapabilityDescriptor(id: "partnerSync", displayName: "Partner sync", trustPath: .embeddedTrustStore),
            CapabilityDescriptor(id: "crashReports", displayName: "Crash reports", trustPath: .embeddedTrustStore,
                                 blockedWhenUpgradeRequired: false),
            CapabilityDescriptor(id: "photoBackup", displayName: "Photo backup", trustPath: .systemTrust),
        ]))
        let vulnerable = [Fixture.range(nil, "4.2.0")]
        return LabScenario(
            catalog: catalog, vulnerableBuild: Fixture.version("4.1.0"), fixedBuild: Fixture.version("4.2.0"),
            incidentRules: [
                CapabilityRule(id: "CA-1", capability: "partnerSync", action: .disable,
                               affectedBuilds: vulnerable, reason: "SDK trusts a compromised root"),
                CapabilityRule(id: "CA-2", capability: "crashReports", action: .degrade,
                               affectedBuilds: vulnerable, reason: "Buffer locally"),
            ],
            hardEnforcementAfterDays: 3,
            initialFleet: [
                InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: 6_000),
                InstallCohort(build: Fixture.version("4.0.2"), activeInstalls: 1_500),
                InstallCohort(build: Fixture.version("5.0.0"), activeInstalls: 9),
            ],
            minimumCohortSize: 50)
    }

    static func state(_ lab: RemediationLab, _ capability: String) -> CapabilityState? {
        lab.snapshot?.decision(for: capability)?.state
    }

    static func testFullIncidentScript() async throws {
        let lab = try XCTUnwrap(RemediationLab(scenario: try Self.scenario()))
        await lab.start()
        XCTAssertEqual(lab.snapshot?.versionFloor, 1)
        XCTAssertEqual(Self.state(lab, "partnerSync"), .full, "baseline manifest vouches for the path")

        await lab.run(.declareIncident)
        XCTAssertEqual(lab.snapshot?.versionFloor, 2)
        XCTAssertEqual(Self.state(lab, "partnerSync"), .disabled)
        XCTAssertEqual(Self.state(lab, "crashReports"), .degraded)
        XCTAssertEqual(Self.state(lab, "photoBackup"), .full)
        guard case .recommended(_, let deadline?) = lab.snapshot?.upgrade else { return XCTFail("staged upgrade") }
        XCTAssertEqual(deadline, lab.serverNow.addingTimeInterval(3 * Fixture.day))
        XCTAssertEqual(lab.exposure.exposedActive, 7_500)

        await lab.run(.replayOldManifest)
        XCTAssertEqual(lab.log.first?.tone, .bad)
        XCTAssertTrue(lab.log.first?.detail.contains("Rollback") ?? false)
        XCTAssertEqual(Self.state(lab, "partnerSync"), .disabled, "replay did not lift the block")

        await lab.run(.tamperInTransit)
        XCTAssertTrue(lab.log.first?.detail.contains("badSignature") ?? false)

        await lab.run(.equivocate)
        XCTAssertEqual(lab.snapshot?.equivocatedVersions, [2])
        XCTAssertEqual(Self.state(lab, "partnerSync"), .disabled, "the unrestricted fork was not applied")

        await lab.run(.advanceEightDays)
        guard case .stale = lab.snapshot?.status else { return XCTFail("manifest should be stale") }
        XCTAssertEqual(lab.snapshot?.upgrade, .required(target: Fixture.version("4.2.0")))
        XCTAssertEqual(Self.state(lab, "photoBackup"), .full, "local-first feature survives hard enforcement")
        XCTAssertLessThan(lab.exposure.exposedActive, 7_500, "simulated adoption moves the fleet")

        await lab.run(.setPhoneClockBackTenDays)
        XCTAssertEqual(lab.snapshot?.upgrade, .required(target: Fixture.version("4.2.0")))

        await lab.run(.rebootDevice)
        XCTAssertEqual(lab.snapshot?.timeBasis, .flooredWallClock)
        XCTAssertEqual(lab.snapshot?.upgrade, .required(target: Fixture.version("4.2.0")),
                       "reboot + clock rollback can't escape the deadline")

        await lab.run(.installFixedBuild)
        XCTAssertEqual(lab.build, Fixture.version("4.2.0"))
        XCTAssertEqual(lab.snapshot?.upgrade, .notNeeded)
        XCTAssertEqual(Self.state(lab, "partnerSync"), .full)

        await lab.run(.allClear)
        XCTAssertEqual(lab.snapshot?.decisions.allSatisfy { $0.state == .full }, true)
    }

    static func testOfflineFirstLaunchHoldsTheSafePosture() async throws {
        let lab = try XCTUnwrap(RemediationLab(scenario: try Self.scenario()))
        await lab.run(.toggleNetwork)
        await lab.start()
        XCTAssertEqual(lab.snapshot?.status, ManifestStatus.absent)
        XCTAssertEqual(Self.state(lab, "partnerSync"), .degraded)
        XCTAssertEqual(Self.state(lab, "photoBackup"), .full)
        await lab.run(.tamperInTransit)
        XCTAssertEqual(lab.log.first?.title, "Tamper in transit needs the network")
    }

    static func testReplayBeforeAnyHistoryIsANoOp() async throws {
        let lab = try XCTUnwrap(RemediationLab(scenario: try Self.scenario()))
        await lab.start()
        await lab.run(.replayOldManifest)
        XCTAssertTrue(lab.log.contains { $0.title == "Nothing to replay yet" })
        XCTAssertEqual(lab.snapshot?.versionFloor, 1)
    }

    static func testOverlappingActionsAreSerialized() async throws {
        let lab = try XCTUnwrap(RemediationLab(scenario: try Self.scenario()))
        await lab.start()
        async let first: Void = lab.run(.declareIncident)
        async let second: Void = lab.run(.rebootDevice)
        _ = await (first, second)
        XCTAssertTrue(lab.log.contains { $0.title.hasSuffix("ignored") }, "one action must be refused while the other runs")
        XCTAssertFalse(lab.isRunning)
    }

    static func testLogIsBounded() async throws {
        let lab = try XCTUnwrap(RemediationLab(scenario: try Self.scenario()))
        await lab.start()
        for _ in 0..<80 { await lab.run(.refresh) }
        XCTAssertEqual(lab.log.count, RemediationLab.maxLogEntries)
    }
}

final class LabTests: XCTestCase {
    func testFullIncidentScript() async throws { try await LabScripts.testFullIncidentScript() }
    func testOfflineFirstLaunchHoldsTheSafePosture() async throws { try await LabScripts.testOfflineFirstLaunchHoldsTheSafePosture() }
    func testReplayBeforeAnyHistoryIsANoOp() async throws { try await LabScripts.testReplayBeforeAnyHistoryIsANoOp() }
    func testOverlappingActionsAreSerialized() async throws { try await LabScripts.testOverlappingActionsAreSerialized() }
    func testLogIsBounded() async throws { try await LabScripts.testLogIsBounded() }
}
