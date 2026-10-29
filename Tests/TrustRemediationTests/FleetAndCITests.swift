import Foundation
@testable import TrustRemediation
import XCTest

final class ExposureTests: XCTestCase {
    private let vulnerable = [Fixture.range(nil, "4.2.0")]

    func testExposedShareAndKAnonymousBuckets() {
        let report = ExposureAnalyzer.report(cohorts: [
            InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: 600),
            InstallCohort(build: Fixture.version("4.2.0"), activeInstalls: 380),
            InstallCohort(build: Fixture.version("4.0.0"), activeInstalls: 12),  // < k
            InstallCohort(build: Fixture.version("9.9.9"), activeInstalls: 8),   // < k (internal build)
        ], vulnerable: vulnerable, minimumCohortSize: 50)
        XCTAssertEqual(report.totalActive, 1000)
        XCTAssertEqual(report.exposedActive, 612)
        XCTAssertEqual(report.exposedBasisPoints, 6120)
        XCTAssertEqual(report.buckets.map(\.build), [Fixture.version("4.1.0"), Fixture.version("4.2.0"), nil])
        XCTAssertEqual(report.buckets.last?.activeInstalls, 20)
        XCTAssertNil(report.buckets.last?.exposed, "merged bucket withholds exposure")
        XCTAssertEqual(report.suppressedCohorts, 2)
    }

    func testEmptyZeroAndNegativeInputsDoNotTrap() {
        let empty = ExposureAnalyzer.report(cohorts: [], vulnerable: vulnerable, minimumCohortSize: 0)
        XCTAssertEqual(empty.totalActive, 0)
        XCTAssertNil(empty.exposedBasisPoints, "no denominator, no percentage")
        XCTAssertTrue(empty.buckets.isEmpty)

        let odd = ExposureAnalyzer.report(cohorts: [
            InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: -5),
            InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: 0),
        ], vulnerable: vulnerable, minimumCohortSize: -3)
        XCTAssertEqual(odd.totalActive, 0)
        XCTAssertNil(odd.exposedBasisPoints)
    }

    func testHugeCountsSaturateInsteadOfOverflowing() {
        let report = ExposureAnalyzer.report(cohorts: [
            InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: Int.max),
            InstallCohort(build: Fixture.version("4.1.1"), activeInstalls: Int.max),
            InstallCohort(build: Fixture.version("4.2.0"), activeInstalls: Int.max),
        ], vulnerable: vulnerable, minimumCohortSize: 1)
        XCTAssertEqual(report.totalActive, Int.max)
        XCTAssertEqual(report.exposedBasisPoints, 10_000)
    }

    func testDuplicateBuildsMergeAndTiesOrderDeterministically() {
        let report = ExposureAnalyzer.report(cohorts: [
            InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: 50),
            InstallCohort(build: Fixture.version("4.3.0"), activeInstalls: 100),
            InstallCohort(build: Fixture.version("4.1.0"), activeInstalls: 50),
        ], vulnerable: vulnerable, minimumCohortSize: 1)
        XCTAssertEqual(report.buckets.map(\.build), [Fixture.version("4.3.0"), Fixture.version("4.1.0")])
    }
}

final class AdvisoryGateTests: XCTestCase {
    private let resolvedV2 = Data(#"""
    {
      "pins" : [
        { "identity" : "firebase-ios-sdk", "kind" : "remoteSourceControl",
          "location" : "https://github.com/firebase/firebase-ios-sdk",
          "state" : { "revision" : "abc", "version" : "12.19.2" } },
        { "identity" : "grpc-binary", "kind" : "remoteSourceControl",
          "location" : "https://github.com/google/grpc-binary",
          "state" : { "branch" : "main", "revision" : "def" } },
        { "identity" : "swift-log", "kind" : "remoteSourceControl",
          "location" : "https://github.com/apple/swift-log",
          "state" : { "revision" : "123", "version" : "1.6.1" } }
      ],
      "version" : 2
    }
    """#.utf8)

    private var advisories: [PackageAdvisory] {
        [
            PackageAdvisory(id: "ADV-1", package: "Firebase-iOS-SDK", affected: [Fixture.range(nil, "12.19.3")],
                            severity: .critical, summary: "Embedded compromised root"),
            PackageAdvisory(id: "ADV-2", package: "grpc-binary", affected: [Fixture.range(nil, "1.70.0")],
                            severity: .high, summary: "Embedded root bundle"),
            PackageAdvisory(id: "ADV-3", package: "swift-log", affected: [Fixture.range("1.0.0", "1.2.0")],
                            severity: .low, summary: "Not affected at 1.6.1"),
        ]
    }

    func testFindsAffectedAndUnassessablePinsAndFailsClosed() throws {
        let pins = try PackageResolvedParser.parse(resolvedV2)
        XCTAssertEqual(pins.count, 3)
        let verdict = AdvisoryGate.evaluate(pins: pins, advisories: advisories, failAt: .high)
        XCTAssertFalse(verdict.passed)
        XCTAssertEqual(verdict.findings.map(\.advisoryID), ["ADV-1", "ADV-2"])
        XCTAssertEqual(verdict.findings.first?.kind, .affected(version: Fixture.version("12.19.2")))
        XCTAssertEqual(verdict.findings.last?.kind, .unassessable, "branch pin can't be proven safe")
    }

    func testFixedVersionPasses() throws {
        let fixed = String(decoding: resolvedV2, as: UTF8.self)
            .replacingOccurrences(of: "12.19.2", with: "12.19.3")
            .replacingOccurrences(of: #""branch" : "main", "revision" : "def""#, with: #""revision" : "def", "version" : "1.70.0""#)
        let verdict = AdvisoryGate.evaluate(pins: try PackageResolvedParser.parse(Data(fixed.utf8)),
                                            advisories: advisories, failAt: .low)
        XCTAssertTrue(verdict.passed)
        XCTAssertTrue(verdict.findings.isEmpty)
    }

    func testThresholdOnlyGatesSeverity() throws {
        let pins = try PackageResolvedParser.parse(resolvedV2)
        let verdict = AdvisoryGate.evaluate(pins: pins, advisories: advisories, failAt: .critical)
        XCTAssertEqual(verdict.failingFindings.map(\.advisoryID), ["ADV-1"])
        XCTAssertEqual(verdict.findings.count, 2)
    }

    func testParsesVersionOneAndRejectsUnknownFormats() throws {
        let v1 = Data(#"{"object":{"pins":[{"package":"Firebase","repositoryURL":"https://github.com/firebase/firebase-ios-sdk.git","state":{"branch":null,"revision":"a","version":"12.19.2"}}]},"version":1}"#.utf8)
        let pins = try PackageResolvedParser.parse(v1)
        XCTAssertEqual(pins, [ResolvedPin(identity: "firebase-ios-sdk", version: Fixture.version("12.19.2"), revision: "a")],
                       "v1 stores the manifest name; identity must come from the URL")
        XCTAssertFalse(AdvisoryGate.evaluate(pins: pins, advisories: advisories, failAt: .high).passed,
                       "a v1 file must not fail open")
        XCTAssertThrowsError(try PackageResolvedParser.parse(Data(#"{"version":9,"pins":[]}"#.utf8))) {
            XCTAssertEqual($0 as? PackageResolvedError, .unsupportedFormat(9))
        }
        XCTAssertThrowsError(try PackageResolvedParser.parse(Data("[]".utf8))) {
            XCTAssertEqual($0 as? PackageResolvedError, .malformed)
        }
        XCTAssertThrowsError(try PackageResolvedParser.parse(Data(#"{"version":2}"#.utf8))) {
            XCTAssertEqual($0 as? PackageResolvedError, .malformed)
        }
    }

    func testIdentityFromURLMatchesSwiftPMRules() {
        XCTAssertEqual(PackageResolvedParser.identity(fromURL: "https://github.com/apple/swift-log.git"), "swift-log")
        XCTAssertEqual(PackageResolvedParser.identity(fromURL: "https://github.com/apple/swift-log/"), "swift-log")
        XCTAssertEqual(PackageResolvedParser.identity(fromURL: "git@github.com:org/Repo.GIT"), "Repo")
        XCTAssertEqual(PackageResolvedParser.identity(fromURL: ".git"), "")
        XCTAssertEqual(PackageResolvedParser.identity(fromURL: ""), "")
    }

    func testAdvisoryWithNoRangesCoversEveryVersion() throws {
        let everything = PackageAdvisory(id: "ADV-X", package: "swift-log", affected: [], severity: .high, summary: "")
        let verdict = AdvisoryGate.evaluate(pins: try PackageResolvedParser.parse(resolvedV2),
                                            advisories: [everything], failAt: .high)
        XCTAssertEqual(verdict.failingFindings.map(\.advisoryID), ["ADV-X"], "missing ranges fail closed")
    }

    func testNoPinsOrNoAdvisoriesPass() {
        XCTAssertTrue(AdvisoryGate.evaluate(pins: [], advisories: advisories, failAt: .low).passed)
        XCTAssertTrue(AdvisoryGate.evaluate(pins: [ResolvedPin(identity: "x", version: nil, revision: nil)],
                                            advisories: [], failAt: .low).passed)
    }
}
