import Foundation
@testable import TrustRemediation
import XCTest

final class SaturatingTests: XCTestCase {
    func testAddSaturatesBothWays() {
        XCTAssertEqual(Saturating.add(Int.max, 1), Int.max)
        XCTAssertEqual(Saturating.add(Int.min, -1), Int.min)
        XCTAssertEqual(Saturating.add(2, 3), 5)
    }

    func testMultiplySaturatesBySign() {
        XCTAssertEqual(Saturating.multiply(Int.max, 2), Int.max)
        XCTAssertEqual(Saturating.multiply(Int.max, -2), Int.min)
        XCTAssertEqual(Saturating.multiply(Int.min, -1), Int.max)
        XCTAssertEqual(Saturating.multiply(-4, 5), -20)
    }

    func testDivideGuardsZeroAndMinOverMinusOne() {
        XCTAssertNil(Saturating.divide(10, 0))
        XCTAssertEqual(Saturating.divide(Int.min, -1), Int.max)
        XCTAssertEqual(Saturating.divide(-9, 2), -4)
    }

    func testDoubleConversionRejectsNonFiniteAndOutOfRange() {
        XCTAssertNil(Saturating.int(.nan))
        XCTAssertNil(Saturating.int(.infinity))
        XCTAssertNil(Saturating.int(-.infinity))
        XCTAssertNil(Saturating.int(Double(Int.max)), "Double(Int.max) rounds up out of range")
        XCTAssertNil(Saturating.int(-Double(Int.max) * 4))
        XCTAssertEqual(Saturating.int(-3.9), -3)
    }

    func testBasisPointsNeverOverflowAndClamp() {
        XCTAssertNil(Saturating.basisPoints(1, of: 0))
        XCTAssertNil(Saturating.basisPoints(1, of: -5))
        XCTAssertEqual(Saturating.basisPoints(Int.max, of: Int.max), 10_000)
        XCTAssertEqual(Saturating.basisPoints(Int.max / 2, of: Int.max), 4_999)
        XCTAssertEqual(Saturating.basisPoints(1, of: 3), 3_333)
        XCTAssertEqual(Saturating.basisPoints(7, of: 3), 10_000, "part > whole clamps")
        XCTAssertEqual(Saturating.basisPoints(-7, of: 3), 0, "negative part clamps")
    }
}

final class BuildVersionTests: XCTestCase {
    func testParsesShortAndFullForms() {
        XCTAssertEqual(BuildVersion("4"), BuildVersion(major: 4))
        XCTAssertEqual(BuildVersion("4.2"), BuildVersion(major: 4, minor: 2))
        XCTAssertEqual(BuildVersion(" 4.2.1 "), BuildVersion(major: 4, minor: 2, patch: 1))
    }

    func testRejectsGarbageWithoutTrapping() {
        for bad in ["", ".", "4.", ".4", "4..1", "4.x", "-1", "+1", "1.2.3.4", "١.٢", "99999999999999999999",
                    "1234567890", "4.2-beta", " "] {
            XCTAssertNil(BuildVersion(bad), "should reject \(bad.debugDescription)")
        }
        XCTAssertNil(BuildVersion(major: -1))
        XCTAssertNil(BuildVersion(major: 1, minor: Int.max))
        XCTAssertNotNil(BuildVersion("999999999.999999999.999999999"))
    }

    func testOrderingIsNumericNotLexical() {
        XCTAssertLessThan(Fixture.version("4.9.0"), Fixture.version("4.10.0"))
        XCTAssertLessThan(Fixture.version("4.2"), Fixture.version("4.2.1"))
        XCTAssertEqual(Fixture.version("4.2"), Fixture.version("4.2.0"))
    }

    func testRangeIsHalfOpenAndRejectsEmpty() {
        let range = Fixture.range("4.0.0", "4.2.0")
        XCTAssertFalse(range.contains(Fixture.version("3.9.9")))
        XCTAssertTrue(range.contains(Fixture.version("4.0.0")))
        XCTAssertTrue(range.contains(Fixture.version("4.1.9")))
        XCTAssertFalse(range.contains(Fixture.version("4.2.0")))
        XCTAssertNil(VersionRange(introduced: Fixture.version("4.2"), fixed: Fixture.version("4.2")))
        XCTAssertNil(VersionRange(introduced: Fixture.version("5"), fixed: Fixture.version("4")))
        XCTAssertTrue(Fixture.range(nil, nil).contains(Fixture.version("0")))
    }

    func testEmptyRangeIsRejectedAtDecodeTime() {
        let json = Data(#"{"introduced":"4.2.0","fixed":"4.1.0"}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(VersionRange.self, from: json))
        let ok = Data(#"{"fixed":"4.2.0"}"#.utf8)
        XCTAssertEqual(try JSONDecoder().decode(VersionRange.self, from: ok), Fixture.range(nil, "4.2.0"))
    }
}
