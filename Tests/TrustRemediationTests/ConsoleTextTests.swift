import Foundation
import TrustRemediation
import TrustRemediationUI
import XCTest

/// `ConsoleText` is what the SwiftUI console prints. It lives outside the SwiftUI
/// `#if` precisely so it is compiled and checked on Linux too.
final class ConsoleTextTests: XCTestCase {
    func testRendersEveryCase() throws {
        XCTAssertEqual(ConsoleText.status(nil), "None verified")
        XCTAssertEqual(ConsoleText.status(.absent), "None verified")
        let keys = try Fixture.keys()
        let verified = try keys.verifier.verify(keys.signer.sign(Fixture.manifest(version: 3))).get()
        XCTAssertEqual(ConsoleText.status(.fresh(verified)), "v3 · fresh")
        XCTAssertEqual(ConsoleText.status(.stale(verified)), "v3 · stale (kept)")
        XCTAssertEqual(ConsoleText.basis(.flooredWallClock), "Wall clock (floored)")
        XCTAssertEqual(ConsoleText.upgrade(.required(target: Fixture.version("4.2"))), "Update to 4.2.0 required")
        XCTAssertEqual(ConsoleText.upgrade(.recommended(target: Fixture.version("4.2"), enforcedFrom: Fixture.t0)),
                       "Update to 4.2.0 recommended — required from 2026-10-29")
        XCTAssertEqual(ConsoleText.cause(.rule(id: "CA-1", reason: "x")), "CA-1: x")
        XCTAssertEqual(ConsoleText.percent(nil), "—")
        XCTAssertEqual(ConsoleText.percent(9988), "99.88%")
        XCTAssertEqual(ConsoleText.percent(5), "0.05%")
        XCTAssertEqual(ConsoleText.exposureMark(nil), " · withheld")
    }
}
