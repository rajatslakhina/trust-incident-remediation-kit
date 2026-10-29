import Crypto
import Foundation
@testable import TrustRemediation
import XCTest

final class VerifierTests: XCTestCase {
    func testValidEnvelopeVerifiesAndRoundTrips() throws {
        let keys = try Fixture.keys()
        let manifest = Fixture.manifest(version: 3, rules: [
            CapabilityRule(id: "r1", capability: "partnerSync", action: .disable,
                           affectedBuilds: [Fixture.range(nil, "4.2.0")], reason: "CA"),
        ])
        let envelope = try keys.signer.sign(manifest)
        let verified = try keys.verifier.verify(envelope).get()
        XCTAssertEqual(verified.manifest, manifest)
        XCTAssertEqual(verified.digest, Data(SHA256.hash(data: envelope.payload)))
    }

    func testEverySingleBitFlipInPayloadIsRejected() throws {
        let keys = try Fixture.keys()
        let envelope = try keys.signer.sign(Fixture.manifest(version: 1))
        // Exhaustive over bytes (one bit each) rather than a single sample flip.
        for offset in 0..<envelope.payload.count {
            var payload = envelope.payload
            let index = payload.startIndex + offset
            payload[index] ^= 0x01
            let tampered = SignedManifestEnvelope(keyID: "k1", payload: payload, signature: envelope.signature)
            guard case .failure(.badSignature) = keys.verifier.verify(tampered) else {
                return XCTFail("flip at byte \(offset) was not rejected as badSignature")
            }
        }
    }

    func testSignatureFromUntrustedKeyIsRejectedEvenWithMatchingKeyID() throws {
        let trusted = try Fixture.keys(id: "k1")
        let attacker = try Fixture.keys(id: "k1") // same id, different key material
        let forged = try attacker.signer.sign(Fixture.manifest(version: 99))
        XCTAssertEqual(trusted.verifier.verify(forged).failure, .badSignature)
    }

    func testUnknownKeyIDIsRejected() throws {
        let trusted = try Fixture.keys(id: "k1")
        let other = try Fixture.keys(id: "k2")
        let envelope = try other.signer.sign(Fixture.manifest(version: 1, keyID: "k2"))
        XCTAssertEqual(trusted.verifier.verify(envelope).failure, .unknownKey("k2"))
    }

    func testPayloadKeyIDMustMatchEnvelopeKeyID() throws {
        let keys = try Fixture.keys(id: "k1")
        // Validly signed by k1, but the payload claims to be for k-old.
        let envelope = try keys.signer.sign(Fixture.manifest(version: 1, keyID: "k-old"))
        XCTAssertEqual(keys.verifier.verify(envelope).failure, .keyMismatch(envelope: "k1", manifest: "k-old"))
    }

    func testRotationAcceptsEitherPinnedKey() throws {
        let old = try XCTUnwrap(ManifestSigner.generate(keyID: "2026-a"))
        let next = try XCTUnwrap(ManifestSigner.generate(keyID: "2026-b"))
        let verifier = ManifestVerifier(trustedKeys: try XCTUnwrap(TrustedKeySet([old.trusted, next.trusted])))
        XCTAssertNoThrow(try verifier.verify(old.signer.sign(Fixture.manifest(version: 1, keyID: "2026-a"))).get())
        XCTAssertNoThrow(try verifier.verify(next.signer.sign(Fixture.manifest(version: 2, keyID: "2026-b"))).get())
    }

    func testStructuralLimits() throws {
        let keys = try Fixture.keys(limits: .init(maxPayloadBytes: 4096, maxRules: 2, maxValidity: 10 * Fixture.day))
        let tooLong = try keys.signer.sign(Fixture.manifest(version: 1, lifetime: 11 * Fixture.day))
        XCTAssertEqual(keys.verifier.verify(tooLong).failure, .invalidValidityWindow)
        let backwards = try keys.signer.sign(Fixture.manifest(version: 1, lifetime: -1))
        XCTAssertEqual(keys.verifier.verify(backwards).failure, .invalidValidityWindow)
        let zero = try keys.signer.sign(Fixture.manifest(version: 1, lifetime: 0))
        XCTAssertEqual(keys.verifier.verify(zero).failure, .invalidValidityWindow)

        let rule = { (id: String) in CapabilityRule(id: id, capability: "x", action: .degrade, reason: "") }
        let many = try keys.signer.sign(Fixture.manifest(version: 1, rules: [rule("a"), rule("b"), rule("c")]))
        XCTAssertEqual(keys.verifier.verify(many).failure, .tooManyRules(3))
        let dupes = try keys.signer.sign(Fixture.manifest(version: 1, rules: [rule("a"), rule("a")]))
        XCTAssertEqual(keys.verifier.verify(dupes).failure, .duplicateRuleID("a"))

        let huge = try keys.signer.sign(payload: Data(repeating: 0x20, count: 4097))
        XCTAssertEqual(keys.verifier.verify(huge).failure, .oversizedPayload(bytes: 4097))
    }

    func testSignedGarbageAndFutureSchemaAreRejected() throws {
        let keys = try Fixture.keys()
        XCTAssertEqual(keys.verifier.verify(try keys.signer.sign(payload: Data("not json".utf8))).failure,
                       .malformedPayload)
        let future = SecurityManifest(schemaVersion: 2, version: 1, keyID: "k1", issuedAt: Fixture.t0,
                                      expiresAt: Fixture.t0.addingTimeInterval(Fixture.day), rules: [])
        XCTAssertEqual(keys.verifier.verify(try keys.signer.sign(future)).failure, .unsupportedSchema(2))
        // An empty affected range inside a signed manifest is malformed, not "matches nothing".
        let emptyRange = Data(#"{"advisories":[],"expiresAt":"2026-10-30T00:00:00Z","issuedAt":"2026-10-29T00:00:00Z","keyID":"k1","rules":[{"action":"disable","affectedBuilds":[{"fixed":"1.0.0","introduced":"2.0.0"}],"capability":"x","id":"r","reason":""}],"schemaVersion":1,"version":1}"#.utf8)
        XCTAssertEqual(keys.verifier.verify(try keys.signer.sign(payload: emptyRange)).failure, .malformedPayload)
    }

    func testKeySetRejectsEmptyAndDuplicates() throws {
        let pair = try XCTUnwrap(ManifestSigner.generate(keyID: "k"))
        XCTAssertNil(TrustedKeySet([]))
        XCTAssertNil(TrustedKeySet([pair.trusted, pair.trusted]))
        XCTAssertNil(TrustedKey(keyID: "k", rawPublicKey: Data([1, 2, 3])))
        XCTAssertNil(TrustedKey(keyID: "", rawPublicKey: pair.trusted.rawPublicKey))
    }
}

extension Result {
    var failure: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}
