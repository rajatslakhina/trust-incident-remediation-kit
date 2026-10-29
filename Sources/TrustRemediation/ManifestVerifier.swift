import Crypto
import Foundation

/// A pinned Ed25519 verification key, compiled into the binary.
///
/// Stored as raw bytes (validated once at construction) so the type is trivially
/// `Sendable` regardless of how the crypto library annotates its key types.
public struct TrustedKey: Sendable, Equatable {
    public let keyID: String
    public let rawPublicKey: Data

    public init?(keyID: String, rawPublicKey: Data) {
        guard !keyID.isEmpty,
              (try? Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey)) != nil
        else { return nil }
        self.keyID = keyID
        self.rawPublicKey = rawPublicKey
    }
}

/// The set of keys the binary trusts. More than one key is how rotation works:
/// ship the next key in a release *before* the signer switches to it.
public struct TrustedKeySet: Sendable, Equatable {
    public let keys: [TrustedKey]

    /// `nil` for an empty set or duplicate key ids (ambiguous lookups are a bug).
    public init?(_ keys: [TrustedKey]) {
        guard !keys.isEmpty, Set(keys.map(\.keyID)).count == keys.count else { return nil }
        self.keys = keys
    }

    func key(for keyID: String) -> TrustedKey? { keys.first { $0.keyID == keyID } }
}

public enum VerificationFailure: Error, Equatable, Sendable {
    case oversizedPayload(bytes: Int)
    case unknownKey(String)
    case badSignature
    case malformedPayload
    case keyMismatch(envelope: String, manifest: String)
    case unsupportedSchema(Int)
    case invalidValidityWindow
    case tooManyRules(Int)
    case duplicateRuleID(String)
}

/// A manifest that passed every check in `ManifestVerifier`.
///
/// The initializer is internal: code outside this module cannot fabricate a
/// "verified" manifest, so every function that takes one is guaranteed it was checked
/// (parse, don't validate).
public struct VerifiedManifest: Sendable, Equatable {
    public let manifest: SecurityManifest
    public let envelope: SignedManifestEnvelope
    /// SHA-256 of the signed payload. Two different digests at one version is
    /// equivocation, which the ledger treats as a signing-pipeline incident.
    public let digest: Data

    init(manifest: SecurityManifest, envelope: SignedManifestEnvelope, digest: Data) {
        self.manifest = manifest
        self.envelope = envelope
        self.digest = digest
    }
}

public struct ManifestVerifier: Sendable {
    public struct Limits: Sendable, Equatable {
        public var maxPayloadBytes: Int
        public var maxRules: Int
        /// Caps how long one signature stays usable, which bounds the replay window
        /// for anyone holding an old, validly signed manifest.
        public var maxValidity: TimeInterval

        public init(maxPayloadBytes: Int = 256 * 1024, maxRules: Int = 512,
                    maxValidity: TimeInterval = 30 * 24 * 3600) {
            self.maxPayloadBytes = maxPayloadBytes
            self.maxRules = maxRules
            self.maxValidity = maxValidity
        }
    }

    public let trustedKeys: TrustedKeySet
    public let limits: Limits

    public init(trustedKeys: TrustedKeySet, limits: Limits = Limits()) {
        self.trustedKeys = trustedKeys
        self.limits = limits
    }

    /// Checks run cheapest-first, and nothing is decoded until the signature holds:
    /// an attacker who can reach the parser without a valid signature gets a larger
    /// attack surface for free.
    public func verify(_ envelope: SignedManifestEnvelope) -> Result<VerifiedManifest, VerificationFailure> {
        guard envelope.payload.count <= limits.maxPayloadBytes else {
            return .failure(.oversizedPayload(bytes: envelope.payload.count))
        }
        guard let key = trustedKeys.key(for: envelope.keyID) else {
            return .failure(.unknownKey(envelope.keyID))
        }
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: key.rawPublicKey),
              publicKey.isValidSignature(envelope.signature, for: envelope.payload) else {
            return .failure(.badSignature)
        }
        guard let manifest = try? ManifestCoding.decoder().decode(SecurityManifest.self, from: envelope.payload) else {
            return .failure(.malformedPayload)
        }
        guard manifest.keyID == envelope.keyID else {
            return .failure(.keyMismatch(envelope: envelope.keyID, manifest: manifest.keyID))
        }
        guard manifest.schemaVersion == SecurityManifest.supportedSchemaVersion else {
            return .failure(.unsupportedSchema(manifest.schemaVersion))
        }
        let window = manifest.expiresAt.timeIntervalSince(manifest.issuedAt)
        guard window.isFinite, window > 0, window <= limits.maxValidity else {
            return .failure(.invalidValidityWindow)
        }
        guard manifest.rules.count <= limits.maxRules else {
            return .failure(.tooManyRules(manifest.rules.count))
        }
        var seen = Set<String>()
        for rule in manifest.rules where !seen.insert(rule.id).inserted {
            return .failure(.duplicateRuleID(rule.id))
        }
        let digest = Data(SHA256.hash(data: envelope.payload))
        return .success(VerifiedManifest(manifest: manifest, envelope: envelope, digest: digest))
    }
}

/// Signs manifests. Used by tests, the demo's in-process "server", and any Swift
/// backend that issues manifests; the app binary itself only ever verifies.
public struct ManifestSigner: Sendable {
    public let keyID: String
    private let rawPrivateKey: Data

    public init?(keyID: String, rawPrivateKey: Data) {
        guard !keyID.isEmpty,
              (try? Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey)) != nil
        else { return nil }
        self.keyID = keyID
        self.rawPrivateKey = rawPrivateKey
    }

    /// A fresh random key pair, for tests and demos.
    public static func generate(keyID: String) -> (signer: ManifestSigner, trusted: TrustedKey)? {
        let key = Curve25519.Signing.PrivateKey()
        guard let signer = ManifestSigner(keyID: keyID, rawPrivateKey: key.rawRepresentation),
              let trusted = TrustedKey(keyID: keyID, rawPublicKey: key.publicKey.rawRepresentation)
        else { return nil }
        return (signer, trusted)
    }

    public func sign(_ manifest: SecurityManifest) throws -> SignedManifestEnvelope {
        let payload = try ManifestCoding.encoder().encode(manifest)
        return try sign(payload: payload)
    }

    /// Signs arbitrary bytes. Exposed so tests can build envelopes the encoder never
    /// would (malformed JSON, mismatched key ids).
    public func sign(payload: Data) throws -> SignedManifestEnvelope {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
        let signature = try key.signature(for: payload)
        return SignedManifestEnvelope(keyID: keyID, payload: payload, signature: signature)
    }
}
