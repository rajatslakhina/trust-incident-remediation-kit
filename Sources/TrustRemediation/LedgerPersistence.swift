import Foundation

/// File-backed ledger storage: one JSON document, replaced atomically.
public struct FileLedgerPersistence: LedgerPersistence {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public func load() throws -> PersistedLedgerState? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        // A file that exists but can't be read or decoded throws, which puts the
        // ledger in its never-overwrite mode. Before first unlock on iOS, a protected
        // file is unreadable; treating that as "empty" would wipe the floor.
        let data = try Data(contentsOf: url)
        return try ManifestCoding.decoder().decode(PersistedLedgerState.self, from: data)
    }

    public func save(_ state: PersistedLedgerState) throws {
        let data = try ManifestCoding.encoder().encode(state)
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        #if os(iOS)
        // Readable after first unlock so background refresh can enforce policy.
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: url, options: [.atomic])
        #endif
    }
}

/// In-memory storage with fault injection, for tests and the demo's relaunch button.
public final class InMemoryLedgerPersistence: LedgerPersistence, @unchecked Sendable {
    // @unchecked: every stored property is read and written only while holding `lock`.
    private let lock = NSLock()
    private var stored: PersistedLedgerState?
    private var loadError: Error?
    private var saveError: Error?
    private var saves = 0

    public init(initial: PersistedLedgerState? = nil) {
        stored = initial
    }

    public func load() throws -> PersistedLedgerState? {
        lock.lock()
        defer { lock.unlock() }
        if let loadError { throw loadError }
        return stored
    }

    public func save(_ state: PersistedLedgerState) throws {
        lock.lock()
        defer { lock.unlock() }
        if let saveError { throw saveError }
        stored = state
        saves = Saturating.add(saves, 1)
    }

    public var snapshot: PersistedLedgerState? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    public var saveCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return saves
    }

    public func failLoads(with error: Error?) {
        lock.lock()
        defer { lock.unlock() }
        loadError = error
    }

    public func failSaves(with error: Error?) {
        lock.lock()
        defer { lock.unlock() }
        saveError = error
    }
}
