import Foundation

@MainActor
final class SandboxStore: ToolFileStorage {
    static let shared = SandboxStore()
    private static let ordinaryDataMaximumBytes = 512_000
    private static let maximumReceiptCollectionBytes = 100 * 64_000
    private var root: URL?
    private var scoped = false
    private let manager = FileManager.default
    private let encoder = JSONEncoder()
    private init() { encoder.outputFormatting = [.prettyPrinted, .sortedKeys] }
    var connected: Bool { root != nil }
    var folderName: String { root == nil ? "Not prepared" : scoped ? (root?.lastPathComponent ?? "Selected folder") : "On this iPhone" }
    var backgroundRequiresNetworkConnectivity: Bool { scoped }
    func connect(_ url: URL) throws {
        guard url.startAccessingSecurityScopedResource() else { throw SandboxError.blocked("FOLDER_PERMISSION_REQUIRED") }
        defer { url.stopAccessingSecurityScopedResource() }
        let bookmark = try url.bookmarkData(options: .minimalBookmark, includingResourceValuesForKeys: nil, relativeTo: nil)
        UserDefaults.standard.set(bookmark, forKey: "sandboxBookmark")
        scoped = true
        root = url.standardizedFileURL
        for name in ["config", "workspace", "state", "logs", "output"] {
            try manager.createDirectory(at: url.appendingPathComponent(name), withIntermediateDirectories: true)
        }
    }
    func restore() throws {
        guard Keychain.get("appleUser") != nil else { return }
        guard let data = UserDefaults.standard.data(forKey: "sandboxBookmark") else { try useLocal(); return }
        var stale = false
        let url = try URL(resolvingBookmarkData: data, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
        try connect(url)
    }
    func useLocal() throws {
        guard let user = Keychain.get("appleUser") else { throw SandboxError.blocked("Sign in with Apple first.") }
        let base = try manager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directoryName = try NativeLocalWorkspaceBindingVault.live.directoryName(accountBinding: user)
        let folder = base.appendingPathComponent("LocalSandbox").appendingPathComponent(directoryName)
        for name in ["config", "workspace", "state", "logs", "output"] {
            try manager.createDirectory(at: folder.appendingPathComponent(name), withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        }
        root = folder; scoped = false
        UserDefaults.standard.removeObject(forKey: "sandboxBookmark")
    }
    func disconnect() { root = nil; UserDefaults.standard.removeObject(forKey: "sandboxBookmark") }
    private func access<T>(_ operation: (URL) throws -> T) throws -> T {
        guard Keychain.get("appleUser") != nil, let root else { throw SandboxError.blocked("Sign in and prepare your workspace first.") }
        if scoped && !root.startAccessingSecurityScopedResource() { throw SandboxError.blocked("FOLDER_PERMISSION_REQUIRED") }
        defer { if scoped { root.stopAccessingSecurityScopedResource() } }
        return try operation(root)
    }
    private func resolve(_ path: SandboxPath, under root: URL) throws -> URL {
        let base = root.resolvingSymlinksInPath().standardizedFileURL
        let target = base.appendingPathComponent(path.value).resolvingSymlinksInPath().standardizedFileURL
        guard target.path.hasPrefix(base.path + "/") else { throw SandboxError.invalid("SYMLINK_OUTSIDE_SANDBOX") }
        return target
    }
    func read(_ path: SandboxPath) throws -> String {
        try access { root in
            let url = try resolve(path, under: root)
            var error: NSError?; var output: Result<String, Error>?
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &error) { coordinated in
                output = Result {
                    let size = try coordinated.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= 64000 else { throw SandboxError.invalid("FILE_TOO_LARGE") }
                    return try String(contentsOf: coordinated, encoding: .utf8)
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_READ_UNAVAILABLE") }
            return try output.get()
        }
    }
    func readData(_ path: SandboxPath, maximumBytes: Int) throws -> Data {
        guard (1...Self.ordinaryDataMaximumBytes).contains(maximumBytes) else { throw SandboxError.invalid("INVALID_READ_BOUND") }
        return try readBoundedData(path, maximumBytes: maximumBytes)
    }
    private func readReceiptData(_ path: SandboxPath) throws -> Data {
        guard path.value.hasPrefix("logs/"), path.value.hasSuffix(".json") else {
            throw SandboxError.invalid("INVALID_RECEIPT_PATH")
        }
        return try readBoundedData(path, maximumBytes: ReceiptWireContract.maximumSerializedUTF8Bytes)
    }
    private func readBoundedData(_ path: SandboxPath, maximumBytes: Int) throws -> Data {
        return try access { root in
            let url = try resolve(path, under: root)
            var error: NSError?; var output: Result<Data, Error>?
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &error) { coordinated in
                output = Result {
                    let size = try coordinated.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= maximumBytes else { throw SandboxError.invalid("FILE_TOO_LARGE") }
                    let data = try Data(contentsOf: coordinated, options: [.mappedIfSafe])
                    guard data.count <= maximumBytes else { throw SandboxError.invalid("FILE_TOO_LARGE") }
                    return data
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_READ_UNAVAILABLE") }
            return try output.get()
        }
    }
    func fileByteCount(_ path: SandboxPath) throws -> Int {
        try access { root in
            let url = try resolve(path, under: root)
            var error: NSError?; var output: Result<Int, Error>?
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &error) { coordinated in
                output = Result { try coordinated.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0 }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_READ_UNAVAILABLE") }
            return try output.get()
        }
    }
    func readAutosaveJournal(_ path: SandboxPath) throws -> Data? {
        try validateAutosaveJournalPath(path)
        guard try exists(path) else { return nil }
        return try access { root in
            let url = try resolve(path, under: root)
            var error: NSError?; var output: Result<Data, Error>?
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &error) { coordinated in
                output = Result {
                    let size = try coordinated.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= 512_000 else { throw SandboxError.invalid("AUTOSAVE_JOURNAL_TOO_LARGE") }
                    return try Data(contentsOf: coordinated, options: [.mappedIfSafe])
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("AUTOSAVE_JOURNAL_READ_UNAVAILABLE") }
            return try output.get()
        }
    }

    func writeAutosaveJournal(_ path: SandboxPath, data: Data) throws {
        try validateAutosaveJournalPath(path)
        guard data.count <= 512_000 else { throw SandboxError.invalid("AUTOSAVE_JOURNAL_TOO_LARGE") }
        try access { root in
            let url = try resolve(path, under: root)
            try manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            var error: NSError?; var output: Result<Void, Error>?
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &error) { coordinated in
                output = Result {
                    try data.write(to: coordinated, options: .atomic)
                    if !self.scoped { try self.manager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: coordinated.path) }
                    guard try Data(contentsOf: coordinated) == data else { throw SandboxError.conflict("AUTOSAVE_JOURNAL_READBACK_FAILED") }
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("AUTOSAVE_JOURNAL_WRITE_UNAVAILABLE") }
            try output.get()
        }
    }

    func deleteAutosaveJournal(_ path: SandboxPath) throws {
        try validateAutosaveJournalPath(path)
        try delete(path, expectedSHA256: nil)
    }
    func exists(_ path: SandboxPath) throws -> Bool {
        try access { root in
            let url = try resolve(path, under: root)
            return manager.fileExists(atPath: url.path)
        }
    }
    func write(_ path: SandboxPath, content: String, createOnly: Bool = false, expectedSHA256: String? = nil) throws {
        guard content.utf8.count <= 64000 else { throw SandboxError.invalid("FILE_TOO_LARGE") }
        try access { root in
            let url = try resolve(path, under: root)
            try manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            var error: NSError?; var output: Result<Void, Error>?
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &error) { coordinated in
                output = Result {
                    if createOnly && manager.fileExists(atPath: coordinated.path) { throw SandboxError.conflict("FILE_EXISTS") }
                    if let expectedSHA256 {
                        let actual = try String(contentsOf: coordinated, encoding: .utf8)
                        guard Self.hash(actual) == expectedSHA256 else { throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED") }
                    }
                    try content.write(to: coordinated, atomically: true, encoding: .utf8)
                    if !self.scoped { try self.manager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: coordinated.path) }
                    guard try String(contentsOf: coordinated, encoding: .utf8) == content else { throw SandboxError.conflict("READBACK_FAILED") }
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_WRITE_UNAVAILABLE") }
            try output.get()
        }
    }
    func writeData(
        _ path: SandboxPath,
        data: Data,
        maximumBytes: Int,
        createOnly: Bool = false,
        expectedSHA256: String? = nil
    ) throws {
        guard (1...Self.ordinaryDataMaximumBytes).contains(maximumBytes), data.count <= maximumBytes else {
            throw SandboxError.invalid("FILE_TOO_LARGE")
        }
        try writeBoundedData(path, data: data, maximumBytes: maximumBytes, createOnly: createOnly, expectedSHA256: expectedSHA256)
    }
    private func writeBoundedData(
        _ path: SandboxPath,
        data: Data,
        maximumBytes: Int,
        createOnly: Bool = false,
        expectedSHA256: String? = nil
    ) throws {
        guard data.count <= maximumBytes else { throw SandboxError.invalid("FILE_TOO_LARGE") }
        try access { root in
            let url = try resolve(path, under: root)
            try manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            var error: NSError?; var output: Result<Void, Error>?
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &error) { coordinated in
                output = Result {
                    if createOnly && manager.fileExists(atPath: coordinated.path) { throw SandboxError.conflict("FILE_EXISTS") }
                    if let expectedSHA256 {
                        let actual = try Data(contentsOf: coordinated, options: [.mappedIfSafe])
                        guard NativeDigest.sha256(actual) == expectedSHA256 else {
                            throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED")
                        }
                    }
                    try data.write(to: coordinated, options: .atomic)
                    if !self.scoped {
                        try self.manager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: coordinated.path)
                    }
                    guard try Data(contentsOf: coordinated, options: [.mappedIfSafe]) == data else {
                        throw SandboxError.conflict("READBACK_FAILED")
                    }
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_WRITE_UNAVAILABLE") }
            try output.get()
        }
    }
    func delete(_ path: SandboxPath, expectedSHA256: String?) throws {
        try access { root in
            let url = try resolve(path, under: root)
            var error: NSError?; var output: Result<Void, Error>?
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forDeleting, error: &error) { coordinated in
                output = Result {
                    guard manager.fileExists(atPath: coordinated.path) else { return }
                    if let expectedSHA256 {
                        let actual = try Data(contentsOf: coordinated, options: [.mappedIfSafe])
                        guard NativeDigest.sha256(actual) == expectedSHA256 else { throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED") }
                    }
                    try manager.removeItem(at: coordinated)
                    guard !manager.fileExists(atPath: coordinated.path) else { throw SandboxError.conflict("DELETE_READBACK_FAILED") }
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_DELETE_UNAVAILABLE") }
            try output.get()
        }
    }
    private func validateAutosaveJournalPath(_ path: SandboxPath) throws {
        guard path.value.hasPrefix("state/autosave/"), path.value.hasSuffix(".json") else {
            throw SandboxError.invalid("INVALID_AUTOSAVE_JOURNAL_PATH")
        }
    }
    func list(_ folder: String) throws -> [String] {
        guard ["workspace", "config", "state", "logs", "output"].contains(folder) else { throw SandboxError.invalid("INVALID_FOLDER") }
        return try access { root in
            let directory = root.appendingPathComponent(folder).resolvingSymlinksInPath()
            guard directory.path.hasPrefix(root.resolvingSymlinksInPath().path + "/") else { throw SandboxError.invalid("SYMLINK_OUTSIDE_SANDBOX") }
            return try manager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).prefix(100).map { folder + "/" + $0.lastPathComponent }.sorted()
        }
    }
    func containsRecursively(_ path: SandboxPath, in folder: String) throws -> Bool {
        guard path.value.hasPrefix(folder + "/") else { throw SandboxError.invalid("INVALID_VERIFICATION_FOLDER") }
        let listed = try access { root in
            try SandboxRecursiveIndex.paths(root: root, folder: folder, manager: manager).contains(path.value)
        }
        guard listed else { return false }
        return try exists(path)
    }
    func listWorkspaceFilesRecursively() throws -> [String] {
        try access { root in
            try SandboxRecursiveIndex.regularFilePaths(root: root, folder: "workspace", manager: manager)
        }
    }
    func save<T: Encodable>(_ value: T, path: String) throws { try write(SandboxPath(path), content: String(decoding: encoder.encode(value), as: UTF8.self)) }
    @discardableResult
    func saveReceipt(_ receipt: RunReceipt, path: String) throws -> Data {
        let data = try receipt.encodedWireData()
        let receiptPath = try SandboxPath(path)
        guard receiptPath.value.hasPrefix("logs/"), receiptPath.value.hasSuffix(".json") else {
            throw SandboxError.invalid("INVALID_RECEIPT_PATH")
        }
        try writeBoundedData(
            receiptPath,
            data: data,
            maximumBytes: ReceiptWireContract.maximumSerializedUTF8Bytes
        )
        return data
    }
    func load<T: Decodable>(_ type: T.Type, path: String) throws -> T { try JSONDecoder().decode(type, from: Data(read(SandboxPath(path)).utf8)) }
    func loadIfPresent<T: Decodable>(_ type: T.Type, path: String) throws -> T? {
        let sandboxPath = try SandboxPath(path)
        guard try exists(sandboxPath) else { return nil }
        return try load(type, path: path)
    }
    func receipts() throws -> [RunReceipt] {
        var consumedBytes = 0
        var decoded: [RunReceipt] = []
        for path in try list("logs").filter({ $0.hasSuffix(".json") && !$0.contains("call-") }) {
            do {
                let data = try readReceiptData(SandboxPath(path))
                guard data.count <= Self.maximumReceiptCollectionBytes - consumedBytes else {
                    throw SandboxError.invalid("RECEIPT_COLLECTION_TOO_LARGE")
                }
                consumedBytes += data.count
                decoded.append(try RunReceipt.decodeStrict(from: data))
            } catch {
                throw SandboxError.blocked("RECEIPT_DECODE_FAILED: \(path)")
            }
        }
        return decoded.sorted { $0.createdAt > $1.createdAt }
    }
    var workspaceID: String? {
        guard let user = Keychain.get("appleUser"),
              let directoryName = try? NativeLocalWorkspaceBindingVault.live.directoryName(accountBinding: user) else {
            return nil
        }
        return String(directoryName.prefix(24))
    }
    static func hash(_ text: String) -> String { NativeDigest.sha256(text) }

    func corruptExecutionStateData(_ record: CorruptExecutionState) throws -> Data {
        guard record.canPreserve, let expectedSHA256 = record.sha256 else {
            throw SandboxError.blocked("EXECUTION_STATE_REVIEW_BOUND_EXCEEDED")
        }
        let data = try readData(SandboxPath(record.sourcePath), maximumBytes: CorruptExecutionState.maximumReviewBytes)
        guard data.count == record.byteCount, NativeDigest.sha256(data) == expectedSHA256 else {
            throw SandboxError.conflict("EXECUTION_STATE_CHANGED_REREAD_REQUIRED")
        }
        return data
    }

    func preserveAndDiscardCorruptExecutionState(_ record: CorruptExecutionState) throws -> SandboxPath {
        guard let reviewPath = record.reviewPath else {
            throw SandboxError.blocked("EXECUTION_STATE_REVIEW_BOUND_EXCEEDED")
        }
        let data = try corruptExecutionStateData(record)
        try requireUnaliasedReviewPath(reviewPath)
        try preserveExactData(data, at: reviewPath, maximumBytes: CorruptExecutionState.maximumReviewBytes)
        try requireUnaliasedReviewPath(reviewPath)
        guard try readData(reviewPath, maximumBytes: CorruptExecutionState.maximumReviewBytes) == data else {
            throw SandboxError.conflict("REVIEW_ARCHIVE_READBACK_FAILED")
        }
        try delete(SandboxPath(record.sourcePath), expectedSHA256: record.sha256)
        guard try readData(reviewPath, maximumBytes: CorruptExecutionState.maximumReviewBytes) == data else {
            throw SandboxError.conflict("REVIEW_ARCHIVE_READBACK_FAILED")
        }
        return reviewPath
    }

    func acknowledgeCheckpoint(expected: RunCheckpoint) throws -> SandboxPath {
        let source = try SandboxPath("state/active.json")
        guard try exists(source) else { throw SandboxError.conflict("BACKGROUND_CHECKPOINT_CHANGED") }
        let currentData = try readData(source, maximumBytes: CorruptExecutionState.maximumReviewBytes)
        let current: RunCheckpoint
        do { current = try JSONDecoder().decode(RunCheckpoint.self, from: currentData) }
        catch { throw SandboxError.blocked("CORRUPT_EXECUTION_STATE_REQUIRES_REVIEW") }
        let reviewPath = try CheckpointReviewCore.reviewPath(for: expected)
        try requireUnaliasedReviewPath(reviewPath)
        switch try CheckpointReviewCore.disposition(expected: expected, current: current) {
        case .alreadyAcknowledged:
            guard try exists(reviewPath) else { throw SandboxError.conflict("CHECKPOINT_REVIEW_ARCHIVE_MISSING") }
            let reviewedData = try readData(reviewPath, maximumBytes: CorruptExecutionState.maximumReviewBytes)
            guard let reviewed = try? JSONDecoder().decode(RunCheckpoint.self, from: reviewedData) else {
                throw SandboxError.conflict("CHECKPOINT_REVIEW_ARCHIVE_CHANGED")
            }
            try RunCheckpointIdentity.requireUnchanged(expected: expected, current: reviewed)
        case .acknowledge(let acknowledged):
            try preserveExactData(currentData, at: reviewPath, maximumBytes: CorruptExecutionState.maximumReviewBytes)
            let acknowledgedData = try encoder.encode(acknowledged)
            try writeData(
                source,
                data: acknowledgedData,
                maximumBytes: CorruptExecutionState.maximumReviewBytes,
                expectedSHA256: NativeDigest.sha256(currentData)
            )
        }
        return reviewPath
    }

    private func preserveExactData(_ data: Data, at path: SandboxPath, maximumBytes: Int) throws {
        if try exists(path) {
            guard try readData(path, maximumBytes: maximumBytes) == data else {
                throw SandboxError.conflict("REVIEW_ARCHIVE_CHANGED")
            }
        } else {
            try writeData(path, data: data, maximumBytes: maximumBytes, createOnly: true)
        }
    }

    private func requireUnaliasedReviewPath(_ path: SandboxPath) throws {
        guard path.value.hasPrefix("output/reviewed-") else {
            throw SandboxError.invalid("INVALID_REVIEW_ARCHIVE_PATH")
        }
        try access { root in
            let base = root.resolvingSymlinksInPath().standardizedFileURL
            let lexical = base.appendingPathComponent(path.value).standardizedFileURL
            let resolved = lexical.resolvingSymlinksInPath().standardizedFileURL
            guard lexical.path == resolved.path else {
                throw SandboxError.conflict("REVIEW_ARCHIVE_SYMLINK_REJECTED")
            }
        }
    }
}

struct ExecutionStateSnapshot {
    let checkpoint: RunCheckpoint?
    let shortcutSession: ShortcutSession?
    let corrupt: [CorruptExecutionState]
}

@MainActor
enum ExecutionStateInspector {
    private enum Inspected<Value> {
        case absent
        case value(Value)
        case corrupt(CorruptExecutionState)
    }

    static func inspect(store: SandboxStore = .shared) throws -> ExecutionStateSnapshot {
        let checkpoint: Inspected<RunCheckpoint> = try inspect(
            RunCheckpoint.self,
            kind: .nativeCheckpoint,
            failureCode: "CHECKPOINT_DECODE_FAILED",
            store: store
        )
        let shortcut: Inspected<ShortcutSession> = try inspect(
            ShortcutSession.self,
            kind: .shortcutSession,
            failureCode: "SHORTCUT_SESSION_DECODE_FAILED",
            store: store
        )
        var corrupt: [CorruptExecutionState] = []
        if case .corrupt(let record) = checkpoint { corrupt.append(record) }
        if case .corrupt(let record) = shortcut { corrupt.append(record) }
        return ExecutionStateSnapshot(
            checkpoint: value(checkpoint),
            shortcutSession: value(shortcut),
            corrupt: corrupt
        )
    }

    private static func inspect<Value: Decodable>(
        _ type: Value.Type,
        kind: ExecutionStateKind,
        failureCode: String,
        store: SandboxStore
    ) throws -> Inspected<Value> {
        let path = try SandboxPath(kind.sourcePath)
        guard try store.exists(path) else { return .absent }
        let byteCount = try store.fileByteCount(path)
        guard byteCount <= CorruptExecutionState.maximumReviewBytes else {
            return .corrupt(.oversized(kind: kind, byteCount: byteCount))
        }
        let data = try store.readData(path, maximumBytes: CorruptExecutionState.maximumReviewBytes)
        do { return .value(try JSONDecoder().decode(type, from: data)) }
        catch { return .corrupt(.bounded(kind: kind, data: data, failureCode: failureCode)) }
    }

    private static func value<Value>(_ inspected: Inspected<Value>) -> Value? {
        guard case .value(let value) = inspected else { return nil }
        return value
    }
}

@MainActor
enum GoalVerifier {
    static func verify(_ contract: GoalContract, store: SandboxStore = .shared) -> [AssertionEvidence] {
        contract.assertions.map { assertion in
            let checkedAt = ISO8601DateFormatter().string(from: Date())
            do {
                switch assertion {
                case .exactText(let rawPath, let expected):
                    let actual = try store.read(SandboxPath(rawPath))
                    return evidence(assertion, passed: actual == expected, expected: expected, observed: actual == expected ? "exact match" : "content differed", sha256: SandboxStore.hash(actual), bytes: actual.utf8.count, checkedAt: checkedAt)
                case .sha256(let rawPath, let expected):
                    let actual = try store.read(SandboxPath(rawPath))
                    let digest = SandboxStore.hash(actual)
                    return evidence(assertion, passed: digest == expected, expected: expected, observed: digest, sha256: digest, bytes: actual.utf8.count, checkedAt: checkedAt)
                case .containsText(let rawPath, let expected):
                    let actual = try store.read(SandboxPath(rawPath))
                    return evidence(assertion, passed: actual.contains(expected), expected: expected, observed: actual.contains(expected) ? "text found" : "text absent", sha256: SandboxStore.hash(actual), bytes: actual.utf8.count, checkedAt: checkedAt)
                case .pathExists(let rawPath):
                    let exists = try store.exists(SandboxPath(rawPath))
                    return evidence(assertion, passed: exists, expected: nil, observed: exists ? "exists" : "missing", sha256: nil, bytes: nil, checkedAt: checkedAt)
                case .pathAbsent(let rawPath):
                    let exists = try store.exists(SandboxPath(rawPath))
                    return evidence(assertion, passed: !exists, expected: nil, observed: exists ? "exists" : "absent", sha256: nil, bytes: nil, checkedAt: checkedAt)
                case .folderContains(let folder, let rawPath):
                    let found = try store.containsRecursively(SandboxPath(rawPath), in: folder)
                    return evidence(assertion, passed: found, expected: nil, observed: found ? "listed" : "not listed", sha256: nil, bytes: nil, checkedAt: checkedAt)
                }
            } catch {
                return AssertionEvidence(kind: assertion.kind.rawValue, path: assertion.path, folder: assertion.folder, passed: false, expected: assertion.expected, observed: nil, observedSHA256: nil, byteCount: nil, checkedAt: checkedAt, errorCode: error.localizedDescription)
            }
        }
    }

    private static func evidence(_ assertion: GoalAssertion, passed: Bool, expected: String?, observed: String?, sha256: String?, bytes: Int?, checkedAt: String) -> AssertionEvidence {
        AssertionEvidence(kind: assertion.kind.rawValue, path: assertion.path, folder: assertion.folder, passed: passed, expected: expected, observed: observed, observedSHA256: sha256, byteCount: bytes, checkedAt: checkedAt, errorCode: nil)
    }
}

@MainActor
enum ExecutionAdmission {
    private static let unresolvedNative = Set(["planning", "executing", "ready"])
    private static let unresolvedShortcut = Set(["awaiting_response", "applying"])

    static func ensureCanStart(store: SandboxStore = .shared) throws {
        do {
            let state = try ExecutionStateInspector.inspect(store: store)
            guard state.corrupt.isEmpty else {
                throw SandboxError.blocked("CORRUPT_EXECUTION_STATE_REQUIRES_REVIEW")
            }
            if let checkpoint = state.checkpoint, unresolvedNative.contains(checkpoint.phase) {
                throw SandboxError.blocked("REVIEW_INTERRUPTED_NATIVE_RUN_FIRST")
            }
            if let session = state.shortcutSession, unresolvedShortcut.contains(session.phase) {
                throw SandboxError.blocked("FINISH_PENDING_APP_HANDOFF_FIRST")
            }
        } catch let error as SandboxError { throw error }
        catch { throw SandboxError.blocked("CORRUPT_EXECUTION_STATE_REQUIRES_REVIEW") }
    }

    static func ensureCanResume(_ expected: RunCheckpoint, store: SandboxStore = .shared) throws {
        do {
            let state = try ExecutionStateInspector.inspect(store: store)
            guard state.corrupt.isEmpty else {
                throw SandboxError.blocked("CORRUPT_EXECUTION_STATE_REQUIRES_REVIEW")
            }
            guard let current = state.checkpoint else {
                throw SandboxError.conflict("BACKGROUND_CHECKPOINT_CHANGED")
            }
            try RunCheckpointIdentity.requireUnchanged(expected: expected, current: current)
            guard BackgroundExecutionPolicy.resumablePhases.contains(current.phase) else {
                throw SandboxError.blocked("BACKGROUND_CHECKPOINT_REQUIRES_REVIEW")
            }
            if let session = state.shortcutSession,
               unresolvedShortcut.contains(session.phase) {
                throw SandboxError.blocked("FINISH_PENDING_APP_HANDOFF_FIRST")
            }
        } catch let error as SandboxError { throw error }
        catch { throw SandboxError.blocked("CORRUPT_EXECUTION_STATE_REQUIRES_REVIEW") }
    }
}
