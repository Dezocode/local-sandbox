import Darwin
import Foundation

/// Schema-v1 snapshot storage. The native adapter owns the approved file URL.
/// This package does not choose a sandbox path, bookmark, or network location.
///
/// Commits are compare-and-swap on `snapshotRevision`. Per-instance locks alone cannot protect
/// two engine/store instances that share one file; callers must use `expectedBaseRevision` CAS
/// and, for files, the process-shared writer lock held during load/CAS.
///
/// Commit outcomes:
/// - success: durable bytes match `snapshot`
/// - `notCommitted`: failed before publish; on-disk base unchanged (safe to retry same base)
/// - `committedUnknown`: publish may have advanced; caller must reconcile via `load` before retry.
///   This store does **not** fabricate rollback of a published file.
///
/// Durability: rename/replace under flock is the publish step. This package does **not** claim
/// power-loss durability without host `fsync`/crash proof (unproven; see README).
public protocol IntercomPersistence: Sendable {
    func load() throws -> IntercomSnapshot?
    /// Commits `snapshot` only when the durable base revision equals `expectedBaseRevision`.
    /// Empty storage accepts `expectedBaseRevision == 0`. On mismatch throws `.staleRevision`.
    func commit(_ snapshot: IntercomSnapshot, expectedBaseRevision: UInt64) throws
}

public final class InMemoryIntercomPersistence: IntercomPersistence, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: IntercomSnapshot?
    private var failNextCommitStorage = false

    public init(snapshot: IntercomSnapshot? = nil) {
        self.snapshot = snapshot
    }

    /// When set, the next commit throws `.notCommitted` and leaves the previous snapshot in place.
    public var failNextCommit: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return failNextCommitStorage
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            failNextCommitStorage = newValue
        }
    }

    public func load() throws -> IntercomSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        guard let snapshot else { return nil }
        try snapshot.validate()
        return snapshot
    }

    public func commit(_ snapshot: IntercomSnapshot, expectedBaseRevision: UInt64) throws {
        lock.lock()
        defer { lock.unlock() }
        if failNextCommitStorage {
            failNextCommitStorage = false
            throw IntercomError.notCommitted("INJECTED_COMMIT_FAILURE")
        }
        let actual = self.snapshot?.snapshotRevision ?? 0
        guard actual == expectedBaseRevision else {
            throw IntercomError.staleRevision(expected: expectedBaseRevision, actual: actual)
        }
        if expectedBaseRevision == 0 {
            guard snapshot.snapshotRevision >= 1 else {
                throw IntercomError.invalid("NON_MONOTONIC_SNAPSHOT")
            }
        } else {
            guard snapshot.snapshotRevision > expectedBaseRevision else {
                throw IntercomError.invalid("NON_MONOTONIC_SNAPSHOT")
            }
        }
        try snapshot.validate()
        self.snapshot = snapshot
    }
}

/// Test/host fault injection points for `AtomicFileSnapshotStore.commit`.
/// Production hosts leave this at `.none`.
public enum AtomicFileCommitFault: Sendable, Equatable {
    case none
    /// Before writing the temp file — disk base unchanged → `notCommitted`.
    case beforeWrite
    /// After temp write, before replace/move publish — disk base unchanged → `notCommitted`.
    case beforePublish
    /// Simulated replace/move failure. Classified `notCommitted` only when post-failure
    /// verification proves the durable base is unchanged; otherwise `committedUnknown`.
    case attemptedPublish
    /// After publish replace/move, before readback — disk may be advanced → `committedUnknown`.
    case afterPublish
    /// After publish, force readback path to report unknown — disk may be advanced → `committedUnknown`.
    case readback
}

/// Replaces the snapshot file by writing a sibling temp file and atomically renaming it into place.
/// Uses durable expected-revision CAS plus a shared flock on a sibling lock file so two store
/// instances sharing one path cannot silently lose updates.
///
/// Concurrent cross-process flock stress is **not** covered by package tests (documented gap).
public final class AtomicFileSnapshotStore: IntercomPersistence, @unchecked Sendable {
    private let url: URL
    private let lockURL: URL
    private let fileManager = FileManager()
    private let lock = NSLock()
    private var faultStorage: AtomicFileCommitFault = .none
    private var loadFaultStorage = false
    private var verifyReadFaultStorage = false

    public init(fileURL: URL) throws {
        guard fileURL.isFileURL else { throw IntercomError.invalid("SNAPSHOT_URL_NOT_FILE") }
        self.url = fileURL.standardizedFileURL
        self.lockURL = self.url.deletingLastPathComponent()
            .appendingPathComponent(".\(self.url.lastPathComponent).writer.lock")
    }

    /// Injected commit fault for discriminating regressions. Cleared when consumed.
    public var injectCommitFault: AtomicFileCommitFault {
        get {
            lock.lock()
            defer { lock.unlock() }
            return faultStorage
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            faultStorage = newValue
        }
    }

    /// When true, next `load()` throws and clears the flag.
    public var injectLoadFault: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return loadFaultStorage
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            loadFaultStorage = newValue
        }
    }

    /// When true, next in-commit verification `readUnlocked` throws (ambiguous publish path).
    public var injectVerifyReadFault: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return verifyReadFaultStorage
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            verifyReadFaultStorage = newValue
        }
    }

    public func load() throws -> IntercomSnapshot? {
        try withWriterLock {
            if consumeLoadFault() {
                throw IntercomError.persistence("INJECTED_LOAD_FAILURE")
            }
            return try readUnlocked()
        }
    }

    public func commit(_ snapshot: IntercomSnapshot, expectedBaseRevision: UInt64) throws {
        try withWriterLock {
            // Capture proven durable base (exact snapshot) before any publish attempt.
            let priorSnapshot = try readUnlocked()
            let actual = priorSnapshot?.snapshotRevision ?? 0
            guard actual == expectedBaseRevision else {
                throw IntercomError.staleRevision(expected: expectedBaseRevision, actual: actual)
            }
            let priorBytes = try readRawBytesIfPresent()
            if expectedBaseRevision == 0 {
                guard snapshot.snapshotRevision >= 1 else {
                    throw IntercomError.invalid("NON_MONOTONIC_SNAPSHOT")
                }
            } else {
                guard snapshot.snapshotRevision > expectedBaseRevision else {
                    throw IntercomError.invalid("NON_MONOTONIC_SNAPSHOT")
                }
            }
            try snapshot.validate()
            let data = try IntercomCodec.encode(snapshot)
            guard data.count <= IntercomLimits.maxSnapshotBytes else {
                throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
            }
            let directory = url.deletingLastPathComponent()
            do {
                try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            } catch {
                throw IntercomError.notCommitted("SNAPSHOT_DIRECTORY_FAILED")
            }
            let temp = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
            defer {
                if fileManager.fileExists(atPath: temp.path) {
                    try? fileManager.removeItem(at: temp)
                }
            }

            let fault = consumeCommitFault()
            if fault == .beforeWrite {
                throw IntercomError.notCommitted("INJECTED_PREWRITE")
            }

            do {
                try data.write(to: temp, options: [.atomic])
            } catch let error as IntercomError {
                throw error
            } catch {
                throw IntercomError.notCommitted("SNAPSHOT_TEMP_WRITE_FAILED")
            }

            // Re-check CAS base after encoding, before publish, under the same writer lock.
            let recheck = try readUnlocked()
            guard (recheck?.snapshotRevision ?? 0) == expectedBaseRevision, recheck == priorSnapshot else {
                throw IntercomError.staleRevision(
                    expected: expectedBaseRevision,
                    actual: recheck?.snapshotRevision ?? 0
                )
            }

            if fault == .beforePublish {
                throw IntercomError.notCommitted("INJECTED_PREPUBLISH")
            }

            do {
                if fault == .attemptedPublish {
                    throw IntercomError.persistence("INJECTED_ATTEMPTED_PUBLISH")
                }
                if fileManager.fileExists(atPath: url.path) {
                    _ = try fileManager.replaceItemAt(url, withItemAt: temp)
                } else {
                    try fileManager.moveItem(at: temp, to: url)
                }
            } catch let error as IntercomError {
                switch error {
                case .notCommitted, .committedUnknown(_, _):
                    throw error
                default:
                    // Attempted publish may or may not have mutated durable bytes.
                    // `notCommitted` only when verification proves exact prior base unchanged.
                    try classifyAfterAttemptedPublish(
                        priorSnapshot: priorSnapshot,
                        priorBytes: priorBytes,
                        intendedRevision: snapshot.snapshotRevision,
                        fallbackDetail: "SNAPSHOT_REPLACE_FAILED"
                    )
                }
            } catch {
                try classifyAfterAttemptedPublish(
                    priorSnapshot: priorSnapshot,
                    priorBytes: priorBytes,
                    intendedRevision: snapshot.snapshotRevision,
                    fallbackDetail: "SNAPSHOT_REPLACE_FAILED"
                )
            }

            // Publish completed. Failures from here are committedUnknown — no fake rollback.
            if fault == .afterPublish {
                throw IntercomError.committedUnknown(
                    publishedRevision: snapshot.snapshotRevision,
                    detail: "INJECTED_POSTPUBLISH"
                )
            }

            if fault == .readback {
                throw IntercomError.committedUnknown(
                    publishedRevision: snapshot.snapshotRevision,
                    detail: "INJECTED_READBACK"
                )
            }

            let readBack: IntercomSnapshot?
            do {
                readBack = try readUnlocked()
            } catch {
                throw IntercomError.committedUnknown(
                    publishedRevision: snapshot.snapshotRevision,
                    detail: "SNAPSHOT_READBACK_FAILED"
                )
            }
            guard readBack == snapshot else {
                throw IntercomError.committedUnknown(
                    publishedRevision: snapshot.snapshotRevision,
                    detail: "SNAPSHOT_READBACK_MISMATCH"
                )
            }
            cleanLeftoverTemps(in: directory)
        }
    }

    /// After replace/move throws: prove unchanged base for `notCommitted`, else `committedUnknown`.
    private func classifyAfterAttemptedPublish(
        priorSnapshot: IntercomSnapshot?,
        priorBytes: Data?,
        intendedRevision: UInt64,
        fallbackDetail: String
    ) throws -> Never {
        let afterSnapshot: IntercomSnapshot?
        let afterBytes: Data?
        do {
            // Verify-read fault applies only here (post-attempt), not to pre-publish CAS reads.
            afterSnapshot = try readUnlocked(consumeVerifyFault: true)
            afterBytes = try readRawBytesIfPresent()
        } catch {
            // Unreadable/unknown disk after attempted publish cannot prove non-publication.
            throw IntercomError.committedUnknown(
                publishedRevision: intendedRevision,
                detail: "SNAPSHOT_REPLACE_UNVERIFIED"
            )
        }
        if afterSnapshot == priorSnapshot, afterBytes == priorBytes {
            throw IntercomError.notCommitted(fallbackDetail)
        }
        let published = afterSnapshot?.snapshotRevision ?? intendedRevision
        throw IntercomError.committedUnknown(
            publishedRevision: published,
            detail: "SNAPSHOT_REPLACE_AMBIGUOUS"
        )
    }

    private func consumeCommitFault() -> AtomicFileCommitFault {
        lock.lock()
        defer { lock.unlock() }
        let value = faultStorage
        faultStorage = .none
        return value
    }

    private func consumeLoadFault() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let value = loadFaultStorage
        loadFaultStorage = false
        return value
    }

    private func consumeVerifyReadFault() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let value = verifyReadFaultStorage
        verifyReadFaultStorage = false
        return value
    }

    private func readRawBytesIfPresent() throws -> Data? {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) else { return nil }
        if isDirectory.boolValue { throw IntercomError.persistence("SNAPSHOT_PATH_IS_DIRECTORY") }
        let attrs = try fileManager.attributesOfItem(atPath: url.path)
        if let size = attrs[.size] as? NSNumber, size.intValue > IntercomLimits.maxSnapshotBytes {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        let data = try Data(contentsOf: url)
        guard data.count <= IntercomLimits.maxSnapshotBytes else {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        return data
    }

    private func readUnlocked(consumeVerifyFault: Bool = false) throws -> IntercomSnapshot? {
        if consumeVerifyFault, consumeVerifyReadFault() {
            throw IntercomError.persistence("INJECTED_VERIFY_READ_FAILURE")
        }
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) else { return nil }
        if isDirectory.boolValue { throw IntercomError.persistence("SNAPSHOT_PATH_IS_DIRECTORY") }
        // 1 MiB pre-read cap: reject oversized files before decoding the full buffer.
        do {
            let attrs = try fileManager.attributesOfItem(atPath: url.path)
            if let size = attrs[.size] as? NSNumber, size.intValue > IntercomLimits.maxSnapshotBytes {
                throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
            }
        } catch let error as IntercomError {
            throw error
        } catch {
            throw IntercomError.persistence("SNAPSHOT_READ_FAILED")
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw IntercomError.persistence("SNAPSHOT_READ_FAILED")
        }
        guard data.count <= IntercomLimits.maxSnapshotBytes else {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        return try IntercomCodec.decodeSnapshot(data)
    }

    private func cleanLeftoverTemps(in directory: URL) {
        let prefix = ".\(url.lastPathComponent)."
        guard let names = try? fileManager.contentsOfDirectory(atPath: directory.path) else { return }
        for name in names where name.hasPrefix(prefix) && name.hasSuffix(".tmp") {
            try? fileManager.removeItem(at: directory.appendingPathComponent(name))
        }
    }

    private func withWriterLock<T>(_ body: () throws -> T) throws -> T {
        let directory = lockURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: lockURL.path) {
            fileManager.createFile(atPath: lockURL.path, contents: Data(), attributes: nil)
        }
        let handle: FileHandle
        do {
            handle = try FileHandle(forWritingTo: lockURL)
        } catch {
            throw IntercomError.persistence("WRITER_LOCK_UNAVAILABLE")
        }
        defer { try? handle.close() }
        let fd = handle.fileDescriptor
        let result = flock(fd, LOCK_EX)
        guard result == 0 else { throw IntercomError.persistence("WRITER_LOCK_UNAVAILABLE") }
        defer { _ = flock(fd, LOCK_UN) }
        return try body()
    }
}
