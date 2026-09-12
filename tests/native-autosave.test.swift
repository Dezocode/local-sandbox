import Foundation
import CryptoKit

private final class LockedBoolean: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Bool

    init(_ value: Bool) { self.value = value }

    func read() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func write(_ value: Bool) {
        lock.lock()
        self.value = value
        lock.unlock()
    }
}

@main
enum NativeAutosaveContractTests {
    @MainActor
    static func main() async throws {
        try await rapidEditsAndSerialization()
        try await failedSaveRetry()
        try await journalFailureRetry()
        try await conflictResolution()
        try await concurrentEditWinsOverUseCurrentFile()
        try await concurrentEditWinsOverDiscardDraft()
        try await crashReloadRecovery()
        try await deletedFileCrashRecovery()
        try await failedInitialLoadCanCloseSafely()
        print("Native autosave contracts passed: durable rapid edits, serialized saves, failure retry, explicit conflicts, and crash/reload recovery.")
    }

    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func digest(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    @MainActor
    static func fixture(initial: String = "base") -> (
        NativeAutosaveJournal,
        NativeAutosaveRepository,
        () -> NativeAutosaveDraft?,
        (String) -> Void,
        () -> String,
        () -> [(String, String)]
    ) {
        var draft: NativeAutosaveDraft?
        var remote = initial
        var writes: [(String, String)] = []
        let journal = NativeAutosaveJournal(
            load: { _ in draft },
            save: { draft = $0 },
            removeIf: { path, generation in
                guard draft?.path == path, draft?.generation == generation else { return false }
                draft = nil;return true
            },
            remove: { _ in draft = nil }
        )
        let repository = NativeAutosaveRepository(
            read: { _ in remote },
            write: { path, content, expectedSHA256 in
                guard digest(remote) == expectedSHA256 else { throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED") }
                writes.append((path, content));remote = content;return remote
            }
        )
        return (journal, repository, { draft }, { remote = $0 }, { remote }, { writes })
    }

    @MainActor
    static func rapidEditsAndSerialization() async throws {
        let (journal, repository, currentDraft, _, remote, writes) = fixture()
        let editor = NativeAutosaveCoordinator(path: "workspace/a.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await editor.load()
        editor.edit("one");editor.edit("two");editor.edit("three")
        require(currentDraft()?.content == "three" && currentDraft()?.generation == 3, "rapid edits were not durably coalesced to the latest generation")
        require(editor.state.phase == .dirty, "rapid edits were not visibly dirty")
        await editor.flush()
        require(writes().map(\.1) == ["three"], "rapid edits performed more than one repository write")
        require(remote() == "three" && editor.state.phase == .saved && currentDraft() == nil, "flush did not confirm and clean the latest draft")

        var gatedRemote = "base"
        var gatedDraft: NativeAutosaveDraft?
        var release: CheckedContinuation<Void, Never>?
        var gatedWrites: [String] = []
        let gatedJournal = NativeAutosaveJournal(
            load: { _ in gatedDraft }, save: { gatedDraft = $0 },
            removeIf: { _, generation in guard gatedDraft?.generation == generation else { return false };gatedDraft=nil;return true },
            remove: { _ in gatedDraft = nil }
        )
        let gatedRepository = NativeAutosaveRepository(
            read: { _ in gatedRemote },
            write: { _, content, expected in
                guard digest(gatedRemote) == expected else { throw SandboxError.conflict("stale") }
                if gatedWrites.isEmpty { await withCheckedContinuation { release = $0 } }
                gatedWrites.append(content);gatedRemote=content;return content
            }
        )
        let gated = NativeAutosaveCoordinator(path: "workspace/b.txt", journal: gatedJournal, repository: gatedRepository, debounceMilliseconds: 60_000)
        await gated.load();gated.edit("first")
        let first = Task { await gated.flush() }
        while release == nil { await Task.yield() }
        gated.edit("second")
        let second = Task { await gated.flush() }
        release?.resume();await first.value;await second.value
        require(gatedWrites == ["first", "second"], "in-flight edit was not serialized and rebased")
        require(gatedRemote == "second" && gated.state.phase == .saved, "serialized save did not finish cleanly")
    }

    @MainActor
    static func failedSaveRetry() async throws {
        var remote = "base", draft: NativeAutosaveDraft?
        let fail = LockedBoolean(true)
        let journal = NativeAutosaveJournal(
            load: { _ in draft }, save: { draft = $0 },
            removeIf: { _, generation in guard draft?.generation == generation else { return false };draft=nil;return true },
            remove: { _ in draft = nil }
        )
        let repository = NativeAutosaveRepository(
            read: { _ in remote },
            write: { _, content, expected in
                guard digest(remote) == expected else { throw SandboxError.conflict("stale") }
                if fail.read() { throw SandboxError.blocked("ICLOUD_OFFLINE") }
                remote=content;return content
            }
        )
        let editor = NativeAutosaveCoordinator(path: "workspace/failure.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await editor.load();editor.edit("durable draft");await editor.flush()
        require(editor.state.phase == .offlineOrFailed && draft?.content == "durable draft", "failed save lost its durable journal or visible state")
        fail.write(false);await editor.retry()
        require(remote == "durable draft" && draft == nil && editor.state.phase == .saved, "retry did not recover the failed save")
    }

    @MainActor
    static func journalFailureRetry() async throws {
        var remote = "base", draft: NativeAutosaveDraft?
        let failJournal = LockedBoolean(true)
        let journal = NativeAutosaveJournal(
            load: { _ in draft },
            save: { value in
                if failJournal.read() { throw SandboxError.blocked("JOURNAL_OFFLINE") }
                draft = value
            },
            removeIf: { _, generation in
                guard draft?.generation == generation else { return false }
                draft = nil;return true
            },
            remove: { _ in draft = nil }
        )
        let repository = NativeAutosaveRepository(
            read: { _ in remote },
            write: { _, content, expected in
                guard digest(remote) == expected else { throw SandboxError.conflict("stale") }
                remote = content;return content
            }
        )
        let editor = NativeAutosaveCoordinator(path: "workspace/journal-failure.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await editor.load();editor.edit("still visible")
        require(editor.content == "still visible" && editor.state.phase == .offlineOrFailed && editor.hasPendingChanges, "journal failure hid the unsaved in-memory edit")
        failJournal.write(false);await editor.retry()
        require(remote == "still visible" && draft == nil && editor.state.phase == .saved, "journal retry did not durably save the visible edit")
    }

    @MainActor
    static func conflictResolution() async throws {
        let (journal, repository, draft, setRemote, remote, _) = fixture()
        let editor = NativeAutosaveCoordinator(path: "workspace/conflict.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await editor.load();editor.edit("mine");setRemote("theirs");await editor.flush()
        require(editor.state.phase == .conflict && editor.state.remoteContent == "theirs" && draft()?.content == "mine", "conflict was not retained for review")
        editor.edit("mine revised")
        let reopened = NativeAutosaveCoordinator(path: "workspace/conflict.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await reopened.load()
        require(reopened.state.phase == .conflict && reopened.content == "mine revised", "crash/reload silently converted an unresolved conflict into an autosave")
        await reopened.keepDraft()
        require(remote() == "mine revised" && reopened.state.phase == .saved && draft() == nil, "keep-draft did not perform a guarded rebase")
    }

    @MainActor
    static func concurrentEditWinsOverUseCurrentFile() async throws {
        let path = "workspace/concurrent-resolution.txt"
        var draft: NativeAutosaveDraft? = try NativeAutosaveDraft(
            path: path,
            baseSHA256: digest("base"),
            content: "reviewed local",
            generation: 1,
            updatedAt: ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: 1_800_000_000))
        )
        var reads = 0
        var resumeRead: CheckedContinuation<String?, Never>?
        let journal = NativeAutosaveJournal(
            load: { _ in draft },
            save: { draft = $0 },
            removeIf: { _, generation in
                guard draft?.generation == generation else { return false }
                draft = nil;return true
            },
            remove: { _ in draft = nil }
        )
        let repository = NativeAutosaveRepository(
            read: { _ in
                reads += 1
                if reads == 1 { return "reviewed remote" }
                return await withCheckedContinuation { resumeRead = $0 }
            },
            write: { _, _, _ in throw SandboxError.blocked("UNEXPECTED_WRITE") }
        )
        let editor = NativeAutosaveCoordinator(path: path, journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await editor.load()
        require(editor.state.phase == .conflict, "fixture did not enter conflict review")
        let selection = Task { await editor.useCurrentFile() }
        while resumeRead == nil { await Task.yield() }
        editor.edit("newer local edit")
        resumeRead?.resume(returning: "reviewed remote")
        await selection.value
        require(editor.state.phase == .conflict, "use-current marked a newer edit clean")
        require(editor.content == "newer local edit", "use-current overwrote the newer visible edit")
        require(draft?.content == "newer local edit", "use-current removed the newer recovery journal")
    }

    @MainActor
    static func concurrentEditWinsOverDiscardDraft() async throws {
        let path = "workspace/concurrent-discard.txt"
        var draft: NativeAutosaveDraft?
        var reads = 0
        var resumeRead: CheckedContinuation<String?, Never>?
        let journal = NativeAutosaveJournal(
            load: { _ in draft },
            save: { draft = $0 },
            removeIf: { _, generation in
                guard draft?.generation == generation else { return false }
                draft = nil;return true
            },
            remove: { _ in draft = nil }
        )
        let repository = NativeAutosaveRepository(
            read: { _ in
                reads += 1
                if reads == 1 { return "base" }
                return await withCheckedContinuation { resumeRead = $0 }
            },
            write: { _, _, _ in throw SandboxError.blocked("UNEXPECTED_WRITE") }
        )
        let editor = NativeAutosaveCoordinator(path: path, journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await editor.load()
        editor.edit("discard candidate")
        let discard = Task { await editor.discardDraft() }
        while resumeRead == nil { await Task.yield() }
        editor.edit("newer local edit")
        resumeRead?.resume(returning: "remote")
        await discard.value
        require(editor.state.phase == .dirty, "discard marked a newer edit clean")
        require(editor.content == "newer local edit", "discard overwrote the newer visible edit")
        require(draft?.content == "newer local edit", "discard removed the newer recovery journal")
    }

    @MainActor
    static func crashReloadRecovery() async throws {
        let (journal, repository, draft, _, remote, _) = fixture()
        let first = NativeAutosaveCoordinator(path: "workspace/recover.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await first.load();first.edit("survives crash");first.stopScheduling()
        require(draft()?.content == "survives crash" && remote() == "base", "pre-crash draft was not durable before debounce")
        let reopened = NativeAutosaveCoordinator(path: "workspace/recover.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await reopened.load()
        require(reopened.content == "survives crash" && reopened.state.phase == .recovered, "reload did not surface the recovered draft")
        await reopened.flush()
        require(remote() == "survives crash" && draft() == nil && reopened.state.phase == .saved, "recovered draft did not save and clean its journal")
    }

    @MainActor
    static func deletedFileCrashRecovery() async throws {
        var remote: String? = "base", draft: NativeAutosaveDraft?
        let journal = NativeAutosaveJournal(
            load: { _ in draft }, save: { draft = $0 },
            removeIf: { _, generation in guard draft?.generation == generation else { return false };draft=nil;return true },
            remove: { _ in draft = nil }
        )
        let repository = NativeAutosaveRepository(
            read: { _ in remote },
            write: { _, content, expected in
                if let expected {
                    guard let current = remote, digest(current) == expected else { throw SandboxError.conflict("stale") }
                } else {
                    guard remote == nil else { throw SandboxError.conflict("exists") }
                }
                remote = content;return content
            }
        )
        let first = NativeAutosaveCoordinator(path: "workspace/deleted.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await first.load();first.edit("restore me");first.stopScheduling();remote = nil
        let reopened = NativeAutosaveCoordinator(path: "workspace/deleted.txt", journal: journal, repository: repository, debounceMilliseconds: 60_000)
        await reopened.load()
        require(reopened.state.phase == .conflict && reopened.content == "restore me" && draft != nil, "deleted-file reload did not retain the recoverable draft as a conflict")
        await reopened.keepDraft()
        require(remote == "restore me" && draft == nil && reopened.state.phase == .saved, "reviewed draft did not recreate the deleted file with create-only semantics")
    }

    @MainActor
    static func failedInitialLoadCanCloseSafely() async throws {
        let journal = NativeAutosaveJournal(load: { _ in nil }, save: { _ in }, removeIf: { _, _ in true }, remove: { _ in })
        let repository = NativeAutosaveRepository(
            read: { _ in throw SandboxError.blocked("ICLOUD_OFFLINE") },
            write: { _, _, _ in throw SandboxError.blocked("UNEXPECTED_WRITE") }
        )
        let editor = NativeAutosaveCoordinator(path: "workspace/offline.txt", journal: journal, repository: repository)
        await editor.load()
        require(editor.state.phase == .offlineOrFailed && !editor.hasPendingChanges && editor.canCloseWithoutDiscard, "failed initial load trapped the user in an empty editor")
    }
}
