import Foundation
import Combine
import CryptoKit

struct NativeAutosaveDraft: Codable, Equatable {
    private static let maximumSafeInteger = 9_007_199_254_740_991
    let schemaVersion: Int
    let path: String
    let baseSHA256: String?
    let content: String
    let generation: Int
    let updatedAt: String

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, path, baseSHA256, content, generation, updatedAt
    }

    init(path: String, baseSHA256: String?, content: String, generation: Int, updatedAt: String) throws {
        self.schemaVersion = 1;self.path = path;self.baseSHA256 = baseSHA256
        self.content = content;self.generation = generation;self.updatedAt = updatedAt
        try validate()
    }

    func validate() throws {
        _ = try SandboxPath(path)
        guard schemaVersion == 1,
              baseSHA256 == nil || baseSHA256!.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              content.utf8.count <= 64_000, (1...Self.maximumSafeInteger).contains(generation),
              ISO8601DateFormatter().date(from: updatedAt) != nil else {
            throw SandboxError.invalid("AUTOSAVE_DRAFT_INVALID")
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard container.contains(.baseSHA256) else { throw SandboxError.invalid("AUTOSAVE_DRAFT_INVALID") }
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        path = try container.decode(String.self, forKey: .path)
        baseSHA256 = try container.decodeIfPresent(String.self, forKey: .baseSHA256)
        content = try container.decode(String.self, forKey: .content)
        generation = try container.decode(Int.self, forKey: .generation)
        updatedAt = try container.decode(String.self, forKey: .updatedAt)
        try validate()
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(path, forKey: .path)
        if let baseSHA256 { try container.encode(baseSHA256, forKey: .baseSHA256) }
        else { try container.encodeNil(forKey: .baseSHA256) }
        try container.encode(content, forKey: .content)
        try container.encode(generation, forKey: .generation)
        try container.encode(updatedAt, forKey: .updatedAt)
    }
}

struct NativeAutosaveJournal {
    let load: @MainActor (String) throws -> NativeAutosaveDraft?
    let save: @MainActor (NativeAutosaveDraft) throws -> Void
    let removeIf: @MainActor (String, Int) throws -> Bool
    let remove: @MainActor (String) throws -> Void
}

struct NativeAutosaveRepository {
    let read: @MainActor (String) async throws -> String?
    let write: @MainActor (String, String, String?) async throws -> String
}

enum NativeAutosavePhase: String, Equatable {
    case loading
    case clean
    case dirty
    case recovered
    case saving
    case saved
    case offlineOrFailed
    case conflict
}

struct NativeAutosaveState: Equatable {
    let phase: NativeAutosavePhase
    let message: String
    let remoteContent: String?
}

@MainActor
final class NativeAutosaveCoordinator: ObservableObject {
    @Published private(set) var content = ""
    @Published private(set) var state = NativeAutosaveState(phase: .loading, message: "Loading…", remoteContent: nil)

    let path: String
    private let journal: NativeAutosaveJournal
    private let repository: NativeAutosaveRepository
    private let debounceNanoseconds: UInt64
    private let now: () -> Date
    private var loaded = false
    private var baseSHA256: String?
    private var generation = 0
    private var journaledGeneration: Int?
    private var debounceTask: Task<Void, Never>?
    private var saveTail: Task<Void, Never> = Task {}

    init(
        path: String,
        journal: NativeAutosaveJournal,
        repository: NativeAutosaveRepository,
        debounceMilliseconds: Int = 650,
        now: @escaping () -> Date = Date.init
    ) {
        self.path = path;self.journal = journal;self.repository = repository;self.now = now
        self.debounceNanoseconds = UInt64(min(max(0, debounceMilliseconds), 60_000)) * 1_000_000
    }

    var hasPendingChanges: Bool {
        loaded && ![.clean, .saved].contains(state.phase)
    }

    var canCloseWithoutDiscard: Bool { !hasPendingChanges }
    var acceptsEdits: Bool { loaded }

    func load() async {
        guard !loaded else { return }
        let draft: NativeAutosaveDraft?
        do {
            _ = try SandboxPath(path)
            draft = try journal.load(path)
            try draft?.validate()
            guard draft?.path == nil || draft?.path == path else { throw SandboxError.invalid("AUTOSAVE_DRAFT_PATH_MISMATCH") }
        } catch {
            state = .init(phase: .offlineOrFailed, message: "Draft journal could not be opened: \(error.localizedDescription)", remoteContent: nil)
            return
        }
        do {
            let remote = try await repository.read(path)
            guard remote != nil || draft != nil else { throw SandboxError.conflict("AUTOSAVE_FILE_MISSING") }
            loaded = true
            guard let draft else {
                guard let remote else { throw SandboxError.conflict("AUTOSAVE_FILE_MISSING") }
                baseSHA256 = sha256(remote)
                content = remote
                state = .init(phase: .clean, message: "Up to date", remoteContent: nil)
                return
            }
            generation = draft.generation;journaledGeneration = draft.generation
            if draft.content == remote {
                baseSHA256 = remote.map(sha256)
                content = draft.content
                guard try journal.removeIf(path, draft.generation) else { throw SandboxError.conflict("AUTOSAVE_JOURNAL_CHANGED") }
                journaledGeneration = nil
                state = .init(phase: .saved, message: "Recovered save confirmed", remoteContent: nil)
            } else if let remote, draft.baseSHA256 == sha256(remote) {
                baseSHA256 = sha256(remote)
                content = draft.content
                state = .init(phase: .recovered, message: "Recovered unsaved draft; autosave pending", remoteContent: nil)
                schedule()
            } else {
                baseSHA256 = draft.baseSHA256
                content = draft.content
                state = .init(phase: .conflict, message: remote == nil ? "Recovered draft conflicts with a deleted file" : "Recovered draft conflicts with the current file", remoteContent: remote)
            }
        } catch {
            if let draft {
                content = draft.content;baseSHA256 = draft.baseSHA256;generation = draft.generation
                journaledGeneration = draft.generation;loaded = true
                state = .init(phase: .offlineOrFailed, message: "Recovered journal; current file is unavailable: \(error.localizedDescription)", remoteContent: nil)
            } else {
                state = .init(phase: .offlineOrFailed, message: error.localizedDescription, remoteContent: nil)
            }
        }
    }

    func edit(_ value: String) {
        guard loaded, value != content else { return }
        content = value
        guard generation < 9_007_199_254_740_991 else {
            cancelDebounce()
            state = .init(phase: .offlineOrFailed, message: "Draft generation limit reached; copy the text before closing", remoteContent: nil)
            return
        }
        generation += 1
        do {
            let draft = try makeDraft(content: value, generation: generation)
            try journal.save(draft);journaledGeneration = generation
            if state.phase == .conflict {
                state = .init(phase: .conflict, message: "Local draft changed; resolve it against the current file", remoteContent: state.remoteContent)
            } else {
                state = .init(phase: .dirty, message: "Draft journaled; waiting to save", remoteContent: nil)
                schedule()
            }
        } catch {
            journaledGeneration = nil;cancelDebounce()
            state = .init(phase: .offlineOrFailed, message: "Draft journal failed: \(error.localizedDescription)", remoteContent: nil)
        }
    }

    func flush() async {
        cancelDebounce()
        let preceding = saveTail
        let operation = Task { @MainActor [weak self] in
            await preceding.value
            await self?.saveLatest()
        }
        saveTail = operation
        await operation.value
    }

    func retry() async {
        guard loaded else { await load();return }
        if journaledGeneration != generation {
            do {
                try journal.save(try makeDraft(content: content, generation: max(1, generation)))
                generation = max(1, generation);journaledGeneration = generation
            } catch {
                state = .init(phase: .offlineOrFailed, message: "Draft journal failed: \(error.localizedDescription)", remoteContent: nil);return
            }
        }
        state = .init(phase: .dirty, message: "Retry queued", remoteContent: nil)
        await flush()
    }

    func useCurrentFile() async {
        guard state.phase == .conflict else { return }
        let selectedGeneration = generation
        let selectedJournaledGeneration = journaledGeneration
        do {
            let remote = try await repository.read(path)
            guard state.phase == .conflict,
                  generation == selectedGeneration,
                  journaledGeneration == selectedJournaledGeneration else { return }
            if let selectedJournaledGeneration { guard try journal.removeIf(path, selectedJournaledGeneration) else { throw SandboxError.conflict("AUTOSAVE_JOURNAL_CHANGED") } }
            else { try journal.remove(path) }
            content = remote ?? "";baseSHA256 = remote.map(sha256);self.journaledGeneration = nil
            state = .init(phase: .saved, message: remote == nil ? "Using the current deleted state" : "Using current file", remoteContent: nil)
        } catch { state = .init(phase: .offlineOrFailed, message: error.localizedDescription, remoteContent: state.remoteContent) }
    }

    func keepDraft() async {
        guard state.phase == .conflict else { return }
        do {
            let remote = try await repository.read(path)
            guard generation < 9_007_199_254_740_991 else { throw SandboxError.blocked("AUTOSAVE_GENERATION_LIMIT") }
            baseSHA256 = remote.map(sha256);generation += 1
            try journal.save(try makeDraft(content: content, generation: generation));journaledGeneration = generation
            state = .init(phase: .dirty, message: "Rebased draft queued", remoteContent: nil)
            await flush()
        } catch { state = .init(phase: .offlineOrFailed, message: error.localizedDescription, remoteContent: state.remoteContent) }
    }

    func discardDraft() async {
        let selectedGeneration = generation
        let selectedJournaledGeneration = journaledGeneration
        do {
            let remote = try await repository.read(path)
            guard generation == selectedGeneration,
                  journaledGeneration == selectedJournaledGeneration else { return }
            if let selectedJournaledGeneration { guard try journal.removeIf(path, selectedJournaledGeneration) else { throw SandboxError.conflict("AUTOSAVE_JOURNAL_CHANGED") } }
            else { try journal.remove(path) }
            content = remote ?? "";baseSHA256 = remote.map(sha256);self.journaledGeneration = nil
            loaded = true
            state = .init(phase: .clean, message: remote == nil ? "Draft discarded; file remains deleted" : "Draft discarded", remoteContent: nil)
        } catch { state = .init(phase: .offlineOrFailed, message: error.localizedDescription, remoteContent: state.remoteContent) }
    }

    func stopScheduling() { cancelDebounce() }

    private func schedule() {
        cancelDebounce()
        debounceTask = Task { @MainActor [weak self] in
            guard let self else { return }
            if debounceNanoseconds > 0 {
                do { try await Task.sleep(nanoseconds: debounceNanoseconds) }
                catch { return }
            }
            guard !Task.isCancelled else { return }
            await flush()
        }
    }

    private func cancelDebounce() { debounceTask?.cancel();debounceTask = nil }

    private func saveLatest() async {
        guard loaded, state.phase != .conflict, let journaledGeneration, journaledGeneration == generation else { return }
        let capturedContent = content
        let capturedGeneration = generation
        let capturedBaseHash = baseSHA256
        state = .init(phase: .saving, message: "Saving…", remoteContent: nil)
        do {
            let observed = try await repository.write(path, capturedContent, capturedBaseHash)
            guard observed == capturedContent else { throw SandboxError.conflict("AUTOSAVE_READBACK_DIVERGED") }
            try completeSave(content: observed, generation: capturedGeneration)
        } catch {
            await reconcileAfterFailure(error, content: capturedContent, generation: capturedGeneration, baseHash: capturedBaseHash)
        }
    }

    private func completeSave(content savedContent: String, generation savedGeneration: Int) throws {
        let savedHash = sha256(savedContent)
        let removed = try journal.removeIf(path, savedGeneration)
        baseSHA256 = savedHash
        if generation == savedGeneration {
            guard removed else { throw SandboxError.conflict("AUTOSAVE_JOURNAL_CHANGED") }
            journaledGeneration = nil
            state = .init(phase: .saved, message: "Saved", remoteContent: nil)
            return
        }
        let latest = try makeDraft(content: content, generation: generation)
        try journal.save(latest);journaledGeneration = generation
        state = .init(phase: .dirty, message: "Newer draft journaled; next save queued", remoteContent: nil)
        schedule()
    }

    private func reconcileAfterFailure(_ original: Error, content attempted: String, generation attemptedGeneration: Int, baseHash: String?) async {
        do {
            let remote = try await repository.read(path)
            if remote == attempted {
                do { try completeSave(content: attempted, generation: attemptedGeneration) }
                catch { state = .init(phase: .offlineOrFailed, message: error.localizedDescription, remoteContent: nil) }
                return
            }
            if let remote, sha256(remote) != baseHash {
                state = .init(phase: .conflict, message: "Save conflict: the current file changed", remoteContent: remote)
                return
            }
            if remote == nil, baseHash != nil {
                state = .init(phase: .conflict, message: "Save conflict: the current file was removed", remoteContent: nil)
                return
            }
        } catch {
            state = .init(phase: .offlineOrFailed, message: "Save and readback failed: \(error.localizedDescription)", remoteContent: nil)
            return
        }
        state = .init(phase: .offlineOrFailed, message: "Save failed; draft remains journaled: \(original.localizedDescription)", remoteContent: nil)
    }

    private func makeDraft(content: String, generation: Int) throws -> NativeAutosaveDraft {
        let formatter = ISO8601DateFormatter()
        return try NativeAutosaveDraft(path: path, baseSHA256: baseSHA256, content: content, generation: generation, updatedAt: formatter.string(from: now()))
    }

    private func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
