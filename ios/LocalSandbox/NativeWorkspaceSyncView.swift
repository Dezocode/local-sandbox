import SwiftUI

extension Notification.Name {
    static let localSandboxDidLock = Notification.Name("LocalSandbox.didLock")
}

struct NativeSyncDifference: Identifiable {
    let path: String
    let nativeContent: String?
    let nativeSHA256: String?
    let remoteContent: String?
    let remoteRevision: Int
    var id: String { path }
}

struct NativePushConflict: Identifiable {
    let path: String
    let nativeContent: String?
    let nativeGeneration: Int
    let remote: WorkspaceRecord
    let remoteRevision: Int
    var id: String { path }
}

@MainActor
final class NativeWorkspaceSyncModel: ObservableObject {
    private enum OperationImpact {
        case readOnly
        case hostedMutation
    }

    private struct ActiveOperation {
        let id: UUID
        let impact: OperationImpact
        let task: Task<Void, Error>
    }

    @Published var workspaces: [NativeSyncWorkspaceSummary] = []
    @Published var selectedWorkspaceId = ""
    @Published var status = "Sign in, then choose a manual sync action."
    @Published var busy = false
    @Published var differences: [NativeSyncDifference] = []
    @Published var conflict: NativePushConflict?
    @Published private(set) var displayedRecoverySecret: String?
    @Published private(set) var unlockedWorkspaceId: String?
    @Published private(set) var orphanedRecoveryWorkspaceIds: [String] = []

    private let api: NativeWorkspaceSyncAPI
    private let bearerVault: NativeBearerVault
    private let recoveryVault: NativeRecoverySecretVault
    private let nativeAuth: NativeAppleAuthController
    private var cryptoSession: WorkspaceCryptoSession?
    private var stagedDifferences: [NativeSyncDifference] = []
    private var reviewIndex = WorkspaceReviewIndex()
    private var lockObserver: NSObjectProtocol?
    private let writerDevice: String
    private var lifecycleGeneration = NativeLifecycleGeneration()
    private var activeOperation: ActiveOperation?

    init(
        api: NativeWorkspaceSyncAPI = NativeWorkspaceSyncAPI(),
        bearerVault: NativeBearerVault = .live,
        recoveryVault: NativeRecoverySecretVault = .live,
        nativeAuth: NativeAppleAuthController = .live
    ) {
        self.api = api
        self.bearerVault = bearerVault
        self.recoveryVault = recoveryVault
        self.nativeAuth = nativeAuth
        self.writerDevice = "device_\((try? NativeAppleNonce.make()) ?? UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        lockObserver = NotificationCenter.default.addObserver(forName: .localSandboxDidLock, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.lock() }
        }
    }

    isolated deinit {
        activeOperation?.task.cancel()
        if let lockObserver { NotificationCenter.default.removeObserver(lockObserver) }
    }

    func lock() {
        let hostedCommitMayBeAmbiguous = activeOperation?.impact == .hostedMutation
        lifecycleGeneration.invalidate()
        activeOperation?.task.cancel()
        activeOperation = nil
        busy = false
        clearInMemoryWorkspaceSecrets()
        status = hostedCommitMayBeAmbiguous
            ? "Local Sandbox locked and cancelled the client operation. A hosted mutation may already have committed; sign in and refresh for idempotent readback before retrying."
            : "Encryption keys were cleared when Local Sandbox locked."
    }

    func captureOperationGeneration() -> UInt64 {
        lifecycleGeneration.capture()
    }

    func isOperationGenerationCurrent(_ capturedGeneration: UInt64) -> Bool {
        lifecycleGeneration.isCurrent(capturedGeneration)
    }

    private func clearInMemoryWorkspaceSecrets() {
        cryptoSession = nil
        unlockedWorkspaceId = nil
        differences = []
        stagedDifferences = []
        reviewIndex.clear()
        conflict = nil
        displayedRecoverySecret = nil
    }

    func refreshWorkspaces(operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration) { generation in
            let bearer = try self.activeBearer()
            let workspaces = try await self.api.list(bearer: bearer.token)
            try self.requireCurrent(generation)
            let registeredWorkspaceIds = try self.recoveryVault.registeredWorkspaceIds()
            let hostedWorkspaceIds = Set(workspaces.map(\.workspaceId))
            let unlockedWorkspaceWasRemoved = self.unlockedWorkspaceId.map { !hostedWorkspaceIds.contains($0) } ?? false
            if unlockedWorkspaceWasRemoved {
                self.clearInMemoryWorkspaceSecrets()
            }
            self.workspaces = workspaces
            self.orphanedRecoveryWorkspaceIds = registeredWorkspaceIds.filter { !hostedWorkspaceIds.contains($0) }
            if !self.workspaces.contains(where: { $0.workspaceId == self.selectedWorkspaceId }) {
                self.selectedWorkspaceId = self.workspaces.first?.workspaceId ?? ""
            }
            if !self.orphanedRecoveryWorkspaceIds.isEmpty {
                self.status = unlockedWorkspaceWasRemoved
                    ? "The previously unlocked hosted workspace is no longer present. Its in-memory key was cleared; review the obsolete iCloud recovery credential below."
                    : "One or more recovery credentials remain in iCloud Keychain without a matching hosted workspace. Review the cleanup section."
            } else if unlockedWorkspaceWasRemoved {
                self.status = "The previously unlocked hosted workspace is no longer present. Its in-memory key and review state were cleared."
            } else {
                self.status = self.workspaces.isEmpty ? "No encrypted workspaces are enrolled." : "Choose a workspace and unlock it manually."
            }
        }
    }

    func create(useICloudRecovery: Bool, localPassphrase: String, operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration, impact: .hostedMutation) { generation in
            let bearer = try self.activeBearer()
            let passphrase: String
            if useICloudRecovery {
                passphrase = try self.recoveryVault.newSecret()
            } else {
                passphrase = localPassphrase
            }
            let created = try WorkspaceCrypto.create(passphrase: passphrase)
            if useICloudRecovery {
                try self.recoveryVault.save(passphrase, workspaceId: created.0.workspaceId)
            }
            do {
                try await self.api.enroll(recovery: created.1, bearer: bearer.token)
                try self.requireCurrent(generation)
            } catch {
                if useICloudRecovery && self.lifecycleGeneration.isCurrent(generation) {
                    // Enrollment is idempotent, but a lost HTTP response is ambiguous. Keep the recovery
                    // secret because the server may already hold its envelope; deleting it would strand
                    // committed ciphertext. A later list refresh can confirm whether enrollment landed.
                    self.displayedRecoverySecret = passphrase
                }
                throw error
            }
            let workspaces = try await self.api.list(bearer: bearer.token)
            try self.requireCurrent(generation)
            self.cryptoSession = created.0
            self.unlockedWorkspaceId = created.0.workspaceId
            self.selectedWorkspaceId = created.0.workspaceId
            self.orphanedRecoveryWorkspaceIds.removeAll { $0 == created.0.workspaceId }
            self.differences = []
            self.reviewIndex.clear()
            self.conflict = nil
            self.displayedRecoverySecret = useICloudRecovery ? passphrase : nil
            self.workspaces = workspaces
            self.status = useICloudRecovery
                ? "Created and unlocked. Back up the one-time recovery secret for browser access."
                : "Created and unlocked with a local-only recovery passphrase."
        }
    }

    func unlock(useICloudRecovery: Bool, localPassphrase: String, operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration) { generation in
            guard !self.selectedWorkspaceId.isEmpty else { throw SandboxError.invalid("SELECT_A_SYNC_WORKSPACE") }
            let bearer = try self.activeBearer()
            let snapshot = try await self.api.readWorkspace(workspaceId: self.selectedWorkspaceId, bearer: bearer.token)
            try self.requireCurrent(generation)
            let session: WorkspaceCryptoSession
            if useICloudRecovery {
                session = try self.restoreWithICloudRecovery(snapshot)
            } else {
                session = try WorkspaceCrypto.restore(snapshot.recovery, passphrase: localPassphrase)
            }
            guard session.workspaceId == snapshot.workspaceId, session.epoch == snapshot.epoch else {
                throw SandboxError.blocked("SYNC_KEY_EPOCH_CONFLICT")
            }
            _ = try self.open(snapshot: snapshot, session: session)
            self.reviewIndex.clear()
            self.stagedDifferences = []
            self.cryptoSession = session
            self.unlockedWorkspaceId = session.workspaceId
            self.orphanedRecoveryWorkspaceIds.removeAll { $0 == session.workspaceId }
            self.differences = []
            self.conflict = nil
            self.status = "Encrypted workspace unlocked in memory. Pull or push remains manual."
        }
    }

    func enrollRecoveryInICloud(currentPassphrase: String, operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration) { generation in
            guard !self.selectedWorkspaceId.isEmpty else { throw SandboxError.invalid("SELECT_A_SYNC_WORKSPACE") }
            let bearer = try self.activeBearer()
            let snapshot = try await self.api.readWorkspace(workspaceId: self.selectedWorkspaceId, bearer: bearer.token)
            try self.requireCurrent(generation)
            let session = try WorkspaceCrypto.restore(snapshot.recovery, passphrase: currentPassphrase)
            try self.recoveryVault.save(currentPassphrase, workspaceId: snapshot.workspaceId)
            guard try self.recoveryVault.recoverySecret(workspaceId: snapshot.workspaceId) == currentPassphrase else {
                throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_PERSISTENCE_FAILED")
            }
            self.cryptoSession = session
            self.unlockedWorkspaceId = session.workspaceId
            self.selectedWorkspaceId = session.workspaceId
            self.orphanedRecoveryWorkspaceIds.removeAll { $0 == session.workspaceId }
            self.reviewIndex.clear()
            self.stagedDifferences = []
            self.differences = []
            self.conflict = nil
            self.status = "Recovery key saved and read back from synchronizable iCloud Keychain."
        }
    }

    func removeRecoveryFromICloud(operationGeneration: UInt64) {
        do { try requireCurrent(operationGeneration) }
        catch { return }
        let workspaceId = unlockedWorkspaceId ?? selectedWorkspaceId
        guard !workspaceId.isEmpty else { status = "Choose an encrypted workspace first."; return }
        do {
            try recoveryVault.remove(workspaceId: workspaceId)
            displayedRecoverySecret = nil
            status = "Recovery key removed from synchronizable iCloud Keychain. The in-memory workspace remains unlocked until Local Sandbox locks."
        } catch { status = error.localizedDescription }
    }

    func removeOrphanedRecoveryFromICloud(workspaceId: String, operationGeneration: UInt64) {
        do { try requireCurrent(operationGeneration) }
        catch { return }
        guard orphanedRecoveryWorkspaceIds.contains(workspaceId) else {
            status = "Refresh encrypted workspaces before removing an obsolete recovery credential."
            return
        }
        do {
            try recoveryVault.remove(workspaceId: workspaceId)
            orphanedRecoveryWorkspaceIds.removeAll { $0 == workspaceId }
            status = "Obsolete recovery credential removed from synchronizable iCloud Keychain. No hosted or local files were changed."
        } catch { status = error.localizedDescription }
    }

    func rotateRecovery(
        currentPassphrase: String,
        replacementPassphrase: String,
        storeReplacementInICloud: Bool,
        operationGeneration: UInt64
    ) async {
        await run(operationGeneration: operationGeneration, impact: .hostedMutation) { generation in
            let (activeSession, bearer) = try self.activeWorkspace()
            let snapshot = try await self.api.readWorkspace(workspaceId: activeSession.workspaceId, bearer: bearer.token)
            try self.requireCurrent(generation)
            guard snapshot.epoch == activeSession.epoch else { throw SandboxError.blocked("SYNC_KEY_EPOCH_CONFLICT") }
            let currentSecret: String
            if currentPassphrase.isEmpty {
                currentSecret = try self.matchingICloudRecoverySecret(snapshot).secret
            } else {
                currentSecret = currentPassphrase
            }
            let replacementSecret = storeReplacementInICloud
                ? try self.recoveryVault.newSecret()
                : replacementPassphrase
            let rotated = try WorkspaceCrypto.rewrapRecovery(
                snapshot.recovery,
                currentPassphrase: currentSecret,
                replacementPassphrase: replacementSecret
            )
            _ = try self.open(snapshot: snapshot, session: rotated.0)
            if storeReplacementInICloud {
                try self.recoveryVault.stageReplacement(replacementSecret, workspaceId: snapshot.workspaceId)
            }
            let committedRevision = try await self.api.replaceRecovery(
                workspaceId: snapshot.workspaceId,
                expectedEpoch: snapshot.epoch,
                expectedRevision: snapshot.snapshotRevision,
                recovery: rotated.1,
                bearer: bearer.token
            )
            try self.requireCurrent(generation)
            let verified = try await self.api.readWorkspace(workspaceId: snapshot.workspaceId, bearer: bearer.token)
            try self.requireCurrent(generation)
            guard verified.epoch == snapshot.epoch, verified.recovery == rotated.1,
                  verified.snapshotRevision >= committedRevision else {
                throw SandboxError.blocked("SYNC_RECOVERY_ROTATION_READBACK_FAILED")
            }
            let verifiedSession = try WorkspaceCrypto.restore(verified.recovery, passphrase: replacementSecret)
            _ = try self.open(snapshot: verified, session: verifiedSession)
            self.cryptoSession = verifiedSession
            self.reviewIndex.clear()
            self.stagedDifferences = []
            self.differences = []
            self.conflict = nil
            if storeReplacementInICloud {
                self.displayedRecoverySecret = replacementSecret
                do {
                    try self.recoveryVault.commitStagedReplacement(workspaceId: snapshot.workspaceId)
                } catch {
                    self.status = "Hosted recovery rotation committed and read back. The replacement remains in pending iCloud Keychain storage; unlock this workspace again to finish promotion. Back up the displayed secret. \(error.localizedDescription)"
                    return
                }
            } else {
                self.displayedRecoverySecret = nil
                do {
                    try self.recoveryVault.remove(workspaceId: snapshot.workspaceId)
                } catch {
                    self.status = "Hosted recovery rotation committed and read back, but the obsolete iCloud Keychain item could not be removed. The new local passphrase is active. \(error.localizedDescription)"
                    return
                }
            }
            self.status = storeReplacementInICloud
                ? "Recovery key rotated, read back, and committed to iCloud Keychain. Back up the new one-time secret."
                : "Recovery passphrase rotated and read back. The old iCloud recovery key was removed."
        }
    }

    func deleteUnlockedWorkspace(operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration, impact: .hostedMutation) { generation in
            let (session, bearer) = try self.activeWorkspace()
            let snapshot = try await self.api.readWorkspace(workspaceId: session.workspaceId, bearer: bearer.token)
            try self.requireCurrent(generation)
            guard snapshot.epoch == session.epoch else { throw SandboxError.blocked("SYNC_KEY_EPOCH_CONFLICT") }
            try await self.api.deleteWorkspace(
                workspaceId: session.workspaceId,
                expectedEpoch: session.epoch,
                expectedRevision: snapshot.snapshotRevision,
                bearer: bearer.token
            )
            // Client cancellation cannot retract a delete the server already accepted. Fence all
            // local cleanup after the await; a later refresh/readback reconciles an ambiguous commit.
            try self.requireCurrent(generation)
            let deletedWorkspaceId = session.workspaceId
            self.workspaces.removeAll { $0.workspaceId == deletedWorkspaceId }
            self.selectedWorkspaceId = self.workspaces.first?.workspaceId ?? ""
            self.clearInMemoryWorkspaceSecrets()
            do {
                try self.recoveryVault.remove(workspaceId: deletedWorkspaceId)
                self.orphanedRecoveryWorkspaceIds.removeAll { $0 == deletedWorkspaceId }
                self.status = "Hosted recovery envelope and ciphertext records deleted. Local Files and iCloud documents were retained."
            } catch {
                if !self.orphanedRecoveryWorkspaceIds.contains(deletedWorkspaceId) {
                    self.orphanedRecoveryWorkspaceIds.append(deletedWorkspaceId)
                    self.orphanedRecoveryWorkspaceIds.sort()
                }
                self.status = "Hosted ciphertext was deleted, but the obsolete iCloud recovery credential could not be removed. Sign in, refresh encrypted workspaces, then use the cleanup control. \(error.localizedDescription)"
            }
        }
    }

    func revealICloudRecoverySecret(operationGeneration: UInt64) {
        do { try requireCurrent(operationGeneration) }
        catch { return }
        guard let workspaceId = unlockedWorkspaceId else { status = "Unlock the encrypted workspace first.";return }
        do {
            displayedRecoverySecret = try recoveryVault.recoverySecret(workspaceId: workspaceId)
            status = "Recovery secret revealed after device authentication. Clear it when browser backup is complete."
        } catch { status = error.localizedDescription }
    }

    func clearDisplayedRecoverySecret() { displayedRecoverySecret = nil }

    func stagePull(operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration) { generation in
            let (session, bearer) = try self.activeWorkspace()
            let snapshot = try await self.api.readWorkspace(workspaceId: session.workspaceId, bearer: bearer.token)
            try self.requireCurrent(generation)
            let opened = try self.open(snapshot: snapshot, session: session)
            var staged: [NativeSyncDifference] = []
            for item in opened {
                let path = try SandboxPath(item.value.path)
                let native = try SandboxStore.shared.exists(path) ? try SandboxStore.shared.read(path) : nil
                if native != item.value.content {
                    staged.append(NativeSyncDifference(
                        path: path.value,
                        nativeContent: native,
                        nativeSHA256: native.map(SandboxStore.hash),
                        remoteContent: item.value.content,
                        remoteRevision: item.record.revision
                    ))
                }
            }
            self.stagedDifferences = staged
            self.differences = staged
            self.reviewIndex.clear()
            for item in staged {
                self.reviewIndex.remember(path: item.path, revision: item.remoteRevision, content: item.remoteContent)
            }
            self.conflict = nil
            self.status = staged.isEmpty
                ? "Pull checked authenticated records; native files already match."
                : "Review \(staged.count) side-by-side change\(staged.count == 1 ? "" : "s") before importing."
        }
    }

    func applyStagedPull(operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration) { _ in
            guard !self.stagedDifferences.isEmpty else { throw SandboxError.invalid("NO_STAGED_SYNC_CHANGES") }
            let originalCount = self.stagedDifferences.count
            var applied = 0
            do {
                while let item = self.stagedDifferences.first {
                    let path = try SandboxPath(item.path)
                    let current = try SandboxStore.shared.exists(path) ? try SandboxStore.shared.read(path) : nil
                    if current == item.remoteContent {
                        self.stagedDifferences.removeFirst()
                        self.differences = self.stagedDifferences
                        applied += 1
                        continue
                    }
                    guard current.map(SandboxStore.hash) == item.nativeSHA256 else {
                        throw SandboxError.conflict("NATIVE_FILE_CHANGED_REVIEW_PULL_AGAIN")
                    }
                    if let remote = item.remoteContent {
                        if item.nativeContent == nil {
                            try SandboxStore.shared.write(path, content: remote, createOnly: true)
                        } else {
                            try SandboxStore.shared.write(path, content: remote, expectedSHA256: item.nativeSHA256)
                        }
                    } else {
                        try SandboxStore.shared.delete(path, expectedSHA256: item.nativeSHA256)
                    }
                    self.stagedDifferences.removeFirst()
                    self.differences = self.stagedDifferences
                    applied += 1
                }
            } catch {
                throw SandboxError.blocked("SYNC_PULL_PARTIAL_\(applied)_OF_\(originalCount): \(error.localizedDescription)")
            }
            self.status = "Imported \(applied) reviewed remote change\(applied == 1 ? "" : "s") with readback checks."
        }
    }

    func push(path rawPath: String, operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration, impact: .hostedMutation) { generation in
            let (session, bearer) = try self.activeWorkspace()
            let path = try SandboxPath(rawPath)
            guard isNativeDefaultSyncPath(path.value) else { throw SandboxError.invalid("SYNC_PATH_NOT_ALLOWED") }
            let nativeContent = try SandboxStore.shared.exists(path) ? try SandboxStore.shared.read(path) : nil
            let recordId = try WorkspaceCrypto.recordID(session: session, path: path.value)
            let current = try await self.api.readRecord(workspaceId: session.workspaceId, recordId: recordId, bearer: bearer.token)
            try self.requireCurrent(generation)
            let remote = try current.map { try WorkspaceCrypto.open(session: session, envelope: $0.envelope) }
            if let remote, remote.path != path.value { throw SandboxError.blocked("SYNC_RECORD_PATH_MISMATCH") }
            let currentBase = current.map { WorkspaceReviewedBase(revision: $0.revision, content: remote?.content) }
            let baseRevision: Int?
            switch self.reviewIndex.decision(path: path.value, current: currentBase) {
            case .create:
                baseRevision = nil
            case .write(let reviewedRevision):
                baseRevision = reviewedRevision
            case .conflict:
                guard let current, let remote else { throw SandboxError.blocked("SYNC_REVIEWED_RECORD_DISAPPEARED") }
                self.conflict = NativePushConflict(
                    path: path.value,
                    nativeContent: nativeContent,
                    nativeGeneration: remote.generation + 1,
                    remote: remote,
                    remoteRevision: current.revision
                )
                self.status = "The encrypted file changed after its last review. Compare both versions before keeping the native copy."
                return
            }
            let latestNative = try SandboxStore.shared.exists(path) ? try SandboxStore.shared.read(path) : nil
            guard latestNative.map(SandboxStore.hash) == nativeContent.map(SandboxStore.hash) else {
                throw SandboxError.conflict("NATIVE_FILE_CHANGED_BEFORE_PUSH_REVIEW_AGAIN")
            }
            let recordGeneration = max(remote?.generation ?? -1, -1) + 1
            let envelope = try WorkspaceCrypto.seal(
                session: session,
                path: path.value,
                content: nativeContent,
                baseRevision: baseRevision,
                generation: recordGeneration,
                writerDevice: self.writerDevice
            )
            do {
                let saved = try await self.api.write(workspaceId: session.workspaceId, expectedRevision: baseRevision, envelope: envelope, bearer: bearer.token)
                try self.requireCurrent(generation)
                let savedValue = try WorkspaceCrypto.open(session: session, envelope: saved.envelope)
                self.reviewIndex.remember(path: path.value, revision: saved.revision, content: savedValue.content)
                self.conflict = nil
                self.status = "Pushed the confirmed \(path.value) snapshot as encrypted revision \(saved.revision). Later native edits, if any, remain unsynced."
            } catch let error as NativeServiceError where error.status == 409 && error.code == "SYNC_VERSION_CONFLICT" {
                try self.requireCurrent(generation)
                guard let encrypted = error.conflictRecord else { throw SandboxError.blocked("SYNC_CONFLICT_RESPONSE_INVALID") }
                let latest = try WorkspaceCrypto.open(session: session, envelope: encrypted.envelope)
                guard latest.path == path.value else { throw SandboxError.blocked("SYNC_CONFLICT_PATH_MISMATCH") }
                self.conflict = NativePushConflict(
                    path: path.value,
                    nativeContent: nativeContent,
                    nativeGeneration: recordGeneration,
                    remote: latest,
                    remoteRevision: encrypted.revision
                )
                self.status = "Conflict detected. Review both versions before keeping the native copy."
            }
        }
    }

    func keepNativeAfterConflict(operationGeneration: UInt64) async {
        await run(operationGeneration: operationGeneration, impact: .hostedMutation) { generation in
            guard let conflict = self.conflict else { throw SandboxError.invalid("NO_SYNC_CONFLICT") }
            let (session, bearer) = try self.activeWorkspace()
            let path = try SandboxPath(conflict.path)
            let latestNative = try SandboxStore.shared.exists(path) ? try SandboxStore.shared.read(path) : nil
            guard latestNative.map(SandboxStore.hash) == conflict.nativeContent.map(SandboxStore.hash) else {
                throw SandboxError.conflict("NATIVE_FILE_CHANGED_REVIEW_CONFLICT_AGAIN")
            }
            let envelope = try WorkspaceCrypto.seal(
                session: session,
                path: conflict.path,
                content: conflict.nativeContent,
                baseRevision: conflict.remoteRevision,
                generation: max(conflict.nativeGeneration, conflict.remote.generation + 1),
                writerDevice: self.writerDevice
            )
            do {
                let saved = try await self.api.write(workspaceId: session.workspaceId, expectedRevision: conflict.remoteRevision, envelope: envelope, bearer: bearer.token)
                try self.requireCurrent(generation)
                let savedValue = try WorkspaceCrypto.open(session: session, envelope: saved.envelope)
                self.reviewIndex.remember(path: conflict.path, revision: saved.revision, content: savedValue.content)
                self.conflict = nil
                self.status = "Kept the reviewed native copy as encrypted revision \(saved.revision)."
            } catch let error as NativeServiceError where error.status == 409 && error.code == "SYNC_VERSION_CONFLICT" {
                try self.requireCurrent(generation)
                throw SandboxError.conflict("SYNC_CHANGED_AGAIN_PULL_REQUIRED")
            }
        }
    }

    private func activeBearer() throws -> NativeBearerSession {
        guard let bearer = bearerVault.load() else { throw SandboxError.blocked("APPLE_NATIVE_SESSION_REQUIRED") }
        return bearer
    }

    private func activeWorkspace() throws -> (WorkspaceCryptoSession, NativeBearerSession) {
        guard let session = cryptoSession else { throw SandboxError.blocked("UNLOCK_ENCRYPTED_WORKSPACE_FIRST") }
        return (session, try activeBearer())
    }

    private func matchingICloudRecoverySecret(_ snapshot: NativeSyncWorkspaceSnapshot) throws -> NativeRecoverySecretCandidate {
        for candidate in try recoveryVault.recoveryCandidates(workspaceId: snapshot.workspaceId) {
            if let session = try? WorkspaceCrypto.restore(snapshot.recovery, passphrase: candidate.secret),
               session.workspaceId == snapshot.workspaceId, session.epoch == snapshot.epoch {
                return candidate
            }
        }
        throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_UNAVAILABLE")
    }

    private func restoreWithICloudRecovery(_ snapshot: NativeSyncWorkspaceSnapshot) throws -> WorkspaceCryptoSession {
        let candidate = try matchingICloudRecoverySecret(snapshot)
        let session = try WorkspaceCrypto.restore(snapshot.recovery, passphrase: candidate.secret)
        if candidate.staged {
            try recoveryVault.commitStagedReplacement(workspaceId: snapshot.workspaceId)
        } else {
            try recoveryVault.discardStagedReplacement(workspaceId: snapshot.workspaceId)
        }
        return session
    }

    private func open(
        snapshot: NativeSyncWorkspaceSnapshot,
        session: WorkspaceCryptoSession
    ) throws -> [(record: NativeStoredEncryptedRecord, value: WorkspaceRecord)] {
        guard snapshot.workspaceId == session.workspaceId, snapshot.epoch == session.epoch else {
            throw SandboxError.blocked("SYNC_KEY_EPOCH_CONFLICT")
        }
        var paths = Set<String>()
        return try snapshot.records.map { record in
            let value = try WorkspaceCrypto.open(session: session, envelope: record.envelope)
            guard isNativeDefaultSyncPath(value.path), paths.insert(value.path).inserted else {
                throw SandboxError.blocked("SYNC_RECORD_SET_INVALID")
            }
            return (record, value)
        }.sorted { $0.value.path < $1.value.path }
    }

    private func requireCurrent(_ capturedGeneration: UInt64) throws {
        try Task.checkCancellation()
        guard lifecycleGeneration.isCurrent(capturedGeneration) else {
            throw SandboxError.blocked("SYNC_OPERATION_CANCELLED_BY_LOCK")
        }
    }

    private func run(
        operationGeneration capturedGeneration: UInt64,
        impact: OperationImpact = .readOnly,
        _ operation: @escaping @MainActor (UInt64) async throws -> Void
    ) async {
        guard lifecycleGeneration.isCurrent(capturedGeneration) else { return }
        guard activeOperation == nil else { return }
        let operationID = UUID()
        let task = Task { @MainActor in
            try requireCurrent(capturedGeneration)
            try await operation(capturedGeneration)
            try requireCurrent(capturedGeneration)
        }
        activeOperation = ActiveOperation(id: operationID, impact: impact, task: task)
        busy = true
        let result = await task.result
        guard activeOperation?.id == operationID else { return }
        activeOperation = nil
        busy = false
        do { try result.get() }
        catch let error as NativeServiceError {
            guard lifecycleGeneration.isCurrent(capturedGeneration) else { return }
            if error.status == 401 {
                NativeHostedAccessAdmission.block()
                lock()
                let retirementGeneration = lifecycleGeneration.capture()
                do {
                    try await nativeAuth.disconnect()
                    guard lifecycleGeneration.isCurrent(retirementGeneration) else { return }
                    status = "Hosted authorization was rejected, so encrypted sync was locked and a separate server revocation was confirmed."
                } catch is NativeRevocationDeferredError {
                    guard lifecycleGeneration.isCurrent(retirementGeneration) else { return }
                    status = "Hosted authorization was rejected, so encrypted sync was locked. The exact bearer is disabled locally and saved in device-only Keychain until server revocation is confirmed."
                } catch {
                    guard lifecycleGeneration.isCurrent(retirementGeneration) else { return }
                    status = "Hosted authorization was rejected, so encrypted sync was locked. Retirement could not complete; the exact bearer remains retained or durably queued and blocked from use. \(error.localizedDescription)"
                }
                return
            }
            status = error.localizedDescription
        } catch {
            guard lifecycleGeneration.isCurrent(capturedGeneration) else { return }
            status = error.localizedDescription
        }
    }
}

struct EncryptedWorkspaceSyncView: View {
    @EnvironmentObject private var app: AppModel
    @StateObject private var sync = NativeWorkspaceSyncModel()
    @State private var useICloudRecovery = true
    @State private var passphrase = ""
    @State private var path = "workspace/test.txt"
    @State private var confirmCreate = false
    @State private var confirmImport = false
    @State private var confirmPush = false
    @State private var confirmKeepNative = false
    @State private var acceptedRecoveryResponsibility = false
    @State private var currentRecoveryPassphrase = ""
    @State private var replacementRecoveryPassphrase = ""
    @State private var replacementRecoveryConfirmation = ""
    @State private var storeReplacementInICloud = true
    @State private var confirmRecoveryRotation = false
    @State private var confirmICloudEnrollment = false
    @State private var confirmICloudRemoval = false
    @State private var confirmWorkspaceDeletion = false
    @State private var confirmOrphanedRecoveryRemoval = false
    @State private var orphanedRecoveryRemovalTarget: String?

    var body: some View {
        Form {
            Section("Native Apple session") {
                if let expiry = app.nativeSessionExpiry {
                    LabeledContent("Bearer expires", value: expiry.formatted(date: .omitted, time: .standard))
                    Button("Disconnect and revoke", role: .destructive) {
                        let executionGeneration = ExecutionContinuationGate.shared.capture()
                        let operationGeneration = sync.captureOperationGeneration()
                        Task { @MainActor in
                            guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                            await app.disconnectNativeSync(executionGeneration: executionGeneration)
                        }
                    }
                } else {
                    Text("Sign in with Apple to create or reopen your Apple-owned workspace and receive a short-lived sync session. To use an existing ChatGPT-hosted workspace, link Apple from that signed-in account before this device's first native sign-in. Local Sandbox never merges accounts by email.")
                        .font(.footnote).foregroundStyle(.secondary)
                    AppleLoginButton()
                }
            }

            Section("Encrypted workspaces") {
                Button(sync.busy ? "Working…" : "Refresh list") {
                    let operationGeneration = sync.captureOperationGeneration()
                    Task { @MainActor in
                        await sync.refreshWorkspaces(operationGeneration: operationGeneration)
                        if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                    }
                }
                    .disabled(sync.busy || app.nativeSessionExpiry == nil)
                if !sync.workspaces.isEmpty {
                    Picker("Workspace", selection: $sync.selectedWorkspaceId) {
                        ForEach(sync.workspaces) { item in Text(String(item.workspaceId.prefix(12))).tag(item.workspaceId) }
                    }
                    Button("Unlock with iCloud Keychain") {
                        let operationGeneration = sync.captureOperationGeneration()
                        Task { @MainActor in
                            await sync.unlock(useICloudRecovery: true, localPassphrase: "", operationGeneration: operationGeneration)
                            if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                        }
                    }
                        .disabled(sync.busy || sync.selectedWorkspaceId.isEmpty)
                    SecureField("Local-only recovery passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Unlock with local passphrase") {
                        let phrase = passphrase
                        passphrase = ""
                        let operationGeneration = sync.captureOperationGeneration()
                        Task { @MainActor in
                            await sync.unlock(useICloudRecovery: false, localPassphrase: phrase, operationGeneration: operationGeneration)
                            if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                        }
                    }.disabled(sync.busy || sync.selectedWorkspaceId.isEmpty || passphrase.utf8.count < 12)
                }
                Text("A new iPhone can recover an Apple-recovered workspace after iCloud Keychain synchronizes. If that key never arrives, the old ciphertext cannot be decrypted; use its original local passphrase when applicable or create a new workspace.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            Section("Create workspace") {
                Toggle("Store a random recovery secret in iCloud Keychain", isOn: $useICloudRecovery)
                if useICloudRecovery {
                    Toggle("I will back up the one-time secret for browser recovery", isOn: $acceptedRecoveryResponsibility)
                }
                if !useICloudRecovery {
                    SecureField("12–1,024 UTF-8 byte passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Button("Create encrypted workspace") { confirmCreate = true }
                    .disabled(sync.busy || (useICloudRecovery && !acceptedRecoveryResponsibility) || (!useICloudRecovery && !(12...1_024).contains(passphrase.utf8.count)))
                Text("Apple identity tokens and account identifiers are never encryption keys. Apple recovery uses a separate random 256-bit secret in synchronizable Keychain. The same one-time secret unlocks this workspace in the hosted or local PWA; local-only mode leaves recovery entirely to you.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            if !sync.orphanedRecoveryWorkspaceIds.isEmpty {
                Section("Obsolete iCloud recovery credentials") {
                    ForEach(sync.orphanedRecoveryWorkspaceIds, id: \.self) { workspaceId in
                        LabeledContent("Hosted workspace", value: String(workspaceId.prefix(12)) + "…")
                        Button("Remove this obsolete credential", role: .destructive) {
                            orphanedRecoveryRemovalTarget = workspaceId
                            confirmOrphanedRecoveryRemoval = true
                        }.disabled(sync.busy)
                    }
                    Text("These account-scoped synchronizable Keychain entries have no matching hosted encrypted workspace in the latest authenticated list. Removing one changes only its recovery credential; it does not delete local Files or iCloud documents.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }

            if let recoverySecret = sync.displayedRecoverySecret {
                Section("Back up recovery secret now") {
                    Text(recoverySecret).font(.caption.monospaced()).textSelection(.enabled)
                    ShareLink("Export recovery secret", item: recoverySecret)
                    Button("I saved it; clear from this screen") { sync.clearDisplayedRecoverySecret() }
                    Text("This is the only non-Apple path into an Apple-recovered workspace. Paste it as the recovery passphrase in the hosted or local PWA. It disappears from this screen when the app locks and requires device authentication to reveal again.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }

            if let workspaceId = sync.unlockedWorkspaceId {
                Section("Manual sync · \(String(workspaceId.prefix(12)))") {
                    TextField("workspace/file.txt", text: $path)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Review remote changes") {
                        let operationGeneration = sync.captureOperationGeneration()
                        Task { @MainActor in
                            await sync.stagePull(operationGeneration: operationGeneration)
                            if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                        }
                    }.disabled(sync.busy)
                    Button("Push this native path") { confirmPush = true }.disabled(sync.busy || path.isEmpty)
                    Button("Reveal iCloud recovery secret") {
                        let executionGeneration = ExecutionContinuationGate.shared.capture()
                        let operationGeneration = sync.captureOperationGeneration()
                        Task { @MainActor in
                            do {
                                let localAccessLease = try await LocalAccess.authenticate(executionGeneration: executionGeneration)
                                try localAccessLease.requireCurrent()
                                sync.revealICloudRecoverySecret(operationGeneration: operationGeneration)
                            }
                            catch {
                                guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                                app.error=error.localizedDescription
                            }
                        }
                    }.disabled(sync.busy)
                    Text("Only non-private workspace/ and output/ paths are eligible. Credential, profile, private-export, and signing-material paths are rejected. Nothing polls or syncs in the background.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Recovery lifecycle · \(String(workspaceId.prefix(12)))") {
                    SecureField("Current passphrase, optional with iCloud recovery", text: $currentRecoveryPassphrase)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Toggle("Store replacement in iCloud Keychain", isOn: $storeReplacementInICloud)
                    if !storeReplacementInICloud {
                        SecureField("New 12–1,024 UTF-8 byte passphrase", text: $replacementRecoveryPassphrase)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        SecureField("Confirm new passphrase", text: $replacementRecoveryConfirmation)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    Button("Rotate recovery key") { confirmRecoveryRotation = true }
                        .disabled(sync.busy || (!storeReplacementInICloud && (!(12...1_024).contains(replacementRecoveryPassphrase.utf8.count) || replacementRecoveryPassphrase != replacementRecoveryConfirmation)))
                    Button("Save current recovery key to iCloud Keychain") { confirmICloudEnrollment = true }
                        .disabled(sync.busy || !(12...1_024).contains(currentRecoveryPassphrase.utf8.count))
                    Button("Remove recovery key from iCloud Keychain", role: .destructive) { confirmICloudRemoval = true }
                        .disabled(sync.busy)
                    Button("Delete hosted encrypted workspace", role: .destructive) { confirmWorkspaceDeletion = true }
                        .disabled(sync.busy)
                    Text("Rotation rewraps the same 256-bit workspace key and advances the hosted snapshot revision. Other devices must use the replacement recovery key. Removing the iCloud item affects synchronizable Keychain; locking only clears this app's in-memory key. Hosted deletion keeps local Files and iCloud documents.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }

            if !sync.differences.isEmpty {
                Section("Review remote changes") {
                    ForEach(sync.differences) { item in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(item.path).font(.headline)
                            LabeledContent("On this iPhone", value: preview(item.nativeContent))
                            LabeledContent("Encrypted remote", value: preview(item.remoteContent))
                            Text("Remote revision \(item.remoteRevision)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Button("Import reviewed remote changes") { confirmImport = true }
                        .disabled(sync.busy)
                }
            }

            if let conflict = sync.conflict {
                Section("Sync conflict") {
                    Text(conflict.path).font(.headline)
                    LabeledContent("On this iPhone", value: preview(conflict.nativeContent))
                    LabeledContent("Encrypted remote", value: preview(conflict.remote.content))
                    Button("Keep reviewed native copy") { confirmKeepNative = true }
                        .disabled(sync.busy)
                }
            }

            Section("Status") { Text(sync.status).font(.footnote).textSelection(.enabled) }
        }
        .navigationTitle("Encrypted sync")
        .onReceive(NotificationCenter.default.publisher(for: .localSandboxDidLock)) { _ in
            passphrase = ""
            currentRecoveryPassphrase = ""
            replacementRecoveryPassphrase = ""
            replacementRecoveryConfirmation = ""
            confirmCreate = false
            confirmRecoveryRotation = false
            confirmICloudEnrollment = false
            confirmICloudRemoval = false
            confirmWorkspaceDeletion = false
            confirmOrphanedRecoveryRemoval = false
            orphanedRecoveryRemovalTarget = nil
        }
        .task {
            let operationGeneration = sync.captureOperationGeneration()
            if app.nativeSessionExpiry != nil {
                await sync.refreshWorkspaces(operationGeneration: operationGeneration)
                if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
            }
        }
        .alert("Create encrypted workspace?", isPresented: $confirmCreate) {
            Button("Create") {
                let phrase = passphrase
                let storesRecoveryInICloud = useICloudRecovery
                passphrase = ""
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    await sync.create(useICloudRecovery: storesRecoveryInICloud, localPassphrase: phrase, operationGeneration: operationGeneration)
                    if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("This enrolls a new encrypted workspace in the signed-in hosted account.") }
        .alert("Import remote changes?", isPresented: $confirmImport) {
            Button("Import") {
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    await sync.applyStagedPull(operationGeneration: operationGeneration)
                    if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("Each reviewed value is checked immediately before it is applied. If a later item conflicts, applied items stay complete and the remaining items stay available for retry.") }
        .alert("Push native file?", isPresented: $confirmPush) {
            Button("Push") {
                let selectedPath = path
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    await sync.push(path: selectedPath, operationGeneration: operationGeneration)
                    if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("The selected native value will be encrypted locally and written with a compare-and-swap revision check.") }
        .alert("Keep native copy?", isPresented: $confirmKeepNative) {
            Button("Keep native") {
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    await sync.keepNativeAfterConflict(operationGeneration: operationGeneration)
                    if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("This writes over the reviewed remote revision only if it has not changed again.") }
        .alert("Rotate recovery key?", isPresented: $confirmRecoveryRotation) {
            Button("Rotate") {
                let current = currentRecoveryPassphrase
                let replacement = replacementRecoveryPassphrase
                currentRecoveryPassphrase = ""
                replacementRecoveryPassphrase = ""
                replacementRecoveryConfirmation = ""
                let storesReplacementInICloud = storeReplacementInICloud
                let executionGeneration = ExecutionContinuationGate.shared.capture()
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    do {
                        let localAccessLease = try await LocalAccess.authenticate(executionGeneration: executionGeneration)
                        try localAccessLease.requireCurrent()
                        await sync.rotateRecovery(
                            currentPassphrase: current,
                            replacementPassphrase: replacement,
                            storeReplacementInICloud: storesReplacementInICloud,
                            operationGeneration: operationGeneration
                        )
                        if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                    } catch {
                        guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                        app.error = error.localizedDescription
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("The old recovery credential stops opening the hosted recovery envelope after the compare-and-swap update. Active workspace record encryption stays on the same 256-bit key.") }
        .alert("Save recovery key to iCloud Keychain?", isPresented: $confirmICloudEnrollment) {
            Button("Save") {
                let current = currentRecoveryPassphrase
                currentRecoveryPassphrase = ""
                let executionGeneration = ExecutionContinuationGate.shared.capture()
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    do {
                        let localAccessLease = try await LocalAccess.authenticate(executionGeneration: executionGeneration)
                        try localAccessLease.requireCurrent()
                        await sync.enrollRecoveryInICloud(currentPassphrase: current, operationGeneration: operationGeneration)
                        if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                    } catch {
                        guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                        app.error = error.localizedDescription
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("Local Sandbox first proves this passphrase opens the selected recovery envelope, then stores and reads it back from synchronizable iCloud Keychain.") }
        .alert("Remove iCloud recovery key?", isPresented: $confirmICloudRemoval) {
            Button("Remove", role: .destructive) {
                let executionGeneration = ExecutionContinuationGate.shared.capture()
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    do {
                        let localAccessLease = try await LocalAccess.authenticate(executionGeneration: executionGeneration)
                        try localAccessLease.requireCurrent()
                        sync.removeRecoveryFromICloud(operationGeneration: operationGeneration)
                        if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                    }
                    catch {
                        guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                        app.error = error.localizedDescription
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("This removes the selected workspace recovery key from synchronizable iCloud Keychain. The hosted ciphertext and local Files remain.") }
        .alert("Delete hosted encrypted workspace?", isPresented: $confirmWorkspaceDeletion) {
            Button("Delete ciphertext", role: .destructive) {
                let executionGeneration = ExecutionContinuationGate.shared.capture()
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    do {
                        let localAccessLease = try await LocalAccess.authenticate(executionGeneration: executionGeneration)
                        try localAccessLease.requireCurrent()
                        await sync.deleteUnlockedWorkspace(operationGeneration: operationGeneration)
                        if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                    }
                    catch {
                        guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                        app.error = error.localizedDescription
                    }
                }
            }
            Button("Keep workspace", role: .cancel) {}
        } message: { Text("This permanently deletes the hosted recovery envelope and every ciphertext record only if the authenticated snapshot has not changed. Local Files and iCloud documents remain.") }
        .alert("Remove obsolete iCloud recovery credential?", isPresented: $confirmOrphanedRecoveryRemoval) {
            Button("Remove credential", role: .destructive) {
                let workspaceId = orphanedRecoveryRemovalTarget
                orphanedRecoveryRemovalTarget = nil
                let executionGeneration = ExecutionContinuationGate.shared.capture()
                let operationGeneration = sync.captureOperationGeneration()
                Task { @MainActor in
                    do {
                        let localAccessLease = try await LocalAccess.authenticate(executionGeneration: executionGeneration)
                        try localAccessLease.requireCurrent()
                        if let workspaceId {
                            sync.removeOrphanedRecoveryFromICloud(workspaceId: workspaceId, operationGeneration: operationGeneration)
                        }
                        if sync.isOperationGenerationCurrent(operationGeneration) { app.refresh() }
                    } catch {
                        guard sync.isOperationGenerationCurrent(operationGeneration) else { return }
                        app.error = error.localizedDescription
                    }
                }
            }
            Button("Keep credential", role: .cancel) { orphanedRecoveryRemovalTarget = nil }
        } message: { Text("This removes only the selected account-scoped recovery credential from synchronizable iCloud Keychain. Hosted data is already absent, and local Files and iCloud documents remain.") }
    }

    private func preview(_ value: String?) -> String {
        guard let value else { return "Deleted" }
        if value.count <= 160 { return value.isEmpty ? "Empty" : value }
        return String(value.prefix(160)) + "…"
    }
}
