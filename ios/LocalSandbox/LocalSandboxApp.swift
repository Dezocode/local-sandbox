import SwiftUI
import AppIntents
import Combine
import AuthenticationServices
import UniformTypeIdentifiers
import UserNotifications
import SafariServices

enum AppleCredentialReviewDisplayState: Equatable {
    case notChecked
    case clear
    case required(markedAt: Date)
}

@MainActor
final class AppModel: ObservableObject {
    @Published var unlocked = false
    @Published var policy = ResourcePolicy()
    @Published var connected = false
    @Published var folderName = "No folder selected"
    @Published var userID = ""
    @Published var running = false
    @Published var progress = "Ready to plan"
    @Published var error = ""
    @Published var files: [String] = []
    @Published var receipts: [RunReceipt] = []
    @Published var checkpoint: RunCheckpoint?
    @Published var corruptExecutionStates: [CorruptExecutionState] = []
    @Published var executionStateInspectionError = ""
    @Published var backgroundStatus: BackgroundExecutionRecord?
    @Published private(set) var nativeSessionExpiry: Date?
    @Published var nativeRevocationFollowUp: NativePendingRevocationStatus?
    @Published var appleAccountMode: NativeAppleAccountMode?
    @Published var appleAccountDeletionPending = false
    @Published var appleAccountDeletionNeedsReauthentication = false
    @Published var appleAccountDeletionNeedsDiscard = false
    @Published var appleTransferRecoveryUserID: String?
    @Published var appleAuthorizationInFlight = false
    @Published var deletingAppleAccount = false
    @Published var accountDeletionNotice: String?
    @Published private(set) var appleCredentialReviewDisplayState: AppleCredentialReviewDisplayState = .notChecked
    @Published private(set) var checkingAppleCredentialReview = false
    @Published private(set) var acknowledgingAppleCredentialReview = false
    private let nativeAuth: NativeAppleAuthController
    private let accountModeVault: NativeAppleAccountModeVault
    private let transferBlockVault: NativeAppleTransferBlockVault
    private let transferMigration: NativeAppleTransferMigrationCoordinator
    private let deletionOutcomeVault: NativeAccountDeletionOutcomeVault
    private let deletionCompletionRecovery: NativeAccountDeletionCompletionRecovery
    private let credentialScrubber: NativeLocalProfileCredentialScrubber
    private let clearShortcutDistributionApproval:@MainActor () throws -> Void
    private let readShortcutDistributionApproval:@MainActor () throws -> String?
    private let localProfileStateIsCleared:@MainActor () -> Bool
    private var appleCredentialRevocationObserver:NSObjectProtocol?
    private var significantTimeChangeObserver:NSObjectProtocol?
    private var authLifecycleGeneration=NativeLifecycleGeneration()
    private var appleCredentialStateGeneration=NativeLifecycleGeneration()
    private var appleCredentialReviewLifecycleGeneration=NativeLifecycleGeneration()
    private var nativeSessionExpiryGeneration=NativeLifecycleGeneration()
    private var nativeSessionExpiryTask:Task<Void,Never>?
    private var appleCredentialReview:NativeAppleCredentialReview?
    private let nativeSessionNow:@MainActor ()->Date
    init(
        nativeAuth: NativeAppleAuthController = .live,
        accountModeVault: NativeAppleAccountModeVault = .live,
        transferBlockVault: NativeAppleTransferBlockVault = .live,
        transferMigration: NativeAppleTransferMigrationCoordinator = .live,
        deletionOutcomeVault: NativeAccountDeletionOutcomeVault = .live,
        credentialScrubber: NativeLocalProfileCredentialScrubber = .live,
        clearShortcutDistributionApproval:@escaping @MainActor () throws -> Void = {
            try ShortcutDistributionApprovalStore.clear()
        },
        readShortcutDistributionApproval:@escaping @MainActor () throws -> String? = {
            try ShortcutDistributionApprovalStore.approvedOriginChecked()
        },
        localProfileStateIsCleared:@escaping @MainActor () -> Bool = {
            BackgroundExecutionCoordinator.latestStatus() == nil
                && !SandboxStore.shared.connected
                && UserDefaults.standard.object(forKey:"sandboxBookmark") == nil
                && UserDefaults.standard.object(forKey:"githubTarget") == nil
                && UserDefaults.standard.object(forKey:"policy") == nil
                && AppProvider.allCases.allSatisfy {
                    UserDefaults.standard.object(forKey:"adapter.\($0.rawValue)") == nil
                }
        },
        nativeSessionNow:@escaping @MainActor ()->Date = {Date()}
    ) {
        self.nativeAuth=nativeAuth
        self.accountModeVault=accountModeVault
        self.transferBlockVault=transferBlockVault
        self.transferMigration=transferMigration
        self.deletionOutcomeVault=deletionOutcomeVault
        self.deletionCompletionRecovery=NativeAccountDeletionCompletionRecovery(outcomeVault:deletionOutcomeVault)
        self.credentialScrubber=credentialScrubber
        self.clearShortcutDistributionApproval=clearShortcutDistributionApproval
        self.readShortcutDistributionApproval=readShortcutDistributionApproval
        self.localProfileStateIsCleared=localProfileStateIsCleared
        self.nativeSessionNow=nativeSessionNow
        if let saved=UserDefaults.standard.data(forKey:"policy"),var parsed=try? JSONDecoder().decode(ResourcePolicy.self,from:saved){if parsed.provider=="openai"{parsed.provider="chatgpt"};if let valid=try? parsed.validated(){policy=valid}}
        Keychain.delete("openaiKey");Keychain.delete("openaiModel")
        do {
            if try transferMigration.resumePendingMigration() {
                progress="Verified Apple transfer metadata recovery completed. Apple credential state must still be checked before hosted sync resumes."
            }
        } catch {
            self.error="A verified Apple transfer is incomplete. Hosted sync remains blocked until local metadata recovery succeeds. \(error.localizedDescription)"
        }
        userID=Keychain.get("appleUser") ?? ""
        do {
            if let blockedUser=try transferBlockVault.load() {
                guard blockedUser == userID else {
                    throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_CONFLICT")
                }
                appleTransferRecoveryUserID=blockedUser
                progress="A verified Apple transfer reauthorization is required before hosted sync can resume."
            }
        } catch {
            self.error="Hosted sync is blocked because the saved Apple transfer state needs recovery. \(error.localizedDescription)"
        }
        do {
            if let outcome=try deletionOutcomeVault.load() {
                try finishConfirmedAccountDeletion(outcome)
            } else {
                try SandboxStore.shared.restore();refresh()
            }
        } catch {self.error="Hosted account cleanup needs attention. \(error.localizedDescription)";refresh()}
        appleCredentialRevocationObserver=NotificationCenter.default.addObserver(
            forName:ASAuthorizationAppleIDProvider.credentialRevokedNotification,
            object:nil,
            queue:.main
        ){[weak self] _ in Task{@MainActor in self?.recheckAppleCredentialState()}}
        significantTimeChangeObserver=NotificationCenter.default.addObserver(
            forName:UIApplication.significantTimeChangeNotification,
            object:nil,
            queue:.main
        ){[weak self] _ in Task{@MainActor in self?.reconcileNativeSessionAuthorityAfterTimeChange()}}
        recheckAppleCredentialState()
    }
    isolated deinit {
        nativeSessionExpiryTask?.cancel()
        if let appleCredentialRevocationObserver{NotificationCenter.default.removeObserver(appleCredentialRevocationObserver)}
        if let significantTimeChangeObserver{NotificationCenter.default.removeObserver(significantTimeChangeObserver)}
    }
    func applicationDidBecomeActive(){
        reconcileNativeSessionAuthorityAfterTimeChange()
        refresh()
        recheckAppleCredentialState()
    }
    var nativeSessionAuthorityAvailable:Bool {
        guard let nativeSessionExpiry else{return false}
        return NativeBearerAuthorityWindow(expiresAt:nativeSessionExpiry)
            .isAvailable(at:nativeSessionNow())
    }
    private func requireNativeSessionAuthority()->Bool {
        guard nativeSessionAuthorityAvailable else {
            if nativeSessionExpiry == nil {downgradeAppleCredentialReviewClear()}
            else {invalidateAuthLifecycle()}
            return false
        }
        return true
    }
    private func setNativeSessionExpiry(_ expiry:Date?) {
        guard let expiry,
              NativeBearerAuthorityWindow(expiresAt:expiry).isAvailable(at:nativeSessionNow()) else {
            clearNativeSessionAuthority()
            return
        }
        nativeSessionExpiry=expiry
        scheduleNativeSessionExpiryTask(for:expiry)
    }
    private func scheduleNativeSessionExpiryTask(for expiry:Date) {
        cancelNativeSessionExpiryTask()
        let window=NativeBearerAuthorityWindow(expiresAt:expiry)
        guard let remaining=window.remainingSeconds(at:nativeSessionNow()) else {
            invalidateAuthLifecycle()
            return
        }
        let generation=nativeSessionExpiryGeneration.capture()
        nativeSessionExpiryTask=Task{@MainActor [weak self] in
            do {try await Task<Never,Never>.sleep(for:.seconds(remaining))}
            catch {return}
            self?.nativeSessionExpiryTaskFired(expectedExpiry:expiry,generation:generation)
        }
    }
    private func nativeSessionExpiryTaskFired(expectedExpiry:Date,generation:UInt64) {
        guard nativeSessionExpiryGeneration.isCurrent(generation),
              nativeSessionExpiry == expectedExpiry else{return}
        let window=NativeBearerAuthorityWindow(expiresAt:expectedExpiry)
        if window.isAvailable(at:nativeSessionNow()) {
            scheduleNativeSessionExpiryTask(for:expectedExpiry)
        } else {
            invalidateAuthLifecycle()
        }
    }
    private func reconcileNativeSessionAuthorityAfterTimeChange() {
        guard let nativeSessionExpiry else {
            clearNativeSessionAuthority()
            return
        }
        let window=NativeBearerAuthorityWindow(expiresAt:nativeSessionExpiry)
        guard window.isAvailable(at:nativeSessionNow()) else {
            invalidateAuthLifecycle()
            return
        }
        scheduleNativeSessionExpiryTask(for:nativeSessionExpiry)
    }
    private func cancelNativeSessionExpiryTask() {
        nativeSessionExpiryGeneration.invalidate()
        nativeSessionExpiryTask?.cancel()
        nativeSessionExpiryTask=nil
    }
    private func clearNativeSessionAuthority() {
        cancelNativeSessionExpiryTask()
        nativeSessionExpiry=nil
        downgradeAppleCredentialReviewClear()
    }
    private func suspendNativeSessionAuthorityForCredentialCheck() {
        appleCredentialReviewLifecycleGeneration.invalidate()
        checkingAppleCredentialReview=false
        acknowledgingAppleCredentialReview=false
        clearNativeSessionAuthority()
    }
    private func refreshNativeSessionIfNeeded(
        whileHostedAdmissionBlocked:Bool=false
    ) async -> Bool {
        guard appleTransferRecoveryUserID == nil else { return false }
        let refreshGeneration=authLifecycleGeneration.capture()
        do {
            guard let session = try await nativeAuth.refreshIfNeeded(
                persistenceGeneration:refreshGeneration,
                allowWhileHostedAdmissionBlocked:whileHostedAdmissionBlocked
            ) else {
                guard authLifecycleGeneration.isCurrent(refreshGeneration) else{return false}
                clearNativeSessionAuthority()
                return false
            }
            guard authLifecycleGeneration.isCurrent(refreshGeneration),unlocked else{return false}
            setNativeSessionExpiry(Date(timeIntervalSince1970:TimeInterval(session.expiresAt)))
            if !whileHostedAdmissionBlocked { await refreshAppleCredentialReview() }
            guard authLifecycleGeneration.isCurrent(refreshGeneration),unlocked else{return false}
            return true
        } catch {
            guard authLifecycleGeneration.isCurrent(refreshGeneration) else{return false}
            NativeHostedAccessAdmission.block()
            clearNativeSessionAuthority()
            refresh()
            self.error="Apple could not revalidate hosted sync. Hosted authority is blocked while exact revocation follow-up is retained; retry or sign in again after recovery. \(error.localizedDescription)"
            return false
        }
    }
    private func recheckAppleCredentialState(){
        let checkedUserID=userID
        guard !checkedUserID.isEmpty else{return}
        appleCredentialStateGeneration.invalidate()
        let credentialStateGeneration=appleCredentialStateGeneration.capture()
        NativeHostedAccessAdmission.block()
        suspendNativeSessionAuthorityForCredentialCheck()
        NotificationCenter.default.post(name:.localSandboxDidLock,object:nil)
        ASAuthorizationAppleIDProvider().getCredentialState(forUserID:checkedUserID){state,error in
            Task{@MainActor in
                guard self.appleCredentialStateGeneration.isCurrent(credentialStateGeneration),
                      self.userID == checkedUserID else{return}
                guard error == nil else {
                    self.error="Apple credential state could not be verified. Hosted sync remains blocked."
                    return
                }
                switch state {
                case .transferred:
                    await self.blockHostedAccessForTransferredCredential(checkedUserID)
                case .revoked, .notFound:
                    self.appleTransferRecoveryUserID=nil
                    if self.nativeAuth.hasPendingAccountDeletion(){self.refresh()}
                    else{await self.deleteProfile()}
                case .authorized:
                    if self.nativeAuth.hasPendingAccountDeletion() {
                        self.refresh()
                        self.progress="Hosted sync remains blocked until the pending hosted-account deletion is finished, reauthenticated, or explicitly discarded."
                        return
                    }
                    do {
                        if let blockedUser=try self.transferBlockVault.load() {
                            self.appleTransferRecoveryUserID=blockedUser
                            self.progress="Apple transfer recovery remains blocked until you complete the pinned Sign in with Apple flow."
                            return
                        }
                    } catch {
                        self.error="Hosted sync is blocked because the saved Apple transfer state needs recovery. \(error.localizedDescription)"
                        return
                    }
                    guard self.unlocked else {
                        self.progress="Unlock Local Sandbox before restoring hosted sync authority."
                        return
                    }
                    let storedUser:String?
                    do {storedUser=try Keychain.getChecked("appleUser")}
                    catch {
                        self.error="Hosted sync remains blocked because the stored Apple profile could not be read safely. \(error.localizedDescription)"
                        return
                    }
                    guard storedUser == checkedUserID else {
                        self.error="Hosted sync remains blocked because Apple's authorized identity does not match the exact stored profile."
                        return
                    }
                    let activationGeneration=self.authLifecycleGeneration.capture()
                    do {
                        if let resumed=try await self.nativeAuth.resumeOrdinaryPendingActivation(
                            accountBinding:checkedUserID,
                            persistenceGeneration:activationGeneration
                        ) {
                            guard self.authLifecycleGeneration.isCurrent(activationGeneration),
                                  self.appleCredentialStateGeneration.isCurrent(credentialStateGeneration),
                                  self.unlocked,
                                  self.userID == checkedUserID else{return}
                            self.setNativeSessionExpiry(
                                Date(timeIntervalSince1970:TimeInterval(resumed.expiresAt))
                            )
                        }
                    } catch {
                        guard self.authLifecycleGeneration.isCurrent(activationGeneration),
                              self.appleCredentialStateGeneration.isCurrent(credentialStateGeneration),
                              self.userID == checkedUserID else{return}
                        self.error="The saved hosted authorization could not be activated safely. Hosted sync remains blocked. \(error.localizedDescription)"
                        return
                    }
                    guard self.authLifecycleGeneration.isCurrent(activationGeneration),
                          self.appleCredentialStateGeneration.isCurrent(credentialStateGeneration),
                          self.unlocked,
                          self.userID == checkedUserID else{return}
                    guard await self.refreshNativeSessionIfNeeded(
                        whileHostedAdmissionBlocked:true
                    ) else{return}
                    guard self.authLifecycleGeneration.isCurrent(activationGeneration),
                          self.appleCredentialStateGeneration.isCurrent(credentialStateGeneration),
                          self.unlocked,
                          self.userID == checkedUserID else{return}
                    NativeHostedAccessAdmission.allowAfterCredentialVerification()
                    await self.refreshAppleCredentialReview()
                @unknown default:
                    self.error="Apple returned an unknown credential state. Hosted sync stays blocked until the state can be reviewed."
                }
            }
        }
    }
    private func blockHostedAccessForTransferredCredential(_ oldUser:String) async {
        NativeHostedAccessAdmission.block()
        invalidateAuthLifecycle()
        let transferGeneration=authLifecycleGeneration.capture()
        appleTransferRecoveryUserID=oldUser
        NotificationCenter.default.post(name:.localSandboxDidLock,object:nil)
        do {try transferBlockVault.block(oldUser:oldUser)}
        catch {
            self.error="Hosted sync is blocked in this process, but the transfer block could not be saved. Keep Local Sandbox closed if you cannot finish reauthorization now. \(error.localizedDescription)"
            return
        }
        let preparedSessions:NativePreparedAppleSessionRetirement
        do {preparedSessions=try nativeAuth.prepareSessionsForRetirement()}
        catch {
            self.error="The transfer block was saved, but active and pending hosted authorizations could not be atomically handed to revocation follow-up. Their Keychain evidence and the stored profile were kept. \(error.localizedDescription)"
            return
        }
        if !preparedSessions.sessions.isEmpty {await finishPreparedSessionRetirement(
            preparedSessions,
            context:"The transferred credential's hosted bearer was disabled locally."
        )}
        guard authLifecycleGeneration.isCurrent(transferGeneration),
              appleTransferRecoveryUserID == oldUser else{return}
        refresh()
        progress="Apple reports that this credential was transferred. Tap Sign in with Apple to reauthorize the stored identity; hosted sync stays locked until the server verifies Apple's old/new identifier continuity."
    }
    func unlock(executionGeneration:ExecutionContinuationGate.Generation) async {
        do {
            let localAccessLease=try await LocalAccess.authenticate(executionGeneration:executionGeneration)
            try localAccessLease.requireCurrent()
            try SandboxStore.shared.restore()
            try localAccessLease.requireCurrent()
            try prepare()
            try localAccessLease.requireCurrent()
            unlocked=true
            refresh()
            recheckAppleCredentialState()
        } catch {self.error=error.localizedDescription}
    }
    func connect(_ url:URL) {do {try SandboxStore.shared.connect(url);try prepare();refresh()}catch{self.error=error.localizedDescription}}
    func prepare() throws {
        let result=try WorkspacePreparationService.live.prepare(defaultPolicy:policy)
        policy=result.policy
        if let status=result.status{progress=status}
    }
    func refresh() {
        backgroundStatus=BackgroundExecutionCoordinator.latestStatus()
        do {nativeRevocationFollowUp=try nativeAuth.pendingRevocationStatus()}
        catch {nativeRevocationFollowUp=nil;if self.error.isEmpty{self.error="The saved native-session revocation follow-up could not be read or scrubbed. \(error.localizedDescription)"}}
        switch nativeAuth.accountDeletionRecoveryState() {
            case .recoverable(let attempt):
                appleAccountDeletionPending=true
                appleAccountDeletionNeedsReauthentication=attempt.requiresReauthentication
                appleAccountDeletionNeedsDiscard=false
                appleAccountMode=attempt.accountMode
                setNativeSessionExpiry(nil)
            case .none:
                appleAccountDeletionPending=false
                appleAccountDeletionNeedsReauthentication=false
                appleAccountDeletionNeedsDiscard=false
                let session=NativeBearerVault.live.load()
                do {
                    if let session {appleAccountMode=session.accountMode}
                    else {appleAccountMode=userID.isEmpty ? nil : try accountModeVault.load(accountBinding:userID)}
                }
                catch {appleAccountMode=nil;self.error="The saved Apple account mode is unreadable. Sign in with Apple again before changing hosted account access. \(error.localizedDescription)"}
                setNativeSessionExpiry(session.map { Date(timeIntervalSince1970: TimeInterval($0.expiresAt)) })
            case .requiresExplicitDiscard:
                let firstDetection = !appleAccountDeletionNeedsDiscard
                appleAccountDeletionPending=true
                appleAccountDeletionNeedsReauthentication=false
                appleAccountDeletionNeedsDiscard=true
                appleAccountMode=nil
                setNativeSessionExpiry(nil)
                if firstDetection {
                    self.error="The saved hosted-account deletion recovery is expired or unreadable. It was retained. Discard that local retry record before starting a fresh Apple sign-in."
                }
        }
        if nativeSessionExpiry == nil {downgradeAppleCredentialReviewClear()}
        do {if let outcome=try deletionOutcomeVault.load(){accountDeletionNotice=deletionNotice(outcome)}}
        catch {self.error="The saved hosted-account deletion result is unreadable. \(error.localizedDescription)"}
        connected=SandboxStore.shared.connected;folderName=SandboxStore.shared.folderName
        guard connected else {files=[];receipts=[];checkpoint=nil;corruptExecutionStates=[];executionStateInspectionError="";return}
        do {files=try SandboxStore.shared.listWorkspaceFilesRecursively();receipts=try SandboxStore.shared.receipts()}catch{self.error=error.localizedDescription}
        do {
            let state=try ExecutionStateInspector.inspect()
            checkpoint=state.checkpoint.flatMap{["planning","executing","ready"].contains($0.phase) ? $0:nil}
            corruptExecutionStates=state.corrupt
            executionStateInspectionError=""
        } catch {
            checkpoint=nil
            corruptExecutionStates=[]
            executionStateInspectionError="Execution state could not be inspected. New tasks remain blocked. \(error.localizedDescription)"
        }
    }
    func savePolicy() {do {let valid=try policy.validated();if connected{try SandboxStore.shared.save(valid,path:"config/policy.json")};UserDefaults.standard.set(try JSONEncoder().encode(valid),forKey:"policy");LocalSandboxShortcuts.updateAppShortcutParameters();progress="Authorization saved on this iPhone"}catch{self.error=error.localizedDescription}}
    func saveProviderOnly(_ provider:AppProvider) {do {var authorized=try SavedExecutionAuthorization.load();authorized.provider=provider.rawValue;let valid=try authorized.validated();if connected{try SandboxStore.shared.save(valid,path:"config/policy.json")};UserDefaults.standard.set(try JSONEncoder().encode(valid),forKey:"policy");policy=valid;LocalSandboxShortcuts.updateAppShortcutParameters();progress="Saved provider is now \(provider.title); authorized resource limits were preserved"}catch{self.error=error.localizedDescription}}
    func run(_ goal:String,contract:GoalContract,selection:ProviderSelection = .saved,executionGeneration:ExecutionContinuationGate.Generation) async {
        guard checkpoint == nil,corruptExecutionStates.isEmpty,executionStateInspectionError.isEmpty else {error="Inspect the interrupted or corrupt execution state before starting another task.";return}
        running=true;defer{running=false;refresh()}
        do {
            let route=try ProviderRuntimeCapabilities.resolve(selection:selection,policy:policy)
            guard case .onDeviceApple=route.decision else{throw SandboxError.blocked("The resolved provider must continue through its configured Shortcut.")}
            guard let routingEvidence=route.evidence else{throw SandboxError.blocked("ROUTING_EVIDENCE_NOT_COMMITTABLE")}
            var routedPolicy=policy;routedPolicy.provider=route.provider.rawValue
            let result=try await AgentRunner.shared.run(goal:goal,policy:try routedPolicy.validated(),contract:contract,authorizationPolicy:policy,taskOrigin:.app,routingEvidence:routingEvidence,executionGeneration:executionGeneration,onProgress:{self.progress=$0})
            progress="\(result.status.rawValue): \(result.summary)"
        }catch{self.error=error.localizedDescription}
    }
    func applyOracleRecommendation(){do{var authorized=try SavedExecutionAuthorization.load();let provider=try ProviderRuntimeCapabilities.oracleRecommendation(policy:authorized);authorized.provider=provider.rawValue;let valid=try authorized.validated();try ProviderQualificationStore.recordRecommendation(provider:provider,policy:valid);try SandboxStore.shared.save(valid,path:"config/policy.json");UserDefaults.standard.set(try JSONEncoder().encode(valid),forKey:"policy");policy=valid;LocalSandboxShortcuts.updateAppShortcutParameters();progress="Oracle pinned \(provider.title) from fresh device checks; authorized resource limits were preserved"}catch{self.error=error.localizedDescription}}
    func resumeCheckpoint(executionGeneration:ExecutionContinuationGate.Generation) async {
        guard let checkpoint,BackgroundExecutionPolicy.resumablePhases.contains(checkpoint.phase),checkpoint.policy != nil else{error="This checkpoint requires review and cannot be resumed automatically.";return}
        running=true;defer{running=false;refresh()}
        do{let result=try await AgentRunner.shared.resume(checkpoint:checkpoint,executionGeneration:executionGeneration){self.progress=$0};progress="\(result.status.rawValue): \(result.summary)"}catch{self.error=error.localizedDescription}
    }
    func acknowledgeCheckpoint() {
        guard let checkpoint else{return}
        guard !running,!AgentRunner.shared.running else{error="Wait for the native runner to stop before acknowledging its checkpoint.";return}
        do {
            let reviewPath=try SandboxStore.shared.acknowledgeCheckpoint(expected:checkpoint)
            progress="Checkpoint preserved at \(reviewPath.value). No action replayed."
            refresh()
        } catch {self.error=error.localizedDescription;refresh()}
    }
    func corruptExecutionStateData(_ record:CorruptExecutionState) throws -> Data {
        try SandboxStore.shared.corruptExecutionStateData(record)
    }
    func preserveAndDiscardCorruptExecutionState(_ record:CorruptExecutionState) {
        guard !running,!AgentRunner.shared.running else{error="Wait for the native runner to stop before reviewing execution state.";return}
        do {
            let reviewPath=try SandboxStore.shared.preserveAndDiscardCorruptExecutionState(record)
            progress="Original bytes quarantined at \(reviewPath.value). The corrupt \(record.sourcePath) file was removed."
            refresh()
        } catch {self.error=error.localizedDescription;refresh()}
    }
    func completeAppleSignIn(
        user: String,
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        transferRecoveryUser: String?
    ) async {
        NativeHostedAccessAdmission.block()
        invalidateAuthLifecycle()
        let pendingGeneration=authLifecycleGeneration.capture()
        do {_ = try NativeAppleAuthorizationCode.validated(authorizationCode)}
        catch {self.error=error.localizedDescription;return}
        let previous:String?
        do {previous=try Keychain.getChecked("appleUser")}
        catch {self.error=error.localizedDescription;return}
        if let transferRecoveryUser {
            guard appleTransferRecoveryUserID == transferRecoveryUser,
                  previous == transferRecoveryUser else {
                error="The transferred Apple identity changed before reauthorization. No local profile was modified."
                return
            }
        } else if appleTransferRecoveryUserID != nil {
            error="Finish the transferred Apple identity review before starting a different sign-in."
            return
        }
        do {
            if try deletionOutcomeVault.load() != nil {
                error="Dismiss the completed hosted-account update before signing in again."
                return
            }
            if let pending=try nativeAuth.pendingAccountDeletion() {
                appleAccountDeletionPending=true
                appleAccountDeletionNeedsReauthentication=pending.requiresReauthentication
                appleAccountMode=pending.accountMode
                let deletionAccountBinding=transferRecoveryUser ?? user
                guard try pending.belongs(to:deletionAccountBinding) else {
                    error="The pending hosted-account deletion belongs to a different Apple identity. Finish or explicitly discard it before switching identities."
                    return
                }
                guard pending.requiresReauthentication else {
                    error="Finish the pending hosted-account deletion before signing in again."
                    return
                }
                if try nativeAuth.validatePendingActivationContextIfPresent(
                    targetAccountBinding:deletionAccountBinding,
                    purpose:.deletionReauthorization,
                    transferRecoveryUser:transferRecoveryUser
                ) {
                    guard unlocked,previous == (transferRecoveryUser ?? deletionAccountBinding) else {
                        error="Unlock the exact stored Apple profile before resuming its pending hosted-account authorization."
                        return
                    }
                }
                let capturedGeneration=authLifecycleGeneration.capture()
                _ = try await nativeAuth.reauthorizePendingAccountDeletion(
                    identityToken:identityToken,
                    authorizationCode:authorizationCode,
                    rawNonce:rawNonce,
                    accountBinding:deletionAccountBinding,
                    transferRecoveryUser:transferRecoveryUser,
                    persistenceGeneration:capturedGeneration
                )
                guard authLifecycleGeneration.isCurrent(capturedGeneration) else {
                    refresh()
                    return
                }
                appleAccountDeletionNeedsReauthentication=false
                await deleteHostedAppleAccount()
                return
            }
        } catch {
            guard authLifecycleGeneration.isCurrent(pendingGeneration) else{return}
            refresh()
            self.error="The hosted-account deletion retry could not be reauthenticated. \(error.localizedDescription)"
            return
        }
        let verifiedTransfer=transferRecoveryUser != nil
        let switchingProfile=previous != nil && previous != user && !verifiedTransfer
        do {
            if switchingProfile {
                error="This Apple credential is a different account, not a server-verified transfer. Delete the current local profile explicitly before signing in as another Apple user."
                return
            }
            if let transferRecoveryUser {
                guard previous == transferRecoveryUser,user != transferRecoveryUser else {
                    error="The transferred Apple identity did not produce a distinct server-verifiable replacement. No local profile was modified."
                    return
                }
            }
            if nativeAuth.hasPendingAccountDeletion() {
                appleAccountDeletionPending=true
                error="Retry the pending hosted-account deletion before signing in again."
                return
            }
            let activationPurpose:NativeAppleActivationPurpose=verifiedTransfer ? .transferRecovery:.ordinary
            if try nativeAuth.validatePendingActivationContextIfPresent(
                targetAccountBinding:user,
                purpose:activationPurpose,
                transferRecoveryUser:transferRecoveryUser
            ) {
                guard unlocked,previous == (transferRecoveryUser ?? user) else {
                    error="Unlock the exact stored Apple profile before resuming its pending hosted-account authorization."
                    return
                }
            }
            if !switchingProfile && !verifiedTransfer {
                try Keychain.set(user,for:"appleUser")
                userID=user;unlocked=true
                try SandboxStore.shared.restore();try prepare();refresh()
            }
        } catch {
            self.error=error.localizedDescription
            return
        }
        let capturedGeneration=authLifecycleGeneration.capture()
        do {
            let session=try await nativeAuth.connect(
                identityToken:identityToken,
                authorizationCode:authorizationCode,
                rawNonce:rawNonce,
                targetAccountBinding:user,
                transferRecoveryUser:transferRecoveryUser,
                persistenceGeneration:capturedGeneration
            )
            guard authLifecycleGeneration.isCurrent(capturedGeneration) else {
                refresh()
                return
            }
            if verifiedTransfer,let transferRecoveryUser {
                do {
                    try transferMigration.migrateVerifiedTransfer(
                        from:transferRecoveryUser,
                        to:user,
                        verifiedAccountMode:session.accountMode
                    )
                    userID=user
                    NativeHostedAccessAdmission.allowAfterCredentialVerification()
                    refresh()
                } catch {
                    try? await nativeAuth.retireIssuedSession(session,pendingDeletion:false)
                    throw error
                }
            }
            if !verifiedTransfer {
                do {try accountModeVault.save(session.accountMode,accountBinding:user)}
                catch {
                    let modeError=error
                    do {try await nativeAuth.disconnect()}
                    catch {throw SandboxError.blocked("APPLE_NATIVE_SESSION_CLEANUP_FAILED: \(error.localizedDescription)")}
                    throw modeError
                }
                NativeHostedAccessAdmission.allowAfterCredentialVerification()
            }
            appleAccountMode=session.accountMode
            appleTransferRecoveryUserID=nil
            accountDeletionNotice=nil
            setNativeSessionExpiry(Date(timeIntervalSince1970:TimeInterval(session.expiresAt)))
            nativeRevocationFollowUp=try? nativeAuth.pendingRevocationStatus()
            progress=nativeRevocationFollowUp == nil
                ? "Local profile ready; encrypted hosted sync connected for 15 minutes."
                : "Local profile ready; encrypted hosted sync connected. A prior session remains queued until the server confirms Apple grant revocation; its saved horizon is diagnostic only."
            await refreshAppleCredentialReview()
        } catch {
            guard authLifecycleGeneration.isCurrent(capturedGeneration) else{return}
            refresh()
            self.error=verifiedTransfer
                ? "Apple transfer continuity or local metadata migration could not be proven. The original local workspace is preserved and hosted sync remains blocked. \(error.localizedDescription)"
                : switchingProfile
                    ? "The requested Apple profile was not accepted, so the existing local profile was kept unchanged. \(error.localizedDescription)"
                    : "Your local workspace is ready. Encrypted hosted sync is unavailable until you sign in again: \(error.localizedDescription)"
        }
    }
    func disconnectNativeSync(executionGeneration:ExecutionContinuationGate.Generation) async {
        do {try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)}
        catch {return}
        NativeHostedAccessAdmission.block()
        invalidateAuthLifecycle()
        NotificationCenter.default.post(name:.localSandboxDidLock,object:nil)
        do {try await nativeAuth.disconnect();progress="Native sync session revoked"}
        catch {
            nativeRevocationFollowUp=try? nativeAuth.pendingRevocationStatus()
            let retainedBearer:Bool
            do {retainedBearer=try nativeAuth.vault.loadForRetirement() != nil}
            catch {
                transitionToLocked(notifyNativeSync:false)
                self.error="The hosted bearer could not be verified or removed from Keychain, so Local Sandbox was locked. Retry Lock now before using hosted sync. \(error.localizedDescription)"
                return
            }
            if !retainedBearer {
                reportNativeRevocationFollowUp(error,context:"The native bearer was cleared locally.")
            } else {
                transitionToLocked(notifyNativeSync:false)
                self.error="The hosted bearer could not be removed from Keychain, so Local Sandbox was locked. Retry Lock now before using hosted sync. \(error.localizedDescription)"
                return
            }
        }
    }
    func retryNativeRevocationFollowUp() async {
        do {
            let remaining=try await nativeAuth.retryPendingRevocations()
            refresh()
            if let remaining {
                self.error="The server did not yet confirm every native-session revocation. \(remaining.count) checked follow-up \(remaining.count == 1 ? "remains":"remain") saved on this iPhone."
            } else {
                self.error=""
                progress="Native-session revocation follow-up completed."
            }
        } catch {
            refresh()
            self.error="The saved native-session revocation follow-up could not be retried safely. \(error.localizedDescription)"
        }
    }
    func refreshAppleCredentialReview() async {
        guard !acknowledgingAppleCredentialReview else { return }
        guard requireNativeSessionAuthority() else{return}
        appleCredentialReviewLifecycleGeneration.invalidate()
        let generation=appleCredentialReviewLifecycleGeneration.capture()
        let authGeneration=authLifecycleGeneration.capture()
        checkingAppleCredentialReview=true
        defer {
            if appleCredentialReviewLifecycleGeneration.isCurrent(generation) {
                checkingAppleCredentialReview=false
            }
        }
        do {
            guard let review=try await nativeAuth.possibleCredentialReview() else {
                guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                      authLifecycleGeneration.isCurrent(authGeneration) else{return}
                invalidateAuthLifecycle()
                return
            }
            guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                  authLifecycleGeneration.isCurrent(authGeneration) else{return}
            applyAppleCredentialReview(review)
        } catch let serviceError as NativeServiceError {
            guard !Task.isCancelled else{return}
            guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                  authLifecycleGeneration.isCurrent(authGeneration) else{return}
            if serviceError.status == 401 { invalidateAuthLifecycle() }
            self.error="Apple credential cleanup status could not be verified. The last visible warning, if any, was kept. Sign in again if the native session expired. \(serviceError.localizedDescription)"
        } catch {
            guard !Task.isCancelled else{return}
            guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                  authLifecycleGeneration.isCurrent(authGeneration) else{return}
            if error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED" {
                invalidateAuthLifecycle()
            }
            self.error="Apple credential cleanup status could not be verified. The last visible warning, if any, was kept. Sign in again if the native session expired. \(error.localizedDescription)"
        }
    }
    func acknowledgeAppleCredentialReview() async {
        guard !acknowledgingAppleCredentialReview else{return}
        guard requireNativeSessionAuthority() else{return}
        guard case .required(let receipt)=appleCredentialReview else{return}
        appleCredentialReviewLifecycleGeneration.invalidate()
        let generation=appleCredentialReviewLifecycleGeneration.capture()
        let authGeneration=authLifecycleGeneration.capture()
        checkingAppleCredentialReview=false
        acknowledgingAppleCredentialReview=true
        defer {
            if appleCredentialReviewLifecycleGeneration.isCurrent(generation) {
                acknowledgingAppleCredentialReview=false
            }
        }
        do {
            let current=try await nativeAuth.acknowledgePossibleCredentialReview(receipt.acknowledgementID)
            guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                  authLifecycleGeneration.isCurrent(authGeneration),
                  case .required(let displayedReceipt)=appleCredentialReview,
                  displayedReceipt.acknowledgementID == receipt.acknowledgementID else{return}
            applyAppleCredentialReview(current)
            switch current {
            case .clear:
                progress="Apple Account review was confirmed for the current hosted cleanup receipt."
            case .required:
                progress="Apple credential cleanup changed during confirmation. Review the current detection before confirming again."
            }
        } catch let serviceError as NativeServiceError {
            guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                  authLifecycleGeneration.isCurrent(authGeneration) else{return}
            if serviceError.status == 401 { invalidateAuthLifecycle() }
            let refreshCodes:Set<String>=[
                "APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED",
                "APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS",
                "APPLE_ACCOUNT_DELETION_IN_PROGRESS",
                "APPLE_IDENTITY_LINK_MISSING",
            ]
            if serviceError.status == 409,refreshCodes.contains(serviceError.code) {
                do {
                    if let current=try await nativeAuth.possibleCredentialReview(),
                       appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                       authLifecycleGeneration.isCurrent(authGeneration) {
                        applyAppleCredentialReview(current)
                    }
                } catch {
                    guard !Task.isCancelled else{return}
                    self.error="Apple credential cleanup changed, and the current status could not be refreshed. The existing warning was kept. \(error.localizedDescription)"
                    return
                }
            }
            self.error=appleCredentialReviewErrorMessage(serviceError)
        } catch {
            guard !Task.isCancelled else{return}
            guard appleCredentialReviewLifecycleGeneration.isCurrent(generation),
                  authLifecycleGeneration.isCurrent(authGeneration) else{return}
            if error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED" {
                invalidateAuthLifecycle()
            }
            self.error="Apple Account review was not confirmed. The existing cleanup warning was kept. \(error.localizedDescription)"
        }
    }
    private func retireActiveAgentRunForLock() {
        AgentRunner.shared.pauseForSystemInterruption(reason:"LOCAL_SANDBOX_LOCKED")
    }
    private func transitionToLocked(notifyNativeSync:Bool=true) {
        NativeHostedAccessAdmission.block()
        retireActiveAgentRunForLock()
        invalidateAuthLifecycle()
        unlocked=false
        if notifyNativeSync {NotificationCenter.default.post(name:.localSandboxDidLock,object:nil)}
    }
    func lock() {
        transitionToLocked()
        let preparedSessions:NativePreparedAppleSessionRetirement
        do {preparedSessions=try nativeAuth.prepareSessionsForRetirement()}
        catch {
            self.error="Local Sandbox was locked, but active and pending hosted authorizations could not be atomically handed to revocation follow-up. Their Keychain evidence remains blocked from use. \(error.localizedDescription)"
            return
        }
        guard !preparedSessions.sessions.isEmpty else{return}
        Task{@MainActor [weak self] in
            await self?.finishPreparedSessionRetirement(
                preparedSessions,
                context:"Local Sandbox was locked and its hosted bearer was disabled locally."
            )
        }
    }
    func suspendForSystemTransition() {transitionToLocked()}
    func deleteProfile() async {
        NativeHostedAccessAdmission.block()
        invalidateAuthLifecycle()
        let preparedSessions:NativePreparedAppleSessionRetirement
        do {preparedSessions=try nativeAuth.prepareSessionsForRetirement()}
        catch {
            self.error="Active and pending hosted authorizations could not be atomically handed to revocation follow-up, so the local profile and its Keychain evidence were kept unchanged. \(error.localizedDescription)"
            return
        }
        do {try clearLocalProfile(
            discardPendingAccountDeletion:false,
            preserveNativeBearer:false
        )}
        catch {refresh();self.error="The local profile could not be fully removed. \(error.localizedDescription)";return}
        if !preparedSessions.sessions.isEmpty {
            await finishPreparedSessionRetirement(
                preparedSessions,
                context:"The local profile was removed from this iPhone."
            )
        }
    }
    func deleteHostedAppleAccount() async {
        guard !deletingAppleAccount else{return}
        deletingAppleAccount=true;defer{deletingAppleAccount=false}
        var serverConfirmed=false
        do {
            let pending=try nativeAuth.pendingAccountDeletion()
            let accountBinding=userID.isEmpty ? nil:userID
            guard pending != nil || accountBinding != nil else {
                throw SandboxError.blocked("Sign in with Apple before deleting hosted account data.")
            }
            let storedMode:NativeAppleAccountMode?
            if let accountBinding {storedMode=try accountModeVault.load(accountBinding:accountBinding)}
            else {storedMode=nil}
            let mode=pending?.accountMode ?? NativeBearerVault.live.load()?.accountMode ?? storedMode
            guard let mode else {throw SandboxError.blocked("APPLE_ACCOUNT_MODE_REQUIRED")}
            let result=try await nativeAuth.deleteAccount(accountBinding:accountBinding)
            serverConfirmed=true
            lockAndDisconnectLocalProfile(preserveDeletionRecovery:true)
            guard let confirmedAttempt=try nativeAuth.pendingAccountDeletion() else {
                throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
            }
            let outcome=NativeAccountDeletionOutcome(
                accountBindingHash:confirmedAttempt.accountBindingHash,
                accountMode:mode,
                manualRevocationRequired:result.providerCredentials.manualRevocationRequired,
                manualOriginRevocationRequired:result.originConnections.manualRevocationRequired
            )
            try deletionCompletionRecovery.record(outcome)
            try finishConfirmedAccountDeletion(outcome)
        } catch {
            refresh()
            if appleAccountDeletionNeedsReauthentication {
                self.error="The saved deletion key has no server receipt and its short-lived bearer expired. Sign in with the same Apple identity to refresh authorization; the app will keep the same deletion key and retry."
            } else if serverConfirmed {
                self.error="The server confirmed the hosted account change, but this iPhone did not finish verified local cleanup. Retry keeps the completion record and performs cleanup again. \(error.localizedDescription)"
            } else {
                self.error="Hosted account deletion was not confirmed. Retry keeps the same deletion request key. Your local profile and selected Files or iCloud documents remain unchanged. \(error.localizedDescription)"
            }
        }
    }
    func dismissAccountDeletionNotice() {
        do {try deletionOutcomeVault.clearChecked();accountDeletionNotice=nil}
        catch {self.error="The completed account notice could not be cleared from Keychain. \(error.localizedDescription)"}
    }
    func discardHostedAccountDeletionRecovery() async {
        NativeHostedAccessAdmission.block()
        invalidateAuthLifecycle()
        do {
            let preparedSessions=try nativeAuth.preparePendingAccountDeletionDiscard()
            try nativeAuth.discardPendingAccountDeletion()
            refresh()
            if !preparedSessions.sessions.isEmpty {
                await finishPreparedSessionRetirement(
                    preparedSessions,
                    context:"Hosted deletion recovery was discarded on this iPhone."
                )
            } else {
                progress="Hosted deletion recovery was discarded on this iPhone. You can start a fresh Apple sign-in."
            }
        } catch {
            refresh()
            self.error="The hosted deletion recovery could not be removed from Keychain. \(error.localizedDescription)"
        }
    }
    private func finishConfirmedAccountDeletion(_ outcome:NativeAccountDeletionOutcome) throws {
        guard let completedOutcome=try deletionCompletionRecovery.resume(
            scrub:{record in try clearLocalProfile(
                discardPendingAccountDeletion:false,
                hostedDeletionAccountBindingHash:record.accountBindingHash
            )},
            finalizeTransaction:{try nativeAuth.finalizeConfirmedAccountDeletion(
                accountBindingHash:outcome.accountBindingHash
            )}
        ),completedOutcome == outcome else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_OUTCOME_INVALID")
        }
        refresh()
        accountDeletionNotice=deletionNotice(completedOutcome)
    }
    private func deletionNotice(_ outcome:NativeAccountDeletionOutcome)->String {
        let completed = outcome.accountMode == .linked
            ? "Apple access was removed from the linked ChatGPT-owned Local Sandbox workspace. The workspace and other linked identities were retained."
            : "Your standalone Apple-owned Local Sandbox account and its server data were deleted."
        let followUps = [
            outcome.manualRevocationRequired
                ? "Apple may still require manual authorization removal in Apple Account settings."
                : nil,
            outcome.manualOriginRevocationRequired
                ? "Remove any remaining Local Sandbox installation in Cursor Origin settings."
                : nil,
        ].compactMap { $0 }.joined(separator: " ")
        return "\(completed) \(followUps) Selected Files and iCloud documents were not deleted."
    }
    private func clearLocalProfile(
        discardPendingAccountDeletion:Bool=true,
        hostedDeletionAccountBindingHash:String?=nil,
        preserveNativeBearer:Bool=false
    ) throws {
        guard !ProviderQualificationStore.qualificationActive else {
            throw SandboxError.blocked("FINISH_PROVIDER_QUALIFICATION_BEFORE_DELETING_PROFILE")
        }
        let transferBlockedUser=try transferBlockVault.load()
        NativeHostedAccessAdmission.block()
        lockAndDisconnectLocalProfile(preserveDeletionRecovery:!discardPendingAccountDeletion)
        try ProviderQualificationStore.reset()
        try clearShortcutDistributionApproval()
        guard try readShortcutDistributionApproval() == nil else {
            throw SandboxError.blocked("LOCAL_PROFILE_SCRUB_FAILED")
        }
        for provider in AppProvider.allCases{UserDefaults.standard.removeObject(forKey:"adapter.\(provider.rawValue)")}
        for key in ["githubTarget","policy"]{UserDefaults.standard.removeObject(forKey:key)}
        try credentialScrubber.scrubNonIdentity(
            accountBindingHash:hostedDeletionAccountBindingHash,
            includeRecoverySecrets:hostedDeletionAccountBindingHash != nil,
            preserveBearer:preserveNativeBearer
        )
        guard localProfileStateIsCleared() else {
            throw SandboxError.blocked("LOCAL_PROFILE_SCRUB_FAILED")
        }
        if let transferBlockedUser {
            try transferBlockVault.clearChecked(oldUser:transferBlockedUser)
        }
        if discardPendingAccountDeletion {try nativeAuth.discardPendingAccountDeletion()}
        // This is the profile transaction's final commit. Every other checked
        // deletion and state proof must finish while the durable identity still
        // exists so a crash or retry cannot orphan another profile's credentials.
        try credentialScrubber.clearIdentity()
    }
    private func lockAndDisconnectLocalProfile(preserveDeletionRecovery:Bool) {
        NativeHostedAccessAdmission.block()
        retireActiveAgentRunForLock()
        invalidateAuthLifecycle()
        userID="";appleAccountMode=nil;appleAccountDeletionPending=preserveDeletionRecovery&&nativeAuth.hasPendingAccountDeletion();appleAccountDeletionNeedsReauthentication=false;appleAccountDeletionNeedsDiscard=false;unlocked=false;running=false;policy=ResourcePolicy()
        files=[];receipts=[];checkpoint=nil;corruptExecutionStates=[];executionStateInspectionError="";backgroundStatus=nil
        NotificationCenter.default.post(name:.localSandboxDidLock,object:nil)
        BackgroundExecutionCoordinator.shared.resetProfileState()
        SandboxStore.shared.disconnect()
        connected=false;folderName=SandboxStore.shared.folderName
    }
    private func invalidateAuthLifecycle() {
        NativeHostedAccessAdmission.block()
        authLifecycleGeneration.invalidate()
        appleCredentialStateGeneration.invalidate()
        appleCredentialReviewLifecycleGeneration.invalidate()
        checkingAppleCredentialReview=false
        acknowledgingAppleCredentialReview=false
        clearNativeSessionAuthority()
        nativeAuth.invalidatePersistence(generation:authLifecycleGeneration.capture())
    }
    private func downgradeAppleCredentialReviewClear() {
        guard case .clear=appleCredentialReviewDisplayState else{return}
        appleCredentialReview=nil
        appleCredentialReviewDisplayState = .notChecked
    }
    private func applyAppleCredentialReview(_ review:NativeAppleCredentialReview) {
        appleCredentialReview=review
        switch review {
        case .clear:
            appleCredentialReviewDisplayState = .clear
        case .required(let receipt):
            appleCredentialReviewDisplayState = .required(
                markedAt:Date(timeIntervalSince1970:TimeInterval(receipt.markedAt))
            )
        }
    }
    private func appleCredentialReviewErrorMessage(_ error:NativeServiceError)->String {
        switch error.code {
        case "APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED":
            return "Apple credential cleanup changed while you were reviewing it. The current server status was refreshed; review the displayed detection again before confirming."
        case "APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS":
            return "Finish the active Apple sign-in or credential operation, then refresh and review Apple credential cleanup again."
        case "APPLE_ACCOUNT_DELETION_IN_PROGRESS":
            return "Finish the hosted Apple account deletion before confirming credential cleanup."
        case "APPLE_IDENTITY_LINK_MISSING":
            return "This Apple identity is no longer linked to the hosted workspace. Sign in again before reviewing credential cleanup."
        case "APPLE_NATIVE_SESSION_INVALID":
            return "The native Apple session expired. Sign in with Apple again; the unresolved cleanup warning was kept."
        case "APPLE_AUTH_CREDENTIAL_REVIEW_STATE_INVALID", "APPLE_AUTH_CREDENTIAL_REVIEW_UNAVAILABLE":
            return "The server could not verify Apple credential cleanup state. The warning was kept for a later retry."
        default:
            return "Apple Account review was not confirmed. The existing cleanup warning was kept. \(error.localizedDescription)"
        }
    }
    private func reportNativeRevocationFollowUp(
        _ failure:Error,
        context:String,
        durableFollowUpKnown:Bool=false
    ) {
        nativeRevocationFollowUp=try? nativeAuth.pendingRevocationStatus()
        if let followUp=nativeRevocationFollowUp {
            let expiry=Date(timeIntervalSince1970:TimeInterval(followUp.expiresAt))
            let noun=followUp.count == 1 ? "session":"sessions"
            error="\(context) A device-only revocation retry is saved for \(followUp.count) \(noun). Its conservative server-grant horizon is \(expiry.formatted(date:.omitted,time:.shortened)), but the exact debt remains admission-blocking until the server confirms revoke success or authoritative absence."
        } else if durableFollowUpKnown {
            error="\(context) The exact revocation follow-up was saved before local removal, but its current cleanup status could not be verified. \(failure.localizedDescription)"
        } else {
            error="\(context) The server did not confirm revocation and no follow-up could be retained. The bearer expires within 15 minutes. \(failure.localizedDescription)"
        }
    }
    private func finishPreparedSessionRetirement(
        _ prepared:NativePreparedAppleSessionRetirement,
        context:String
    ) async {
        do {
            try await nativeAuth.retirePreparedSessions(prepared)
            if try nativeAuth.pendingRevocationStatus() != nil {
                reportNativeRevocationFollowUp(
                    NativeRevocationDeferredError(
                        expiresAt:try nativeAuth.pendingRevocationStatus()?.expiresAt ?? Int(Date().timeIntervalSince1970)
                    ),
                    context:context
                )
            }
        } catch {
            reportNativeRevocationFollowUp(
                error,
                context:context,
                durableFollowUpKnown:true
            )
        }
    }
}

@main
struct LocalSandboxApp: App {
    @UIApplicationDelegateAdaptor(BackgroundAppDelegate.self) private var appDelegate
    @StateObject private var model=AppModel()
    @Environment(\.scenePhase) private var phase
    init() {LocalSandboxShortcuts.updateAppShortcutParameters()}
    var body: some Scene {WindowGroup {RootView().environmentObject(model).tint(.primary).onChange(of:phase){_,value in if value == .active{model.applicationDidBecomeActive()} else if value == .background {model.suspendForSystemTransition()}}}}
}
struct RootView: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @EnvironmentObject private var model:AppModel
    var body:some View {
        Group {if model.userID.isEmpty {WelcomeView()} else if !model.unlocked {VStack(spacing:24){Image("Brand").resizable().scaledToFit().frame(width:100,height:100);Text("Your workspace is locked").font(.title2);Button("Unlock with Face ID or passcode"){let executionGeneration=ExecutionContinuationGate.shared.capture();Task{@MainActor in await model.unlock(executionGeneration:executionGeneration)}}.buttonStyle(.borderedProminent)}} else {
            TabView {
                Tab("Inbox", systemImage: "tray") {
                    ControlView()
                }
                Tab("Sandbox", systemImage: "folder") {
                    FilesView()
                }
                Tab("Activity", systemImage: "waveform.path") {
                    ActivityView()
                }
                Tab("Settings", systemImage: "slider.horizontal.3") {
                    SettingsView()
                }
            }
            .transition(.opacity)
        }}.animation(reduceMotion ? nil:.easeInOut(duration:0.4),value:model.userID.isEmpty).alert("Local Sandbox",isPresented:Binding(get:{!model.error.isEmpty},set:{if !$0{model.error=""}})){Button("OK"){model.error=""}}message:{Text(model.error)}
    }
}
struct AppleLoginButton:View {
    @EnvironmentObject private var model:AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var state=""
    @State private var rawNonce=""
    @State private var transferRecoveryUser=""
    @State private var exchanging=false
    var body: some View {
        SignInWithAppleButton(.signIn) { request in
            do {
                model.appleAuthorizationInFlight = true
                rawNonce = try NativeAppleNonce.make()
                state = try NativeAppleNonce.make()
                request.nonce = try NativeAppleNonce.requestHash(rawNonce)
                request.state = state
                request.requestedScopes = []
                transferRecoveryUser = model.appleTransferRecoveryUserID ?? ""
                if !transferRecoveryUser.isEmpty { request.user = transferRecoveryUser }
            } catch {
                rawNonce = ""
                state = ""
                transferRecoveryUser = ""
                model.appleAuthorizationInFlight = false
                model.error = error.localizedDescription
            }
        } onCompletion: { result in
            let expectedState = state
            let nonce = rawNonce
            let requestedTransferUser = transferRecoveryUser
            state = ""
            rawNonce = ""
            transferRecoveryUser = ""
            switch result {
            case .success(let authorization):
                guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                      credential.state == expectedState, !nonce.isEmpty else {
                    model.error = "Apple credential could not be verified."
                    model.appleAuthorizationInFlight = false
                    return
                }
                guard let identityTokenData=credential.identityToken,
                      (20...16_000).contains(identityTokenData.count),
                      let identityToken=String(data:identityTokenData,encoding:.utf8),
                      identityToken.utf8.count == identityTokenData.count else {
                    model.error="Apple did not return a valid identity token. The current local profile was not changed."
                    model.appleAuthorizationInFlight = false
                    return
                }
                let authorizationCode:String
                do {authorizationCode=try NativeAppleAuthorizationCode.strictUTF8(credential.authorizationCode)}
                catch {model.error="Apple did not return a valid one-use authorization code. The current local profile was not changed.";model.appleAuthorizationInFlight=false;return}
                exchanging = true
                Task {
                    await model.completeAppleSignIn(
                        user:credential.user,
                        identityToken:identityToken,
                        authorizationCode:authorizationCode,
                        rawNonce:nonce,
                        transferRecoveryUser:requestedTransferUser.isEmpty ? nil:requestedTransferUser
                    )
                    exchanging = false
                    model.appleAuthorizationInFlight = false
                }
            case .failure(let error):
                model.appleAuthorizationInFlight = false
                model.error = error.localizedDescription
            }
        }
        .signInWithAppleButtonStyle(scheme == .dark ? .white : .black)
        .frame(height: 50)
        .clipShape(Capsule())
        .disabled(model.appleAuthorizationInFlight || exchanging || (model.appleAccountDeletionPending && !model.appleAccountDeletionNeedsReauthentication))
    }
}
struct WelcomeView:View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @EnvironmentObject private var model:AppModel
    @State private var glow=false
    @State private var discardDeletionRecovery=false
    var body:some View {
        VStack(spacing:23){
            Spacer()
            Image("Brand").resizable().scaledToFit().frame(width:145,height:145).shadow(color:.gray.opacity(glow ? 0.35:0.08),radius:glow ? 45:16).scaleEffect(glow ? 1.03:1)
            Text("Local Sandbox").font(.system(size:37,weight:.semibold))
            Text("Your apps. One workspace.").font(.title3).foregroundStyle(.secondary)
            if let notice=model.accountDeletionNotice {
                VStack(alignment:.leading,spacing:10){
                    Label("Hosted Apple account update",systemImage:"checkmark.shield").font(.headline)
                    Text(notice).font(.footnote)
                    Button("Dismiss"){model.dismissAccountDeletionNotice()}
                }.padding().frame(maxWidth:420,alignment:.leading).background(.thinMaterial,in:RoundedRectangle(cornerRadius:18))
            }
            if model.appleAccountDeletionPending {
                VStack(alignment:.leading,spacing:10){
                    Label("Hosted deletion recovery",systemImage:"arrow.clockwise.circle").font(.headline)
                    Text(deletionRecoveryMessage).font(.footnote)
                    if !model.appleAccountDeletionNeedsReauthentication && !model.appleAccountDeletionNeedsDiscard {
                        Button("Finish hosted account deletion"){Task{await model.deleteHostedAppleAccount()}}.disabled(model.deletingAppleAccount)
                    }
                    Button("Discard recovery and restart sign-in",role:.destructive){discardDeletionRecovery=true}.disabled(model.appleAuthorizationInFlight)
                }.padding().frame(maxWidth:420,alignment:.leading).background(.thinMaterial,in:RoundedRectangle(cornerRadius:18))
            }
            if let followUp=model.nativeRevocationFollowUp {
                VStack(alignment:.leading,spacing:10){
                    Label("Native-session cleanup",systemImage:"arrow.clockwise.shield").font(.headline)
                    Text("\(followUp.count) saved revocation \(followUp.count == 1 ? "retry remains":"retries remain") on this iPhone. Retry cleanup before starting another Apple sign-in.").font(.footnote)
                    Button("Retry native-session revocation"){Task{await model.retryNativeRevocationFollowUp()}}.disabled(model.appleAuthorizationInFlight)
                }.padding().frame(maxWidth:420,alignment:.leading).background(.thinMaterial,in:RoundedRectangle(cornerRadius:18))
            }
            Spacer()
            AppleLoginButton().frame(maxWidth:340)
            Text("Sign-in prepares a private workspace on this iPhone. Next, connect your app Shortcuts. App subscriptions stay in their own apps.").font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth:330)
            Spacer().frame(height:30)
        }
        .padding(30)
        .frame(maxWidth:.infinity)
        .background(Color(uiColor:.systemBackground))
        .onAppear{if !reduceMotion{withAnimation(.easeInOut(duration:2.8).repeatForever(autoreverses:true)){glow=true}}}
        .alert("Discard hosted deletion recovery?",isPresented:$discardDeletionRecovery,actions:{
            Button("Discard local retry record",role:.destructive){Task{await model.discardHostedAccountDeletionRecovery()}}.disabled(model.appleAuthorizationInFlight)
            Button("Keep recovery",role:.cancel){}
        },message:{Text("This removes only this iPhone's saved retry key and deletion bearer. It does not undo or confirm any server-side account deletion. Afterward, start a fresh Apple sign-in.")})
    }
    private var deletionRecoveryMessage:String {
        if model.appleAccountDeletionNeedsDiscard {
            return "The saved retry record is expired or unreadable and cannot be used. Discard it to unblock a fresh Apple sign-in. Server-side deletion status remains unknown."
        }
        if model.appleAccountDeletionNeedsReauthentication {
            return "The saved request key has no server receipt and its bearer expired. Sign in with the same Apple identity below to refresh authorization and retry with that same key."
        }
        return "A deletion request still needs a completion check or verified device cleanup. You can finish it without signing in again."
    }
}
struct CorruptExecutionStateDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data

    init(data: Data = Data()) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct ControlView:View {
    @EnvironmentObject private var model:AppModel
    @State private var exportDocument=CorruptExecutionStateDocument()
    @State private var exportFilename="local-sandbox-corrupt-state.bin"
    @State private var exporting=false
    @State private var pendingDiscard:CorruptExecutionState?

    var body:some View {
        NavigationStack {
            ScrollView {
                VStack(alignment:.leading,spacing:28) {
                    LazyVGrid(columns:[GridItem(.flexible()),GridItem(.flexible())],spacing:14) {
                        NavigationLink{ProvidersView()}label:{inboxCard("Provider routes",count:AppProvider.allCases.count,icon:"paperplane",color:.orange)}
                        NavigationLink{SetupView()}label:{inboxCard("Needs Attention",count:model.connected ? 1:2,icon:"bell.badge",color:.orange)}
                        NavigationLink{ActivityView()}label:{inboxCard("Working",count:workingCount,icon:"circle.dotted",color:.blue)}
                        NavigationLink{ActivityView()}label:{inboxCard("In Review",count:model.receipts.count,icon:"checkmark.circle",color:.purple)}
                    }.buttonStyle(.plain)
                    Text("Workspaces").font(.title3).foregroundStyle(.secondary)
                    VStack(spacing:0) {
                        NavigationLink{FilesView()}label:{workspaceRow(model.connected ? model.folderName:"Connect iCloud folder",icon:"folder",count:model.files.count)}
                        Divider().padding(.leading,45)
                        NavigationLink{GitHubSettingsView()}label:{workspaceRow("GitHub worktrees",icon:"arrow.triangle.branch",count:nil)}
                        Divider().padding(.leading,45)
                        NavigationLink{SettingsView()}label:{workspaceRow("Add workspace",icon:"folder.badge.plus",count:nil)}
                    }.buttonStyle(.plain)
                    if let session=ShortcutCoordinator.shared.current(),["awaiting_response","applying"].contains(session.phase) {
                        NavigationLink{OracleView()}label:{Label("Continue app handoff · step \(session.step)",systemImage:"arrow.uturn.backward").padding().frame(maxWidth:.infinity,alignment:.leading).background(.thinMaterial,in:RoundedRectangle(cornerRadius:20))}
                    }
                    if !model.executionStateInspectionError.isEmpty {
                        Label(model.executionStateInspectionError,systemImage:"exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .padding()
                    }
                    ForEach(model.corruptExecutionStates) { record in
                        corruptStateCard(record)
                    }
                    if let checkpoint=model.checkpoint {
                        VStack(alignment:.leading,spacing:12) {
                            Label("Interrupted native run",systemImage:"exclamationmark.circle")
                            Text(checkpoint.goal)
                            Text(checkpoint.lastResult).font(.footnote)
                            if BackgroundExecutionPolicy.resumablePhases.contains(checkpoint.phase),checkpoint.policy != nil {
                                Button(model.running ? "Resuming…":"Resume from safe checkpoint"){let executionGeneration=ExecutionContinuationGate.shared.capture();Task{@MainActor in await model.resumeCheckpoint(executionGeneration:executionGeneration)}}.disabled(model.running)
                            }
                            Button("I reviewed affected files"){model.acknowledgeCheckpoint()}
                                .disabled(model.running)
                        }.padding().background(.thinMaterial,in:RoundedRectangle(cornerRadius:22))
                    }
                }.padding(22)
            }
            .navigationTitle("Inbox")
            .toolbar {
                ToolbarItem(placement:.topBarLeading){NavigationLink{SettingsView()}label:{Image("Brand").resizable().scaledToFit().frame(width:38,height:38).clipShape(Circle())}}
                ToolbarItem(placement:.topBarTrailing){NavigationLink{FilesView()}label:{Image(systemName:"magnifyingglass")}}
                ToolbarItem(placement:.topBarTrailing){NavigationLink{SetupView()}label:{Image(systemName:"folder.badge.plus")}}
            }
            .safeAreaInset(edge:.bottom) {
                NavigationLink{OracleView()}label:{HStack{Image(systemName:"plus.circle.fill");Text("Plan, ask, build…");Spacer();Image(systemName:"arrow.up")}.font(.title3).foregroundStyle(.secondary).padding(18).glassEffect(.regular,in:Capsule()).padding(.horizontal,18).padding(.bottom,10)}
            }
            .fileExporter(
                isPresented:$exporting,
                document:exportDocument,
                contentType:.data,
                defaultFilename:exportFilename
            ) { result in
                Task { @MainActor in
                    switch result {
                    case .success:
                        model.progress="Original corrupt state bytes exported. The active state remains blocked until you preserve and discard it."
                    case .failure(let error):
                        model.error="The corrupt state export failed. \(error.localizedDescription)"
                    }
                }
            }
            .alert("Preserve corrupt state before discarding?",isPresented:Binding(
                get:{pendingDiscard != nil},
                set:{if !$0{pendingDiscard=nil}}
            )) {
                Button("Preserve raw bytes and discard",role:.destructive) {
                    if let record=pendingDiscard {model.preserveAndDiscardCorruptExecutionState(record)}
                    pendingDiscard=nil
                }
                Button("Keep blocked state",role:.cancel){pendingDiscard=nil}
            } message: {
                Text("Local Sandbox first writes an exact byte-for-byte copy under output and verifies it. It deletes the active state only if its SHA-256 is unchanged. No action is replayed.")
            }
        }
    }

    @ViewBuilder
    private func corruptStateCard(_ record:CorruptExecutionState)->some View {
        VStack(alignment:.leading,spacing:12) {
            Label("Corrupt \(record.kind.title)",systemImage:"exclamationmark.octagon.fill")
                .foregroundStyle(.red)
            Text(record.sourcePath).font(.caption.monospaced()).textSelection(.enabled)
            Text("\(record.byteCount) bytes · \(record.failureCode)").font(.footnote).foregroundStyle(.secondary)
            if let sha256=record.sha256 {
                Text("SHA-256: \(sha256)").font(.caption.monospaced()).textSelection(.enabled)
            }
            if record.canPreserve {
                Button("Export original bytes"){export(record)}
                Button("Preserve and discard corrupt state",role:.destructive){pendingDiscard=record}
                    .disabled(model.running)
            } else {
                Text("This state exceeds the 64,000-byte in-app review bound. It remains in place and blocks every new task. Review the selected workspace folder outside Local Sandbox; the app will not delete it.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding()
        .background(.thinMaterial,in:RoundedRectangle(cornerRadius:22))
        .accessibilityElement(children:.contain)
    }

    private func export(_ record:CorruptExecutionState) {
        do {
            exportDocument=CorruptExecutionStateDocument(data:try model.corruptExecutionStateData(record))
            exportFilename=record.exportFilename
            exporting=true
        } catch {model.error=error.localizedDescription;model.refresh()}
    }
    private var workingCount:Int {if model.running{return 1};if let session=ShortcutCoordinator.shared.current(),["awaiting_response","applying"].contains(session.phase){return 1};return 0}
    private func inboxCard(_ title:String,count:Int,icon:String,color:Color)->some View {VStack(alignment:.leading,spacing:25){Image(systemName:icon).foregroundStyle(color).font(.title2);HStack(spacing:7){Text(title);Text("\(count)").foregroundStyle(.secondary)}}.font(.system(size:18)).frame(maxWidth:.infinity,minHeight:118,alignment:.bottomLeading).padding(19).background(Color(uiColor:.secondarySystemGroupedBackground),in:RoundedRectangle(cornerRadius:25)).overlay(RoundedRectangle(cornerRadius:25).stroke(.primary.opacity(0.06)))}
    private func workspaceRow(_ title:String,icon:String,count:Int?)->some View {HStack(spacing:18){Image(systemName:icon).foregroundStyle(.secondary);Text(title);Spacer();if let count{Text("\(count)").foregroundStyle(.secondary)};Image(systemName:"chevron.right").foregroundStyle(.tertiary)}.font(.title3).padding(.vertical,20)}
}
struct OracleView:View {
    @EnvironmentObject private var model:AppModel
    @Environment(\.openURL) private var openURL
    @State private var goal="";@State private var response="";@State private var prompt="";@State private var applying=false
    @State private var providerSelection:ProviderSelection = .saved
    @State private var verificationMode="exactText";@State private var verificationPath="workspace/test.txt";@State private var verificationValue="Status: verified"
    var body:some View {ScrollView{VStack(alignment:.leading,spacing:22){Text("What should your phone do?").font(.title2);TextField("A small, verifiable task",text:$goal,axis:.vertical).lineLimit(3...6).padding().background(.thinMaterial,in:RoundedRectangle(cornerRadius:20))
        Picker("Provider route",selection:$providerSelection){ForEach(ProviderSelection.allCases){Text($0.title).tag($0)}}.pickerStyle(.menu)
        GroupBox("Independent verification"){VStack(alignment:.leading){Picker("Expected state",selection:$verificationMode){Text("Exact text").tag("exactText");Text("Contains text").tag("containsText");Text("SHA-256").tag("sha256");Text("Path exists").tag("pathExists");Text("Path absent").tag("pathAbsent")}.pickerStyle(.menu);TextField("workspace/result.txt",text:$verificationPath).textInputAutocapitalization(.never).autocorrectionDisabled();if !["pathExists","pathAbsent"].contains(verificationMode){TextField(verificationMode=="sha256" ? "Expected SHA-256":"Expected text",text:$verificationValue,axis:.vertical).lineLimit(2...5)};Text("Local Sandbox reads this path again after the provider finishes. Only an exact passing assertion can produce a verified receipt.").font(.footnote).foregroundStyle(.secondary)}}
        Button(model.running ? "Running…":"Resolve and begin task"){beginTask()}.buttonStyle(.borderedProminent).disabled(model.running || goal.isEmpty || !model.connected || !model.corruptExecutionStates.isEmpty || !model.executionStateInspectionError.isEmpty)
        if model.running{Button("Stop",role:.destructive){AgentRunner.shared.cancel()}}
        if let session=ShortcutCoordinator.shared.current(),["awaiting_response","applying"].contains(session.phase){Text("Step \(session.step) · \(session.phase.replacingOccurrences(of:"_",with:" "))").font(.footnote).foregroundStyle(.secondary);Button("Resume in app Shortcut"){prompt=ShortcutCoordinator.shared.prompt(session);launch()}.disabled(session.phase != "awaiting_response");Text("Return the app’s JSON response").font(.headline);TextEditor(text:$response).frame(minHeight:170).font(.system(.body,design:.monospaced)).padding(12).background(.thinMaterial,in:RoundedRectangle(cornerRadius:18));Text("Review the proposed tool and arguments before applying. File writes require the exact read hash and produce a readback receipt.").font(.footnote).foregroundStyle(.secondary);Button("Validate and apply response"){let executionGeneration=ExecutionContinuationGate.shared.capture();applying=true;Task{@MainActor in defer{applying=false;model.refresh()};do{prompt=try await ShortcutCoordinator.shared.accept(response,executionGeneration:executionGeneration);response="";model.progress="App response processed"}catch{model.error=error.localizedDescription}}}.disabled(applying || response.isEmpty);Button("Stop handoff",role:.destructive){let executionGeneration=ExecutionContinuationGate.shared.capture();Task{@MainActor in do{try await ShortcutCoordinator.shared.stop(executionGeneration:executionGeneration);model.refresh()}catch{model.error=error.localizedDescription}}}}
        if !prompt.isEmpty{ShareLink("Share current prompt",item:prompt)};Text(model.progress).font(.footnote).foregroundStyle(.secondary)
    }.padding(22)}.navigationTitle("Oracle").onAppear{if let current=ShortcutCoordinator.shared.current(){goal=current.goal;providerSelection=current.providerSelection;prompt=ShortcutCoordinator.shared.prompt(current)}}}
    private func verificationContract()throws->GoalContract{try filesystemGoalContract(mode:verificationMode,path:verificationPath,expected:verificationValue)}
    private func beginTask(){do{let executionGeneration=ExecutionContinuationGate.shared.capture();let contract=try verificationContract();let route=try ProviderRuntimeCapabilities.resolve(selection:providerSelection,policy:model.policy);switch route.decision{case .onDeviceApple:Task{@MainActor in await model.run(goal,contract:contract,selection:providerSelection,executionGeneration:executionGeneration)};case .shortcut:prompt=try ShortcutCoordinator.shared.begin(goal:goal,policy:model.policy,contract:contract,providerSelection:providerSelection,origin:.app,resolvedRoute:route,executionGeneration:executionGeneration);launch();case .blocked(let reason):model.error=reason}}catch{model.error=error.localizedDescription}}
    private func launch(){guard let session=ShortcutCoordinator.shared.current(),!session.shortcutAdapterName.isEmpty else{model.error="The resolved Shortcut route is missing. Begin the task again.";return};if let url=AdapterSettings.runURL(name:session.shortcutAdapterName,input:prompt){openURL(url){ok in if !ok{model.error="Shortcuts could not open the resolved adapter. Install or configure that exact Shortcut first."}}}}
}
struct FilesView:View {
    @EnvironmentObject private var model:AppModel
    @State private var selected:String?
    @State private var newName=""
    @State private var create=false
    var body:some View {
        NavigationStack {
            List {
                Section("Approved workspace") {
                    ForEach(model.files,id:\.self) { file in
                        Button {
                            selected=file
                        } label: {
                            Label(file,systemImage:"doc.text")
                        }
                    }
                    if !model.connected {
                        Text("Select an iCloud Drive folder in Settings.").foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Sandbox")
            .toolbar {
                Button { create=true } label: { Image(systemName:"plus") }
                    .disabled(!model.connected)
            }
            .refreshable { model.refresh() }
            .sheet(isPresented:Binding(get:{selected != nil},set:{if !$0{selected=nil}})) {
                if let selected { NavigationStack { NativeFileEditorView(path:selected){self.selected=nil;model.refresh()} } }
            }
            .alert("New file",isPresented:$create) {
                TextField("notes.md",text:$newName)
                Button("Create") {
                    do {
                        try SandboxStore.shared.write(SandboxPath("workspace/\(newName)"),content:"",createOnly:true)
                        model.refresh()
                        newName=""
                    } catch {
                        model.error=error.localizedDescription
                    }
                }
                Button("Cancel",role:.cancel) {}
            } message: {
                Text("Creates a text file inside workspace. Existing files are preserved.")
            }
        }
    }
}
struct ActivityView: View {
    @EnvironmentObject private var model: AppModel

    private struct ReceiptTraceRow: Identifiable {
        let id: String
        let entry: TraceEntry
    }

    var body: some View {
        NavigationStack {
            List {
                if model.receipts.isEmpty {
                    ContentUnavailableView(
                        "No receipts yet",
                        systemImage: "waveform.path",
                        description: Text("Run a bounded task to create its execution record.")
                    )
                }
                ForEach(model.receipts) { receipt in
                    NavigationLink {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 16) {
                                Text(receipt.goal).font(.title2)
                                Text(receipt.summary)
                                Text("\(receiptProvider(receipt)) · \(receipt.origin)").font(.caption.monospaced())
                                Text("\(receipt.status.rawValue) · \(receipt.steps) steps · \(receipt.failures) failures").font(.caption.monospaced())
                                if let route = receipt.routingEvidence {
                                    GroupBox("Deterministic route") {
                                        VStack(alignment: .leading) {
                                            Text("\(route.selection.title) → \(route.provider.title)")
                                            Text("authorized \(route.authorizedProvider.title) · \(route.strategy.rawValue) · \(route.accessEvidence.rawValue)")
                                                .font(.caption.monospaced())
                                            Text("\(route.distinctProbeCount)/5 probe types · \(route.verifiedCount)/\(route.sampleCount) exact assertions · context \(route.testedContextCharacters.map { String($0) } ?? "unmeasured") · tools \(route.toolCallingQualified ? "qualified" : "unmeasured")")
                                                .font(.footnote)
                                            Text("App Intent return observed \(route.appIntentReturnObserved ? "yes" : "no") · integrity faults \(route.integrityFaultCount)")
                                                .font(.footnote)
                                            if let handoff = route.medianDurationBucketMilliseconds {
                                                Text(route.provider == .apple
                                                     ? "in-process Apple model elapsed-time bucket · \(handoff) ms"
                                                     : "external App Intent round-trip elapsed-time bucket · \(handoff) ms").font(.footnote)
                                            }
                                            Text("device \(route.deviceProfileSHA256.prefix(12))… · config \(route.configurationSHA256.prefix(12))…")
                                                .font(.caption2.monospaced())
                                                .foregroundStyle(.secondary)
                                            Text("This observation does not prove an unattended flow or the provider app, account, action, or model that produced the response.")
                                                .font(.caption2)
                                                .foregroundStyle(.secondary)
                                        }
                                    }
                                }
                                ForEach(receiptTraceRows(receipt)) { row in
                                    VStack(alignment: .leading) {
                                        Label(
                                            row.entry.tool,
                                            systemImage: row.entry.status == "ok" ? "checkmark.circle" : "exclamationmark.circle"
                                        )
                                        Text(row.entry.detail).font(.footnote).foregroundStyle(.secondary)
                                    }
                                }
                                ShareLink("Export JSON receipt", item: receiptJSON(receipt))
                            }
                            .padding()
                        }
                    } label: {
                        VStack(alignment: .leading, spacing: 7) {
                            Text(receipt.goal).lineLimit(2)
                            Text("\(receiptProvider(receipt)) · \(receipt.origin)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(receipt.status.rawValue.uppercased())
                                .font(.caption.monospaced())
                                .foregroundStyle(receipt.status == .verified ? .green : .orange)
                        }
                    }
                }
            }
            .navigationTitle("Activity")
            .refreshable { model.refresh() }
        }
    }

    private func receiptTraceRows(_ receipt: RunReceipt) -> [ReceiptTraceRow] {
        var occurrences: [String: Int] = [:]
        return receipt.trace.map { entry in
            let evidenceIdentity = entry.evidence.map {
                [
                    $0.path ?? "",
                    $0.sha256 ?? "",
                    $0.byteCount.map { String($0) } ?? "",
                    $0.readbackKind,
                    String($0.contentComplete),
                ].joined(separator: "\u{0}")
            } ?? ""
            let fingerprint = NativeDigest.sha256(
                [receipt.id, entry.tool, entry.status, entry.detail, evidenceIdentity].joined(separator: "\u{0}")
            )
            let occurrence = occurrences[fingerprint, default: 0]
            occurrences[fingerprint] = occurrence + 1
            return ReceiptTraceRow(
                id: "\(receipt.id):\(fingerprint):\(occurrence)",
                entry: entry
            )
        }
    }

    private func receiptJSON(_ receipt: RunReceipt) -> String {
        (try? String(decoding: receipt.encodedWireData(), as: UTF8.self)) ?? "{}"
    }

    private func receiptProvider(_ receipt: RunReceipt) -> String {
        receipt.provider.flatMap(AppProvider.init(rawValue:))?.title ?? "Unspecified provider"
    }
}
private struct AppleCredentialReviewSection:View {
    @EnvironmentObject private var model:AppModel
    @State private var confirmingReview=false
    private static let appleAccountSettingsURL=URL(string:"https://account.apple.com/account/manage")!

    var body:some View {
        Section("Apple authorization review") {
            switch model.appleCredentialReviewDisplayState {
            case .notChecked:
                Label("Hosted cleanup status not checked",systemImage:"questionmark.shield")
                Text(!model.nativeSessionAuthorityAvailable
                    ? "Sign in with Apple to check whether an interrupted authorization needs manual cleanup. A local profile alone cannot read this hosted status."
                    : "Refresh the app-owned hosted status before changing Apple authorization settings.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            case .clear:
                Label("No unresolved Apple credential cleanup",systemImage:"checkmark.shield")
                    .foregroundStyle(.green)
                Text("The hosted service has no current possible-credential receipt for this Apple identity. Refresh after any interrupted sign-in.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            case .required(let markedAt):
                Label("Apple credential cleanup needs review",systemImage:"exclamationmark.shield")
                    .foregroundStyle(.orange)
                LabeledContent("Detected",value:markedAt.formatted(date:.abbreviated,time:.shortened))
                Text("An Apple authorization may have been issued during an interrupted sign-in, but Local Sandbox could not prove that it was retained or revoked. Open Apple Account, choose Sign-In & Security, then Sign in with Apple. Remove Local Sandbox if it appears there. Return here only after that review.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Link("Open Apple Account settings",destination:Self.appleAccountSettingsURL)
                Button("I reviewed Apple Account"){confirmingReview=true}
                    .disabled(!model.nativeSessionAuthorityAvailable || model.acknowledgingAppleCredentialReview)
                if !model.nativeSessionAuthorityAvailable {
                    Text("Leaving Local Sandbox locks its short-lived native bearer. Sign in with Apple again above after your review, then confirm this receipt.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if model.checkingAppleCredentialReview || model.acknowledgingAppleCredentialReview {
                ProgressView(model.acknowledgingAppleCredentialReview ? "Confirming review":"Checking status")
            }
            Button("Refresh hosted Apple status"){Task{await model.refreshAppleCredentialReview()}}
                .disabled(!model.nativeSessionAuthorityAvailable || model.checkingAppleCredentialReview || model.acknowledgingAppleCredentialReview)
        }
        .task{await model.refreshAppleCredentialReview()}
        .alert("Confirm Apple Account review?",isPresented:$confirmingReview) {
            Button("Confirm completed review"){Task{await model.acknowledgeAppleCredentialReview()}}
            Button("Review again",role:.cancel){}
        } message: {
            Text("Confirm only after you reviewed Sign in with Apple in Apple Account settings and removed Local Sandbox if it appeared. This acknowledges only the hidden hosted receipt currently displayed. It does not revoke Apple authorization by itself, and a changed receipt will be rejected.")
        }
    }
}

struct SettingsView:View {
    @EnvironmentObject private var model:AppModel
    @State private var picker=false;@State private var delete=false;@State private var deleteHosted=false;@State private var discardDeletionRecovery=false
    var body:some View {NavigationStack{Form{
        Section("Apple account"){
            Label(model.userID.isEmpty ? "Sign in required":"Signed in with Apple",systemImage:"person.crop.circle.badge.checkmark")
            if model.appleTransferRecoveryUserID != nil {
                Label("Transferred credential needs review",systemImage:"person.crop.circle.badge.exclamationmark").foregroundStyle(.orange)
                Text("Tap Sign in with Apple. The request is pinned to the stored old Apple user identifier. Local Sandbox keeps the current profile blocked from hosted refresh and will not switch identities or inherit workspace state unless Apple and the server verify the transfer relationship.").font(.footnote).foregroundStyle(.secondary)
                AppleLoginButton()
            } else if model.nativeSessionAuthorityAvailable,let expiry=model.nativeSessionExpiry {
                LabeledContent("Native sync session",value:"Until \(expiry.formatted(date:.omitted,time:.shortened))")
            } else {
                Text(model.userID.isEmpty ? "Sign in to create your private profile and short-lived sync session.":"Your local profile remains signed in. Sign in again for a new 15-minute encrypted-sync session.").font(.footnote).foregroundStyle(.secondary)
                AppleLoginButton()
            }
            if let followUp=model.nativeRevocationFollowUp {
                LabeledContent("Revocation follow-up",value:"\(followUp.count) · grant horizon \(Date(timeIntervalSince1970:TimeInterval(followUp.expiresAt)).formatted(date:.omitted,time:.shortened))")
                Text("The active bearer was removed from admission. Its exact retired value stays in device-only Keychain for idempotent server revocation retries, including after bearer expiry. The displayed grant horizon is diagnostic; only confirmed revoke success or the revoke endpoint's authoritative absence response removes the debt.").font(.footnote).foregroundStyle(.secondary)
                Button("Retry native-session revocation"){Task{await model.retryNativeRevocationFollowUp()}}.disabled(model.appleAuthorizationInFlight)
            }
        }
        AppleCredentialReviewSection()
        Section("Local workspace · optional iCloud"){Label(model.folderName,systemImage:"folder");Button("Use private on-device workspace"){do{try SandboxStore.shared.useLocal();try model.prepare();model.refresh()}catch{model.error=error.localizedDescription}};Button("Choose LocalSandbox folder"){picker=true};Text("On your next iPhone, sign in again and select this same iCloud folder. iOS rechecks file permission and provider availability.").font(.footnote).foregroundStyle(.secondary)}
        Section{NavigationLink{ProvidersView()}label:{Label("Apps & Shortcuts",systemImage:"square.stack.3d.up")};NavigationLink{GitHubSettingsView()}label:{Label("GitHub authentication & sync",systemImage:"arrow.triangle.branch")};NavigationLink{EncryptedWorkspaceSyncView()}label:{Label("Encrypted hosted sync",systemImage:"lock.icloud")};NavigationLink{SetupView()}label:{Label("Shortcut setup",systemImage:"link")}}
        Section("Resource authorization"){budget("Battery drop",value:$model.policy.batteryBudget,range:1...80);budget("Memory target",value:$model.policy.memoryTarget,range:10...80);Stepper("Battery reserve: \(model.policy.batteryReserve)%",value:$model.policy.batteryReserve,in:5...80);Stepper("Maximum steps: \(model.policy.maxSteps)",value:$model.policy.maxSteps,in:1...24);Stepper("Prompt cap: \(model.policy.contextChars) characters",value:$model.policy.contextChars,in:2000...12000,step:500);Toggle("Allow cloud app handoffs",isOn:$model.policy.cloudAllowed);Toggle("Allow clipboard reads",isOn:$model.policy.clipboardReadAllowed);Toggle("Allow clipboard writes",isOn:$model.policy.clipboardWriteAllowed);Toggle("Completion and tool notifications",isOn:$model.policy.notifications);Button("Enable notifications"){Task{do{_ = try await UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound])}catch{model.error=error.localizedDescription}}};Button("Save authorization"){model.savePolicy()};Text("Resource, clipboard, and cloud-consent changes take effect only after Save authorization on this iPhone. Provider selection and Apply Oracle recommendation change only the saved provider and preserve the already authorized limits. config/policy.json is an export and can never grant permissions when a folder is opened or synced. Apple Intelligence tasks are capped at 6,000 prompt characters in 0.3; qualified external routes can use up to 12,000. Memory covers this app’s process, not another provider app. iOS owns resource allocation and background execution.").font(.footnote).foregroundStyle(.secondary)}
        Section("Native background execution"){if let status=model.backgroundStatus{LabeledContent("Status",value:status.state.rawValue.replacingOccurrences(of:"([a-z])([A-Z])",with:"$1 $2",options:.regularExpression).capitalized);LabeledContent("Reason",value:status.reason.rawValue);if let runID=status.runID{LabeledContent("Run",value:String(runID.prefix(12)))};Text(status.detail ?? "No additional detail was recorded.").font(.footnote).foregroundStyle(.secondary)}else{Text("No background request has been recorded on this device.").foregroundStyle(.secondary)};Text("Only an already-approved Apple Intelligence run can resume in a BGProcessingTask. Provider-app handoffs stay foreground-only. iOS chooses whether and when a request runs, may stop it after minutes, and never grants indefinite execution. Protected workspace files remain unavailable while the device is locked.").font(.footnote).foregroundStyle(.secondary)}
        Section("Device capabilities"){ShareLink("Export device report",item:AdapterSettings.deviceReport());Text("Import this JSON in the dashboard to update its device capability display. Native checks always read current availability.").font(.footnote).foregroundStyle(.secondary)}
        Section("Siri & local privacy"){Text("Run Bounded Task and Begin Oracle Task expose Saved, Best local, Apple Intelligence, Locally, ChatGPT, Grok, Grokbot, and Claude. Saved and explicit routes never substitute. Best local uses its Apple-available cold-start target only while neither Apple nor Locally has comparable evidence, but it still blocks until that target has a task-qualified five-probe suite. As soon as either has a comparable suite, it ranks only comparable, task-qualified Apple and Locally candidates and never chooses cloud.");Button("Lock now"){model.lock()}.disabled(model.appleAuthorizationInFlight);Text("Face ID or the device passcode unlocks this app. Provider authentication stays in each provider app; Local Sandbox records only that a returned response passed local validation, not the provider app, action, account session, or model that produced it. The protected routing ledger never syncs. Receipts contain hashes and bounded scores, not provider output, adapter names, credentials, prompts, or file content. Lock now durably queues and retires hosted authorization before removing its local admission record; background transitions block admission while preserving revocable Keychain evidence. Both paths clear the in-memory workspace key.").font(.footnote).foregroundStyle(.secondary)}
        Section("Updates"){Text("Local Sandbox 0.3.0");Link("Current dashboard & downloads",destination:URL(string:"https://local-sandbox.ctyy4wd4c2.chatgpt.site")!);Text("Native updates use signed Xcode, TestFlight, or App Store builds. Workspace data is preserved. Shortcuts use reviewed, versioned shared links; no executable code is downloaded and run as an app patch.").font(.footnote).foregroundStyle(.secondary)}
        Section("Hosted Apple access and account"){Text(model.appleAccountDeletionNeedsDiscard ? "The saved deletion retry record is expired or unreadable. Discard it before starting a fresh Apple sign-in. Server-side deletion status remains unknown.":model.appleAccountMode == .linked ? "This removes this Apple identity's access and sessions from the linked ChatGPT-owned workspace. It retains that workspace, its data, and other linked identities.":model.appleAccountMode == .standalone ? "This permanently deletes the standalone Apple-owned Local Sandbox account and its server workspace data.":"Account ownership mode is unavailable. Sign in with Apple again before using hosted deletion.").font(.footnote).foregroundStyle(.secondary);Text("This is separate from disconnecting native sync or deleting only this device's local profile. Selected Files and iCloud documents are outside this destructive scope.").font(.footnote).foregroundStyle(.secondary);Button(model.appleAccountDeletionPending ? "Retry hosted account deletion":(model.appleAccountMode == .linked ? "Remove Apple access":model.appleAccountMode == .standalone ? "Delete account and server data":"Account mode unavailable"),role:.destructive){deleteHosted=true}.disabled(model.deletingAppleAccount || model.appleAccountMode == nil || model.appleAuthorizationInFlight);if model.appleAccountDeletionPending{Button("Discard recovery and restart sign-in",role:.destructive){discardDeletionRecovery=true}.disabled(model.appleAuthorizationInFlight)}}
        Section{Button("Delete local profile",role:.destructive){delete=true}.disabled(model.appleAuthorizationInFlight)}
    }
    .navigationTitle("Settings")
    .fileImporter(isPresented:$picker,allowedContentTypes:[.folder],allowsMultipleSelection:false){result in do{if let url=try result.get().first{model.connect(url)}}catch{model.error=error.localizedDescription}}
    .alert("Delete local profile?",isPresented:$delete,actions:{Button("Delete",role:.destructive){Task{await model.deleteProfile()}}.disabled(model.appleAuthorizationInFlight);Button("Cancel",role:.cancel){}},message:{Text(model.appleAccountDeletionPending ? "This removes local identity, GitHub credentials, preferences, and folder access, but retains the uncertain hosted-deletion transaction and its retry key for safe recovery. Workspace files and opted-in iCloud Keychain recovery secrets remain." : "Revokes the current native session and removes local identity, GitHub credentials, preferences, and folder access. Workspace files and opted-in iCloud Keychain recovery secrets remain.")})
    .alert(model.appleAccountMode == .linked ? "Remove this Apple identity's access?":model.appleAccountMode == .standalone ? "Permanently delete account and server data?":"Account mode unavailable",isPresented:$deleteHosted,actions:{Button(model.appleAccountMode == .linked ? "Remove Apple access":model.appleAccountMode == .standalone ? "Permanently delete":"Unavailable",role:.destructive){Task{await model.deleteHostedAppleAccount()}}.disabled(model.appleAccountMode == nil);Button("Keep account",role:.cancel){}},message:{Text(model.appleAccountMode == .linked ? "This revokes this Apple identity's credentials and removes only its access and sessions. The ChatGPT-owned workspace, its Local Sandbox data, and other linked Apple identities are retained. Selected Files and iCloud documents stay on your devices.":model.appleAccountMode == .standalone ? "This deletes the standalone Apple-owned Local Sandbox server account, workspace files, receipts, encrypted sync data, and sessions. Selected Files and iCloud documents stay on your devices; the app only disconnects folder access after confirmed deletion.":"Sign in with Apple again so Local Sandbox can verify whether this is a linked identity or a standalone account.")})
    .alert("Discard hosted deletion recovery?",isPresented:$discardDeletionRecovery,actions:{Button("Discard local retry record",role:.destructive){Task{await model.discardHostedAccountDeletionRecovery()}}.disabled(model.appleAuthorizationInFlight);Button("Keep recovery",role:.cancel){}},message:{Text("This removes only this iPhone's saved retry key and deletion bearer. It does not undo or confirm any server-side account deletion. Afterward, start a fresh Apple sign-in.")})}}
    func budget(_ title:String,value:Binding<Int>,range:ClosedRange<Double>)->some View {VStack{HStack{Text(title);Spacer();Text("\(value.wrappedValue)%").monospacedDigit()};Slider(value:Binding(get:{Double(value.wrappedValue)},set:{value.wrappedValue=Int($0)}),in:range,step:1)}}
}
struct ProvidersView:View {
    @EnvironmentObject private var model:AppModel
    @State private var selected:AppProvider?
    @State private var resetChecks=false
    var body:some View {List{
        Section("Oracle measured routing"){
            Button("Run five Apple checks through App Intent",intent:QualifyAppleProviderIntent()).disabled(model.running || AppProvider.apple.unavailableReason != nil || !model.connected)
            Button("Apply Oracle recommendation"){model.applyOracleRecommendation()}.disabled(model.running || !model.connected)
            Button("Reset this device’s checks",role:.destructive){resetChecks=true}.disabled(model.running)
            Text("A recommendation requires at least five fresh device-local samples covering all five probe types, at least 80% locally schema-valid responses, at least 80% exact assertion passes, all three tool probes, enough tested context, no integrity fault, and an observed App Intent return for each probe. The protected ledger stores at most 240 attempts; scoring uses only the 20 freshest attempts in seven days. An observed return does not prove unattended execution or provider, account, action, or model provenance. Confirm those facts in a live physical-device test. Ranking is schema reliability, assertion quality, then a lower timing bucket only when both candidates use the same transport, followed by a fixed provider tie-break. Apple timing measures in-process model work; external-provider timing measures the App Intent round trip. Those two timings are never compared and neither proves provider inference latency. Cloud candidates also require saved cloud consent.").font(.footnote).foregroundStyle(.secondary)
        }
        Section("Saved provider"){ForEach(AppProvider.allCases){provider in Button{if let reason=provider.unavailableReason{model.error=reason}else if provider == .apple{model.saveProviderOnly(provider)}else{selected=provider}}label:{HStack(spacing:15){Image(systemName:provider == .apple ? "sparkles":"square.stack.3d.up");VStack(alignment:.leading,spacing:4){Text(provider.title).foregroundStyle(.primary);Text(providerStatus(provider)).font(.footnote).foregroundStyle(.secondary)};Spacer();if model.policy.provider==provider.rawValue{Image(systemName:"checkmark")};if provider != .apple{Image(systemName:"chevron.right").foregroundStyle(.tertiary)}}}}}
        Section("Siri routing"){Text("Installing Local Sandbox registers its App Shortcuts automatically. Saved and explicit choices stay pinned. Best local uses its cold-start target only while neither Apple nor Locally has comparable evidence, but it still blocks until that target qualifies; once either has comparable evidence, it ranks only comparable, task-qualified Apple and Locally candidates and never cloud. A route is resolved once before execution and never switches after a provider response or tool action.").font(.footnote).foregroundStyle(.secondary);Text("iOS does not reveal another app’s account session, active model, action inventory, or response provenance. A locally validated response means only that returned text passed this app’s signed device-local challenge and assertions. Provider permissions and subscriptions remain in that app; exact app/action/session proof is a live visual device gate.").font(.footnote).foregroundStyle(.secondary)}}.navigationTitle("Apps & Shortcuts").sheet(item:$selected){provider in NavigationStack{AdapterView(provider:provider)}}.alert("Reset measured checks?",isPresented:$resetChecks,actions:{Button("Reset",role:.destructive){do{try ProviderQualificationStore.reset();model.progress="Device checks reset; provider routes require fresh responses"}catch{model.error=error.localizedDescription}};Button("Keep checks",role:.cancel){}},message:{Text("This removes only the protected routing ledger and invalidates measured provider status on this iPhone. It does not remove provider accounts, Shortcuts, workspace files, or receipts.")})}
    private func providerStatus(_ provider:AppProvider)->String{if provider == .apple,provider.unavailableReason != nil{return "On-device model unavailable · "+ProviderQualificationStore.status(provider:provider,contextCharacters:model.policy.contextChars)};let access=provider == .apple ? "On-device runtime" : (AdapterSettings.get(provider).tested ? "Locally validated response":"No locally validated response");return access+" · "+ProviderQualificationStore.status(provider:provider,contextCharacters:model.policy.contextChars)}
}
struct AdapterView:View {
    let provider:AppProvider
    @EnvironmentObject private var model:AppModel
    @Environment(\.openURL) private var openURL
    @Environment(\.dismiss) private var dismiss
    @State private var adapter=ShortcutAdapter(name:"")
    @State private var installed=false
    @State private var qualificationResponse=""
    @State private var pending:ProviderQualificationChallenge?
    var body:some View {Form{
        Section("Provider-owned account"){Text("Sign in to \(provider.title) in its own app. Local Sandbox never receives its token or reads its login state. A locally validated response proves only that returned text passed this app’s challenge at that time; exact app, action, account session, and model provenance require live visual device evidence.")}
        Section("Shortcut"){
            TextField("Name",text:$adapter.name)
            Toggle("Manual return",isOn:Binding(get:{adapter.mode=="manual"},set:{adapter.mode=$0 ? "manual":"action"}))
            TextField("Shared iCloud install link (optional)",text:$adapter.installURL).textInputAutocapitalization(.never).autocorrectionDisabled()
            if adapter.installURL.isEmpty {NavigationLink{ShortcutPackagesView()}label:{Label("Browse Shortcut packages",systemImage:"square.and.arrow.down")}} else {Button("Open Apple’s Add Shortcut screen"){do{try AdapterSettings.save(adapter,for:provider);if let url=URL(string:adapter.installURL){openURL(url)}}catch{model.error=error.localizedDescription}}}
            Toggle("I reviewed and saved this Shortcut",isOn:$installed)
            Text("Opening the editor or Add Shortcut screen does not install or authorize anything by itself.").font(.footnote)
            Button("Save configuration"){do{try AdapterSettings.save(adapter,for:provider);adapter=AdapterSettings.get(provider)}catch{model.error=error.localizedDescription}}
        }
        Section("Measured device check"){
            Text(ProviderQualificationStore.status(provider:provider,contextCharacters:model.policy.contextChars)).font(.footnote)
            Button(pending == nil ? "Start next measured check":"Run pending check in Shortcuts"){startQualification()}.disabled(!installed)
            if let pending{Text("\(pending.probe.rawValue) · \(pending.attemptID)").font(.caption.monospaced());Text("Paste the raw provider response. The response is validated in memory and is not saved.").font(.footnote).foregroundStyle(.secondary);TextEditor(text:$qualificationResponse).frame(minHeight:130).font(.system(.body,design:.monospaced));Button("Verify and record result"){completeQualification()}.disabled(qualificationResponse.isEmpty)}
            Text("For a native personal flow, repeat Begin Provider Check → Get Dictionary from Input → send only payload to this exact provider action → Record Provider Check with the raw response. Five distinct checks form one comparable suite.").font(.footnote).foregroundStyle(.secondary)
        }
        Section("Wrapper build order"){Text("1. Accept Shortcut Input as text.\n2. Pass it to the installed provider app’s text-returning action.\n3. Stop and Output the raw result.\n\nIf the app exposes no text-returning action, choose Manual return. Manual routes can still be used deliberately, but they are not eligible for unattended Oracle recommendation.")}
        Button("Save configuration and select provider"){do{try AdapterSettings.save(adapter,for:provider);model.saveProviderOnly(provider);if model.error.isEmpty{dismiss()}}catch{model.error=error.localizedDescription}}
    }.navigationTitle(provider.title).navigationBarTitleDisplayMode(.inline).toolbar{Button("Done"){dismiss()}}.onAppear{adapter=AdapterSettings.get(provider);pending=try? ProviderQualificationStore.pending(provider:provider)}.onChange(of:adapter.name){_,_ in installed=false;adapter.tested=false;pending=nil}.onChange(of:adapter.mode){_,_ in installed=false;adapter.tested=false;pending=nil}}
    private func startQualification(){do{try AdapterSettings.save(adapter,for:provider);adapter=AdapterSettings.get(provider);let challenge=try pending ?? ProviderQualificationStore.begin(provider:provider,contextCharacters:model.policy.contextChars);pending=challenge;if let name=challenge.adapterName,let url=AdapterSettings.runURL(name:name,input:challenge.prompt){openURL(url){ok in if !ok{model.error="Shortcuts could not open the exact configured adapter."}}}}catch{model.error=error.localizedDescription}}
    private func completeQualification(){guard let pending else{return};do{let result=try ProviderQualificationStore.complete(attemptID:pending.attemptID,provider:provider,response:qualificationResponse);qualificationResponse="";self.pending=nil;adapter=AdapterSettings.get(provider);model.progress="\(provider.title) \(result.probe.rawValue): \(result.outcome.rawValue)"}catch{model.error=error.localizedDescription}}
}
struct SetupView:View {
    @EnvironmentObject private var model:AppModel
    var body:some View {List{Section("1 · Prepare"){NavigationLink{SettingsView()}label:{Label("Sign in & prepare local files",systemImage:"person.crop.circle")};Button("Prepare workspace"){do{try model.prepare();model.refresh()}catch{model.error=error.localizedDescription}}.disabled(!model.connected);Text("After Apple sign-in and protected workspace preparation, Local Sandbox creates the device-only qualification ledger and refreshes its native App Shortcuts automatically.").font(.footnote).foregroundStyle(.secondary)};Section("2 · App Shortcuts"){Text("iOS 26 registers nine native actions: Begin Oracle Task, Apply Validated Action, Prepare Workspace, Run Bounded Task, Begin Provider Check, Record Provider Check, Qualify Apple Intelligence, Apply Oracle Recommendation, and Open Local Sandbox. iOS 27 additionally registers Run Long Apple Task. Run and Begin retain all eight provider values: Saved, Best local, Apple Intelligence, Locally, ChatGPT, Grok, Grokbot, and Claude.");ShortcutsLink();NavigationLink{ProvidersView()}label:{Label("Qualify providers & apply route",systemImage:"link")}};Section("3 · Qualify and run"){Text("For each external app, visibly review its wrapper Shortcut, then repeat Begin Provider Check → Get Dictionary from Input → send only payload to that exact app action → Record Provider Check with its raw response. Apple’s five checks run through Qualify Apple Intelligence from Apps & Shortcuts, so only a real App Intent execution records transport evidence. Apply Oracle Recommendation is one button after qualification. A task flow remains Run/Begin → Get Dictionary from Input → send payload only → pass the provider action's raw JSON output to Apply Validated Action → Repeat with payload only while phase equals awaiting_response; otherwise retain or import the terminal receipt from payload. Apply validates the action against the saved authorization but does not present a separate content-review screen. Provider authentication remains in its app.");NavigationLink{ShortcutPackagesView()}label:{Label("Install Shortcut packages",systemImage:"square.and.arrow.down")}};Section("Visual guide"){Link("Open setup guide",destination:URL(string:"https://local-sandbox.ctyy4wd4c2.chatgpt.site/downloads/Local-Sandbox-Setup-Guide.pdf")!)}}.navigationTitle("Set up Shortcuts")}
}
struct SafariView:UIViewControllerRepresentable {
    let url:URL
    func makeUIViewController(context:Context)->SFSafariViewController {SFSafariViewController(url:url)}
    func updateUIViewController(_ controller:SFSafariViewController,context:Context){}
}
