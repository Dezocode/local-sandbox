import Foundation

enum BackgroundExecutionState: String, Codable {
    case registered
    case registrationFailed
    case scheduled
    case running
    case deferred
    case reviewRequired
    case expired
    case completed
    case failed
    case noWork
}

enum BackgroundExecutionReason: String, Codable {
    case launchHandlerRegistered
    case launchHandlerRejected
    case systemGrantPending
    case systemGrantStarted
    case anotherExecutionActive
    case noCheckpoint
    case terminalCheckpoint
    case protectedDataUnavailable
    case workspaceUnavailable
    case backgroundRefreshUnavailable
    case missingPolicySnapshot
    case policyChanged
    case unsupportedProvider
    case providerUnavailable
    case unsafeExecutingCheckpoint
    case invalidCheckpointPhase
    case invalidCheckpoint
    case stepBudgetReached
    case failureBudgetReached
    case stateReadFailed
    case schedulerRejected
    case taskExpired
    case resourceGate
    case runnerCompleted
    case runnerFailed
    case statusCorrupt
}

struct BackgroundResumePlan: Equatable {
    let runID: String
    let nextStep: Int
    let requiresNetworkConnectivity: Bool
}

enum BackgroundExecutionDecision: Equatable {
    case resume(BackgroundResumePlan)
    case deferred(BackgroundExecutionReason)
    case reviewRequired(BackgroundExecutionReason)
    case noWork(BackgroundExecutionReason)
}

struct BackgroundExecutionContext: Equatable {
    let protectedDataAvailable: Bool
    let workspaceConnected: Bool
    let workspaceRequiresNetworkConnectivity: Bool
    let backgroundRefreshAvailable: Bool
    let nativeProviderAvailable: Bool
    let currentPolicy: ResourcePolicy?
}

enum BackgroundExecutionPolicy {
    static let resumablePhases = Set(["planning", "ready"])
    static let unfinishedPhases = Set(["planning", "ready", "executing"])
    static let terminalPhases = Set(RunStatus.allCases.map(\.rawValue))

    static func shouldSubmit(checkpoint: RunCheckpoint?) -> Bool {
        guard let checkpoint else { return false }
        return unfinishedPhases.contains(checkpoint.phase)
    }

    static func evaluate(checkpoint: RunCheckpoint?, context: BackgroundExecutionContext) -> BackgroundExecutionDecision {
        guard context.protectedDataAvailable else { return .deferred(.protectedDataUnavailable) }
        guard context.backgroundRefreshAvailable else { return .deferred(.backgroundRefreshUnavailable) }
        guard context.workspaceConnected else { return .deferred(.workspaceUnavailable) }
        guard let checkpoint else { return .noWork(.noCheckpoint) }

        if terminalPhases.contains(checkpoint.phase) { return .noWork(.terminalCheckpoint) }
        if checkpoint.phase == "executing" { return .reviewRequired(.unsafeExecutingCheckpoint) }
        guard resumablePhases.contains(checkpoint.phase) else { return .reviewRequired(.invalidCheckpointPhase) }
        guard let approvedPolicy = checkpoint.policy,
              let approvedAuthorization = checkpoint.authorizationPolicy else {
            return .reviewRequired(.missingPolicySnapshot)
        }
        guard checkpoint.nextStep >= 0,
              !checkpoint.goal.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              checkpoint.goal.count <= 2_000,
              checkpoint.trace.count <= approvedPolicy.maxSteps,
              checkpoint.failures >= 0,
              checkpoint.repeated >= 0 else { return .reviewRequired(.invalidCheckpoint) }
        guard context.currentPolicy == approvedAuthorization else { return .reviewRequired(.policyChanged) }
        guard approvedPolicy.provider == "apple" else { return .reviewRequired(.unsupportedProvider) }
        guard checkpoint.taskOrigin != nil,
              let routingEvidence = checkpoint.routingEvidence,
              routingEvidence.provider == .apple,
              routingEvidence.authorizedProvider.rawValue == approvedAuthorization.provider else {
            return .reviewRequired(.missingPolicySnapshot)
        }
        guard context.nativeProviderAvailable else { return .reviewRequired(.providerUnavailable) }
        guard checkpoint.nextStep < approvedPolicy.maxSteps else { return .reviewRequired(.stepBudgetReached) }
        guard checkpoint.failures < approvedPolicy.maxFailures, checkpoint.repeated < 2 else {
            return .reviewRequired(.failureBudgetReached)
        }

        return .resume(BackgroundResumePlan(
            runID: checkpoint.runID,
            nextStep: checkpoint.nextStep,
            requiresNetworkConnectivity: context.workspaceRequiresNetworkConnectivity
        ))
    }
}

struct BackgroundExecutionRecord: Codable, Equatable {
    let attemptID: String
    let runID: String?
    let state: BackgroundExecutionState
    let reason: BackgroundExecutionReason
    let checkpointPhase: String?
    let nextStep: Int?
    let provider: String?
    let requiresNetworkConnectivity: Bool
    let protectedDataAvailable: Bool
    let recordedAt: String
    let detail: String?
    let evidencePaths: [String]

    init(attemptID: String, runID: String?, state: BackgroundExecutionState,
         reason: BackgroundExecutionReason, checkpointPhase: String? = nil,
         nextStep: Int? = nil, provider: String? = nil,
         requiresNetworkConnectivity: Bool = false, protectedDataAvailable: Bool,
         recordedAt: String, detail: String? = nil,
         evidencePaths: [String] = ["device:backgroundExecutionStatus"]) {
        self.attemptID = attemptID
        self.runID = runID
        self.state = state
        self.reason = reason
        self.checkpointPhase = checkpointPhase
        self.nextStep = nextStep
        self.provider = provider
        self.requiresNetworkConnectivity = requiresNetworkConnectivity
        self.protectedDataAvailable = protectedDataAvailable
        self.recordedAt = recordedAt
        self.detail = detail.map { String($0.prefix(500)) }
        self.evidencePaths = evidencePaths
    }

    private enum CodingKeys: String, CodingKey {
        case recordType, schemaVersion, attemptID, runID, state, reason, checkpointPhase, nextStep
        case provider, requiresNetworkConnectivity, protectedDataAvailable, recordedAt, detail, evidencePaths
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0
        guard version <= 1 else { throw SandboxError.invalid("UNSUPPORTED_BACKGROUND_STATUS_VERSION") }
        if let type = try container.decodeIfPresent(String.self, forKey: .recordType), type != "background-execution-status" {
            throw SandboxError.invalid("WRONG_BACKGROUND_STATUS_RECORD_TYPE")
        }
        attemptID = try container.decode(String.self, forKey: .attemptID)
        runID = try container.decodeIfPresent(String.self, forKey: .runID)
        state = try container.decode(BackgroundExecutionState.self, forKey: .state)
        reason = try container.decode(BackgroundExecutionReason.self, forKey: .reason)
        checkpointPhase = try container.decodeIfPresent(String.self, forKey: .checkpointPhase)
        nextStep = try container.decodeIfPresent(Int.self, forKey: .nextStep)
        provider = try container.decodeIfPresent(String.self, forKey: .provider)
        requiresNetworkConnectivity = try container.decodeIfPresent(Bool.self, forKey: .requiresNetworkConnectivity) ?? false
        protectedDataAvailable = try container.decodeIfPresent(Bool.self, forKey: .protectedDataAvailable) ?? false
        recordedAt = try container.decode(String.self, forKey: .recordedAt)
        detail = try container.decodeIfPresent(String.self, forKey: .detail)
        evidencePaths = try container.decodeIfPresent([String].self, forKey: .evidencePaths) ?? ["device:backgroundExecutionStatus"]
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("background-execution-status", forKey: .recordType)
        try container.encode(1, forKey: .schemaVersion)
        try container.encode(attemptID, forKey: .attemptID)
        try container.encodeIfPresent(runID, forKey: .runID)
        try container.encode(state, forKey: .state)
        try container.encode(reason, forKey: .reason)
        try container.encodeIfPresent(checkpointPhase, forKey: .checkpointPhase)
        try container.encodeIfPresent(nextStep, forKey: .nextStep)
        try container.encodeIfPresent(provider, forKey: .provider)
        try container.encode(requiresNetworkConnectivity, forKey: .requiresNetworkConnectivity)
        try container.encode(protectedDataAvailable, forKey: .protectedDataAvailable)
        try container.encode(recordedAt, forKey: .recordedAt)
        try container.encodeIfPresent(detail, forKey: .detail)
        try container.encode(evidencePaths, forKey: .evidencePaths)
    }
}

final class BackgroundCompletionLatch {
    private let lock = NSLock()
    private var completed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return false }
        completed = true
        return true
    }
}

#if canImport(BackgroundTasks) && canImport(UIKit)
import BackgroundTasks
import UIKit

@MainActor
final class BackgroundAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        BackgroundExecutionCoordinator.shared.registerLaunchHandler()
        return true
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        BackgroundExecutionCoordinator.shared.scheduleIfNeeded(earliestDelay: 60)
    }

    func applicationProtectedDataWillBecomeUnavailable(_ application: UIApplication) {
        BackgroundExecutionCoordinator.shared.protectedDataWillBecomeUnavailable()
    }

    func applicationProtectedDataDidBecomeAvailable(_ application: UIApplication) {
        BackgroundExecutionCoordinator.shared.scheduleIfNeeded(earliestDelay: 60)
    }
}

@MainActor
final class BackgroundExecutionCoordinator {
    static let shared = BackgroundExecutionCoordinator()
    static let taskIdentifier = "com.dezocode.LocalSandbox.processing"
    private static let statusDefaultsKey = "backgroundExecutionStatus"
    private static let deviceIDDefaultsKey = "backgroundExecutionDeviceID"

    private var registered = false
    private var activeWork: Task<Void, Never>?
    private var activeCheckpoint: RunCheckpoint?
    private var lifecycleGeneration = 0
    private var activeSubmission: PendingSubmission?
    private var queuedSubmission: PendingSubmission?
    private init() {}

    private struct PendingSubmission {
        let token: String
        let generation: Int
        let request: BGProcessingTaskRequest
        let checkpoint: RunCheckpoint?
        let reason: BackgroundExecutionReason
        let detail: String
    }

    static func latestStatus() -> BackgroundExecutionRecord? {
        guard let data = UserDefaults.standard.data(forKey: statusDefaultsKey) else { return nil }
        do {
            return try JSONDecoder().decode(BackgroundExecutionRecord.self, from: data)
        } catch {
            return BackgroundExecutionRecord(
                attemptID: "status-read",
                runID: nil,
                state: .failed,
                reason: .statusCorrupt,
                protectedDataAvailable: UIApplication.shared.isProtectedDataAvailable,
                recordedAt: ISO8601DateFormatter().string(from: Date()),
                detail: error.localizedDescription
            )
        }
    }

    func registerLaunchHandler() {
        guard !registered else { return }
        let accepted = BGTaskScheduler.shared.register(
            forTaskWithIdentifier: Self.taskIdentifier,
            using: .main
        ) { task in
            guard let processingTask = task as? BGProcessingTask else {
                task.setTaskCompleted(success: false)
                return
            }
            BackgroundExecutionCoordinator.shared.handle(processingTask)
        }
        registered = accepted
        if !accepted || Self.latestStatus() == nil {
            record(
                attemptID: "registration",
                checkpoint: nil,
                state: accepted ? .registered : .registrationFailed,
                reason: accepted ? .launchHandlerRegistered : .launchHandlerRejected,
                detail: accepted ? "BGProcessingTask launch handler registered." : "The task identifier was not accepted. Check Info.plist."
            )
        }
    }

    func scheduleIfNeeded(earliestDelay: TimeInterval) {
        let protectedData = UIApplication.shared.isProtectedDataAvailable
        guard protectedData else {
            record(attemptID: UUID().uuidString, checkpoint: nil, state: .deferred,
                   reason: .protectedDataUnavailable,
                   detail: "The protected workspace remains locked. iOS may grant another attempt after unlock.")
            return
        }

        do {
            try SandboxStore.shared.restore()
            let checkpoint = try SandboxStore.shared.loadIfPresent(RunCheckpoint.self, path: "state/active.json")
            guard BackgroundExecutionPolicy.shouldSubmit(checkpoint: checkpoint) else {
                BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
                return
            }
            guard let approvedPolicy = checkpoint?.policy, approvedPolicy.provider == "apple" else {
                record(attemptID: UUID().uuidString, checkpoint: checkpoint, state: .reviewRequired,
                       reason: checkpoint?.policy == nil ? .missingPolicySnapshot : .unsupportedProvider,
                       detail: "Only a versioned Apple on-device run can resume without opening another app.")
                return
            }

            let request = BGProcessingTaskRequest(identifier: Self.taskIdentifier)
            request.earliestBeginDate = Date().addingTimeInterval(max(0, earliestDelay))
            request.requiresNetworkConnectivity = SandboxStore.shared.backgroundRequiresNetworkConnectivity
            request.requiresExternalPower = false
            submit(request, checkpoint: checkpoint, reason: .systemGrantPending,
                   detail: "Submitted one bounded request. iOS chooses whether and when it runs and may expire it.")
        } catch {
            let protectedData = UIApplication.shared.isProtectedDataAvailable
            record(attemptID: UUID().uuidString, checkpoint: nil,
                   state: protectedData ? .failed : .deferred,
                   reason: protectedData ? .stateReadFailed : .protectedDataUnavailable,
                   detail: protectedData ? error.localizedDescription : "The device locked while the workspace state was being inspected.")
        }
    }

    func protectedDataWillBecomeUnavailable() {
        let checkpoint = currentCheckpoint()
        AgentRunner.shared.pauseForSystemInterruption(reason: BackgroundExecutionReason.protectedDataUnavailable.rawValue)
        record(attemptID: UUID().uuidString, checkpoint: checkpoint, state: .deferred,
               reason: .protectedDataUnavailable,
               detail: "The device locked. Protected workspace access stopped at the current checkpoint.")
    }

    func resetProfileState() {
        lifecycleGeneration += 1
        queuedSubmission = nil
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
        AgentRunner.shared.cancel()
        activeWork?.cancel()
        activeWork = nil
        activeCheckpoint = nil
        UserDefaults.standard.removeObject(forKey: Self.statusDefaultsKey)
    }

    private func handle(_ task: BGProcessingTask) {
        guard activeWork == nil, !AgentRunner.shared.running else {
            record(attemptID: UUID().uuidString, checkpoint: currentCheckpoint(), state: .deferred,
                   reason: .anotherExecutionActive,
                   detail: "Another native execution already owns the runner.")
            submitBlindRetry(earliestDelay: 15 * 60,
                             requiresNetwork: SandboxStore.shared.connected ? SandboxStore.shared.backgroundRequiresNetworkConnectivity : true,
                             reason: .anotherExecutionActive,
                             detail: "Kept one later request instead of starting a concurrent runner.")
            task.setTaskCompleted(success: false)
            return
        }
        let attemptID = UUID().uuidString
        let generation = lifecycleGeneration
        let completion = BackgroundCompletionLatch()

        task.expirationHandler = {
            guard completion.claim() else { return }
            Task { @MainActor in
                if generation == BackgroundExecutionCoordinator.shared.lifecycleGeneration {
                    let fallback = BackgroundExecutionCoordinator.shared.activeCheckpoint
                    let expiringWork = BackgroundExecutionCoordinator.shared.activeWork
                    expiringWork?.cancel()
                    AgentRunner.shared.pauseForSystemInterruption(reason: BackgroundExecutionReason.taskExpired.rawValue)
                    let checkpoint = BackgroundExecutionCoordinator.shared.currentCheckpoint() ?? fallback
                    BackgroundExecutionCoordinator.shared.record(
                        attemptID: attemptID,
                        checkpoint: checkpoint,
                        state: .expired,
                        reason: .taskExpired,
                        detail: "iOS ended this grant. The saved checkpoint was not silently replayed."
                    )
                    BackgroundExecutionCoordinator.shared.scheduleSafeRetry(fallback: checkpoint, reason: .taskExpired)
                    await expiringWork?.value
                }
                task.setTaskCompleted(success: false)
            }
        }

        activeWork = Task { @MainActor in
            let succeeded = await self.perform(attemptID: attemptID, generation: generation)
            if completion.claim() { task.setTaskCompleted(success: succeeded) }
            if generation == self.lifecycleGeneration {
                self.activeWork = nil
                self.activeCheckpoint = nil
            }
        }
    }

    private func perform(attemptID: String, generation: Int) async -> Bool {
        if Task.isCancelled || generation != lifecycleGeneration { return false }
        let protectedData = UIApplication.shared.isProtectedDataAvailable
        guard protectedData else {
            record(attemptID: attemptID, checkpoint: nil, state: .deferred,
                   reason: .protectedDataUnavailable,
                   detail: "The system grant arrived while complete file protection was active.")
            submitBlindRetry(earliestDelay: 15 * 60, requiresNetwork: true,
                             reason: .protectedDataUnavailable,
                             detail: "Protected data was locked. Submitted a conservative retry that also waits for network availability.")
            return false
        }

        do {
            try SandboxStore.shared.restore()
            let checkpoint = try SandboxStore.shared.loadIfPresent(RunCheckpoint.self, path: "state/active.json")
            let currentPolicy = try savedPolicy()
            let context = BackgroundExecutionContext(
                protectedDataAvailable: protectedData,
                workspaceConnected: SandboxStore.shared.connected,
                workspaceRequiresNetworkConnectivity: SandboxStore.shared.backgroundRequiresNetworkConnectivity,
                backgroundRefreshAvailable: UIApplication.shared.backgroundRefreshStatus == .available,
                nativeProviderAvailable: AppProvider.apple.unavailableReason == nil,
                currentPolicy: currentPolicy
            )
            switch BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: context) {
            case .resume(let plan):
                guard let checkpoint else { return false }
                activeCheckpoint = checkpoint
                record(attemptID: attemptID, checkpoint: checkpoint, state: .running,
                       reason: .systemGrantStarted,
                       requiresNetwork: plan.requiresNetworkConnectivity,
                       detail: "Resuming step \(plan.nextStep + 1) from a persisted safe boundary.")
                do {
                    let receipt = try await AgentRunner.shared.resume(checkpoint: checkpoint)
                    guard generation == lifecycleGeneration else { return false }
                    let goalFinished = receipt.status == .verified
                    record(attemptID: attemptID, checkpoint: currentCheckpoint(),
                           state: goalFinished ? .completed : .reviewRequired,
                           reason: goalFinished ? .runnerCompleted : .runnerFailed,
                           requiresNetwork: plan.requiresNetworkConnectivity,
                           detail: "Run ended with receipt status \(receipt.status.rawValue).")
                    return true
                } catch let interruption as AgentRunInterruption {
                    guard generation == lifecycleGeneration else { return false }
                    let reason = BackgroundExecutionReason(rawValue: interruption.reason) ?? .resourceGate
                    let state: BackgroundExecutionState = reason == .taskExpired ? .expired : .deferred
                    let latestCheckpoint = currentCheckpoint() ?? activeCheckpoint
                    record(attemptID: attemptID, checkpoint: latestCheckpoint, state: state,
                           reason: reason,
                           requiresNetwork: plan.requiresNetworkConnectivity,
                           detail: interruption.localizedDescription)
                    scheduleSafeRetry(fallback: latestCheckpoint, reason: reason)
                    return false
                }
            case .deferred(let reason):
                record(attemptID: attemptID, checkpoint: checkpoint, state: .deferred,
                       reason: reason, detail: "The background prerequisites are not currently available.")
                if reason == .protectedDataUnavailable {
                    submitBlindRetry(earliestDelay: 15 * 60, requiresNetwork: true, reason: reason,
                                     detail: "Submitted a conservative retry because the protected workspace could not be inspected.")
                }
                return false
            case .reviewRequired(let reason):
                record(attemptID: attemptID, checkpoint: checkpoint, state: .reviewRequired,
                       reason: reason,
                       detail: "Open Local Sandbox and inspect the recorded checkpoint before continuing.")
                return false
            case .noWork(let reason):
                record(attemptID: attemptID, checkpoint: checkpoint, state: .noWork,
                       reason: reason, detail: "No resumable native work remained when iOS launched the app.")
                return true
            }
        } catch {
            if Task.isCancelled || generation != lifecycleGeneration { return false }
            if !UIApplication.shared.isProtectedDataAvailable {
                record(attemptID: attemptID, checkpoint: currentCheckpoint(), state: .deferred,
                       reason: .protectedDataUnavailable,
                       detail: "The device locked while the workspace state was being inspected.")
                submitBlindRetry(earliestDelay: 15 * 60, requiresNetwork: true,
                                 reason: .protectedDataUnavailable,
                                 detail: "Submitted a conservative retry because the protected workspace could not be inspected.")
                return false
            }
            record(attemptID: attemptID, checkpoint: currentCheckpoint(), state: .failed,
                   reason: .runnerFailed, detail: error.localizedDescription)
            return false
        }
    }

    private func savedPolicy() throws -> ResourcePolicy? {
        guard let data = UserDefaults.standard.data(forKey: "policy") else { return nil }
        return try JSONDecoder().decode(ResourcePolicy.self, from: data).validated()
    }

    private func currentCheckpoint() -> RunCheckpoint? {
        do { return try SandboxStore.shared.loadIfPresent(RunCheckpoint.self, path: "state/active.json") }
        catch { return nil }
    }

    private func scheduleSafeRetry(fallback: RunCheckpoint?, reason: BackgroundExecutionReason) {
        let checkpoint = currentCheckpoint() ?? fallback
        guard let checkpoint, BackgroundExecutionPolicy.resumablePhases.contains(checkpoint.phase) else { return }
        let requiresNetwork = SandboxStore.shared.connected ? SandboxStore.shared.backgroundRequiresNetworkConnectivity : true
        submitBlindRetry(earliestDelay: 15 * 60, requiresNetwork: requiresNetwork, reason: reason,
                         detail: "Saved a safe checkpoint and submitted one bounded retry.")
    }

    private func submitBlindRetry(earliestDelay: TimeInterval, requiresNetwork: Bool,
                                  reason: BackgroundExecutionReason, detail: String) {
        let request = BGProcessingTaskRequest(identifier: Self.taskIdentifier)
        request.earliestBeginDate = Date().addingTimeInterval(max(0, earliestDelay))
        request.requiresNetworkConnectivity = requiresNetwork
        request.requiresExternalPower = false
        submit(request, checkpoint: activeCheckpoint, reason: reason, detail: detail)
    }

    private func submit(_ request: BGProcessingTaskRequest, checkpoint: RunCheckpoint?,
                        reason: BackgroundExecutionReason, detail: String) {
        queuedSubmission = PendingSubmission(
            token: UUID().uuidString,
            generation: lifecycleGeneration,
            request: request,
            checkpoint: checkpoint,
            reason: reason,
            detail: detail
        )
        drainSubmissionQueue()
    }

    private func drainSubmissionQueue() {
        guard activeSubmission == nil, let submission = queuedSubmission else { return }
        queuedSubmission = nil
        activeSubmission = submission
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
        if #available(iOS 27.0, *) {
            Self.submitTaskRequestOffMain(
                token: submission.token,
                identifier: submission.request.identifier,
                earliestBeginDate: submission.request.earliestBeginDate,
                requiresNetworkConnectivity: submission.request.requiresNetworkConnectivity,
                requiresExternalPower: submission.request.requiresExternalPower
            )
        } else {
            do {
                try BGTaskScheduler.shared.submit(submission.request)
                finishSubmission(token: submission.token, errorDetail: nil)
            } catch {
                finishSubmission(token: submission.token, errorDetail: error.localizedDescription)
            }
        }
    }

    @available(iOS 27.0, *)
    private nonisolated static func submitTaskRequestOffMain(
        token: String,
        identifier: String,
        earliestBeginDate: Date?,
        requiresNetworkConnectivity: Bool,
        requiresExternalPower: Bool
    ) {
        DispatchQueue.global(qos: .utility).async {
            let request = BGProcessingTaskRequest(identifier: identifier)
            request.earliestBeginDate = earliestBeginDate
            request.requiresNetworkConnectivity = requiresNetworkConnectivity
            request.requiresExternalPower = requiresExternalPower
            BGTaskScheduler.shared.submitTaskRequest(request) { error in
                let errorDetail = error?.localizedDescription
                Task { @MainActor in
                    BackgroundExecutionCoordinator.shared.finishSubmission(
                        token: token,
                        errorDetail: errorDetail
                    )
                }
            }
        }
    }

    private func finishSubmission(token: String, errorDetail: String?) {
        guard let submission = activeSubmission, submission.token == token else { return }
        activeSubmission = nil

        if submission.generation != lifecycleGeneration {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
        } else if queuedSubmission == nil {
            if let errorDetail {
                record(
                    attemptID: submission.token, checkpoint: submission.checkpoint, state: .failed,
                    reason: .schedulerRejected,
                    requiresNetwork: submission.request.requiresNetworkConnectivity,
                    detail: errorDetail
                )
            } else {
                record(
                    attemptID: submission.token, checkpoint: submission.checkpoint, state: .scheduled,
                    reason: submission.reason,
                    requiresNetwork: submission.request.requiresNetworkConnectivity,
                    detail: submission.detail
                )
            }
        }
        drainSubmissionQueue()
    }

    private func record(attemptID: String, checkpoint: RunCheckpoint?, state: BackgroundExecutionState,
                        reason: BackgroundExecutionReason, requiresNetwork: Bool = false,
                        detail: String?) {
        let protectedData = UIApplication.shared.isProtectedDataAvailable
        var paths = ["device:backgroundExecutionStatus"]
        let workspacePath = Self.workspaceStatusPath()
        if protectedData && SandboxStore.shared.connected { paths.append(workspacePath) }
        var event = BackgroundExecutionRecord(
            attemptID: attemptID,
            runID: checkpoint?.runID,
            state: state,
            reason: reason,
            checkpointPhase: checkpoint?.phase,
            nextStep: checkpoint?.nextStep,
            provider: checkpoint?.policy?.provider,
            requiresNetworkConnectivity: requiresNetwork,
            protectedDataAvailable: protectedData,
            recordedAt: ISO8601DateFormatter().string(from: Date()),
            detail: detail,
            evidencePaths: paths
        )
        if paths.count == 2 {
            do {
                try SandboxStore.shared.save(event, path: workspacePath)
            } catch {
                event = BackgroundExecutionRecord(
                    attemptID: event.attemptID,
                    runID: event.runID,
                    state: event.state,
                    reason: event.reason,
                    checkpointPhase: event.checkpointPhase,
                    nextStep: event.nextStep,
                    provider: event.provider,
                    requiresNetworkConnectivity: event.requiresNetworkConnectivity,
                    protectedDataAvailable: event.protectedDataAvailable,
                    recordedAt: event.recordedAt,
                    detail: (event.detail ?? "") + " Workspace status mirror failed: " + error.localizedDescription,
                    evidencePaths: ["device:backgroundExecutionStatus"]
                )
            }
        }
        if let data = try? JSONEncoder.sorted.encode(event) {
            UserDefaults.standard.set(data, forKey: Self.statusDefaultsKey)
        }
    }

    private static func workspaceStatusPath() -> String {
        let defaults = UserDefaults.standard
        let deviceID: String
        if let saved = defaults.string(forKey: deviceIDDefaultsKey) {
            deviceID = saved
        } else {
            deviceID = UUID().uuidString
            defaults.set(deviceID, forKey: deviceIDDefaultsKey)
        }
        return "state/background-execution-\(SandboxStore.hash(deviceID).prefix(16)).json"
    }
}
#endif
