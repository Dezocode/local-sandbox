import Foundation
import UIKit
import UserNotifications
import Darwin

struct DeviceSnapshot {
    let battery: Int?
    let memoryBytes: UInt64?
    let physicalMemory: UInt64
    let thermal: ProcessInfo.ThermalState
    @MainActor static func read() -> Self {
        UIDevice.current.isBatteryMonitoringEnabled = true
        let level = UIDevice.current.batteryLevel
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let code = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), rebound, &count)
            }
        }
        return Self(battery: level >= 0 ? Int((level * 100).rounded()) : nil,
                    memoryBytes: code == KERN_SUCCESS ? info.phys_footprint : nil,
                    physicalMemory: ProcessInfo.processInfo.physicalMemory,
                    thermal: ProcessInfo.processInfo.thermalState)
    }
    func stopReason(policy: ResourcePolicy, initialBattery: Int?) -> String? {
        guard let battery, let initialBattery else { return "BATTERY_TELEMETRY_UNAVAILABLE" }
        if battery < policy.batteryReserve { return "BATTERY_RESERVE_REACHED" }
        if initialBattery - battery >= policy.batteryBudget { return "BATTERY_DROP_BUDGET_REACHED" }
        if thermal == .serious || thermal == .critical { return "THERMAL_PRESSURE" }
        guard let memoryBytes else { return "MEMORY_TELEMETRY_UNAVAILABLE" }
        if Double(memoryBytes) / Double(physicalMemory) * 100 > Double(policy.memoryTarget) { return "APP_MEMORY_TARGET_REACHED" }
        return nil
    }
}

@MainActor
final class Dispatcher {
    static let shared = Dispatcher()
    private let store = SandboxStore.shared
    private lazy var executor = NativeToolExecutor(storage: store)

    func execute(
        _ raw: ToolCall,
        callID: String,
        policy: ResourcePolicy,
        authorizedRead: ToolEvidence? = nil,
        beforeSideEffect: @MainActor () throws -> Void
    ) async throws -> ToolResult {
        try beforeSideEffect()
        switch try executor.prepare(raw, callID: callID, authorizedRead: authorizedRead) {
        case .cached(let result):
            return result
        case .ready(let prepared):
            let result: ToolResult
            switch prepared.operation {
            case .read, .list, .create, .append, .patch:
                try beforeSideEffect()
                result = try executor.performFile(prepared, callID: callID)
            case .clipboardGet:
                guard policy.clipboardReadAllowed else { throw SandboxError.blocked("CLIPBOARD_READ_NOT_AUTHORIZED") }
                try beforeSideEffect()
                result = ToolResult(ok: true, tool: ToolName.clipboardGet.rawValue, result: String((UIPasteboard.general.string ?? "").prefix(4_000)), sha256: nil, error_code: nil)
            case .clipboardSet(let content):
                guard policy.clipboardWriteAllowed else { throw SandboxError.blocked("CLIPBOARD_WRITE_NOT_AUTHORIZED") }
                try beforeSideEffect()
                UIPasteboard.general.string = content
                result = ToolResult(ok: true, tool: ToolName.clipboardSet.rawValue, result: "Clipboard updated.", sha256: nil, error_code: nil)
            case .notify(let body):
                guard policy.notifications else { throw SandboxError.blocked("NOTIFICATIONS_NOT_AUTHORIZED") }
                let content = UNMutableNotificationContent()
                content.title = "Local Sandbox"
                content.body = String(body.prefix(200))
                try beforeSideEffect()
                try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: callID, content: content, trigger: nil))
                result = ToolResult(ok: true, tool: ToolName.notify.rawValue, result: "Notification submitted to iOS.", sha256: nil, error_code: nil)
            }
            try beforeSideEffect()
            try executor.complete(prepared, result: result)
            return result
        }
    }
}
extension JSONEncoder { static var sorted: JSONEncoder { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return e } }

enum AgentRunInterruption: LocalizedError {
    case systemDeferred(String)

    var reason: String {
        switch self {
        case .systemDeferred(let reason): return reason
        }
    }

    var errorDescription: String? {
        "BACKGROUND_DEFERRED: \(reason)"
    }
}

enum AgentRunCancellationDisposition: Equatable, Sendable {
    case userCancelled
    case systemDeferred(String)
}

@MainActor
final class AgentRunner {
    static let shared = AgentRunner()
    private(set) var running = false
    private var cancelled = false
    private var generation: Task<String, Error>?
    private var systemInterruptionReason: String?

    func cancel() {
        systemInterruptionReason = nil
        cancelled = true
        generation?.cancel()
    }

    func pauseForSystemInterruption(reason: String) {
        ExecutionContinuationGate.shared.invalidate()
        guard running else { return }
        systemInterruptionReason = reason
        cancelled = true
        generation?.cancel()
    }

    func run(goal: String, policy rawPolicy: ResourcePolicy, contract: GoalContract? = nil,
             authorizationPolicy rawAuthorizationPolicy: ResourcePolicy? = nil,
             taskOrigin: ProviderTaskOrigin,
             routingEvidence: ProviderRoutingEvidence,
             executionGeneration providedExecutionGeneration: ExecutionContinuationGate.Generation? = nil,
             systemManaged: Bool = false,
             cancellationDisposition: @escaping @Sendable () -> AgentRunCancellationDisposition? = { nil },
             onProgress: @escaping (String) -> Void = { _ in },
             onHeartbeat: @escaping (String) -> Void = { _ in }) async throws -> RunReceipt {
        let executionGeneration = providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()
        try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)
        guard !running else { throw SandboxError.blocked("ANOTHER_RUN_IS_ACTIVE") }
        guard !ProviderQualificationStore.qualificationActive else { throw SandboxError.blocked("PROVIDER_QUALIFICATION_IS_ACTIVE") }
        let policy = try rawPolicy.validated()
        let authorizationPolicy = try (rawAuthorizationPolicy ?? policy).validated()
        var expectedResolvedPolicy = authorizationPolicy
        expectedResolvedPolicy.provider = policy.provider
        guard policy == expectedResolvedPolicy else {
            throw SandboxError.blocked("RESOLVED_POLICY_EXCEEDS_SAVED_AUTHORIZATION")
        }
        let continuationValidator = makeContinuationValidator(
            policy: policy,
            authorizationPolicy: authorizationPolicy,
            taskOrigin: taskOrigin,
            routingEvidence: routingEvidence,
            executionGeneration: executionGeneration
        )
        try continuationValidator.beforePlanningContinuation()
        guard !goal.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, goal.count <= 2000 else { throw SandboxError.invalid("GOAL_MUST_BE_1_TO_2000_CHARACTERS") }
        guard SandboxStore.shared.connected else { throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST") }
        try ExecutionAdmission.ensureCanStart()
        return try await execute(goal: goal, policy: policy, authorizationPolicy: authorizationPolicy,
                                 taskOrigin: taskOrigin, routingEvidence: routingEvidence, contract: contract, checkpoint: nil,
                                 continuationValidator: continuationValidator,
                                 systemManaged: systemManaged, cancellationDisposition: cancellationDisposition,
                                 onProgress: onProgress, onHeartbeat: onHeartbeat)
    }

    func resume(
        checkpoint: RunCheckpoint,
        executionGeneration providedExecutionGeneration: ExecutionContinuationGate.Generation? = nil,
        onProgress: @escaping (String) -> Void = { _ in }
    ) async throws -> RunReceipt {
        let executionGeneration = providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()
        try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)
        guard !running else { throw SandboxError.blocked("ANOTHER_RUN_IS_ACTIVE") }
        guard !ProviderQualificationStore.qualificationActive else { throw SandboxError.blocked("PROVIDER_QUALIFICATION_IS_ACTIVE") }
        guard BackgroundExecutionPolicy.resumablePhases.contains(checkpoint.phase) else {
            throw SandboxError.blocked("BACKGROUND_CHECKPOINT_REQUIRES_REVIEW")
        }
        guard let policy = try checkpoint.policy?.validated(), policy.provider == "apple",
              let authorizationPolicy = try checkpoint.authorizationPolicy?.validated(),
              let taskOrigin = checkpoint.taskOrigin,
              let routingEvidence = checkpoint.routingEvidence else {
            throw SandboxError.blocked("BACKGROUND_REQUIRES_APPLE_POLICY_SNAPSHOT")
        }
        guard checkpoint.nextStep < policy.maxSteps else { throw SandboxError.blocked("BACKGROUND_STEP_BUDGET_EXHAUSTED") }
        guard !checkpoint.goal.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, checkpoint.goal.count <= 2000 else {
            throw SandboxError.invalid("GOAL_MUST_BE_1_TO_2000_CHARACTERS")
        }
        guard SandboxStore.shared.connected else { throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST") }
        let continuationValidator = makeContinuationValidator(
            policy: policy,
            authorizationPolicy: authorizationPolicy,
            taskOrigin: taskOrigin,
            routingEvidence: routingEvidence,
            executionGeneration: executionGeneration
        )
        do { try continuationValidator.beforePlanningContinuation() }
        catch { throw SandboxError.blocked("BACKGROUND_AUTHORIZATION_OR_ROUTE_CHANGED") }
        try ExecutionAdmission.ensureCanResume(checkpoint)
        return try await execute(goal: checkpoint.goal, policy: policy, authorizationPolicy: authorizationPolicy,
                                 taskOrigin: taskOrigin, routingEvidence: routingEvidence, contract: checkpoint.contract,
                                 checkpoint: checkpoint, continuationValidator: continuationValidator,
                                 systemManaged: true, cancellationDisposition: { nil },
                                 onProgress: onProgress, onHeartbeat: { _ in })
    }

    private func validateCurrentAppleRoute(
        policy: ResourcePolicy,
        authorizationPolicy: ResourcePolicy,
        taskOrigin: ProviderTaskOrigin,
        routingEvidence: ProviderRoutingEvidence
    ) throws {
        let expectedActivity: ProviderActivitySignal = running ? .nativeRunActive : .workspaceIdle
        guard ProviderRuntimeCapabilities.activity == expectedActivity else {
            throw SandboxError.blocked("APP_ACTIVITY_CHANGED_RESTART_TASK")
        }
        if let session = ShortcutCoordinator.shared.current(), ["awaiting_response", "applying"].contains(session.phase) {
            throw SandboxError.blocked("APP_ACTIVITY_CHANGED_RESTART_TASK")
        }
        guard let authorizedProvider = AppProvider(rawValue: authorizationPolicy.provider) else {
            throw SandboxError.blocked("ROUTING_EVIDENCE_EXCEEDS_SAVED_AUTHORIZATION")
        }
        guard policy.provider == AppProvider.apple.rawValue,
              policy.contextChars <= ProviderQualificationSnapshot.appleMaximumContextCharacters,
              routingEvidence.provider == .apple,
              routingEvidence.authorizedProvider.rawValue == authorizationPolicy.provider,
              routingEvidence.selection != .saved || policy.provider == authorizationPolicy.provider else {
            throw SandboxError.blocked("ROUTING_EVIDENCE_EXCEEDS_SAVED_AUTHORIZATION")
        }
        do { try routingEvidence.validate() }
        catch { throw SandboxError.blocked("PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK") }
        let qualifications: [AppProvider: ProviderQualificationSnapshot]
        do { qualifications = try ProviderQualificationStore.snapshots() }
        catch { throw SandboxError.blocked("PROVIDER_QUALIFICATION_LEDGER_UNREADABLE_RESTART_TASK") }
        let requirements = OracleTaskRequirements.filesystem(
            policyContextCharacters: policy.contextChars,
            localOnly: true,
            unattended: taskOrigin == .appIntent
        )
        let savedStrategy: ProviderRoutingStrategy = routingEvidence.selection == .saved &&
            ProviderQualificationStore.hasCurrentRecommendation(provider: authorizedProvider, policy: authorizationPolicy)
            ? .oracleRecommendation : .savedPinned
        let resolved = ProviderRoutingPolicy.resolve(
            selection: routingEvidence.selection,
            savedProvider: authorizedProvider,
            appleAvailability: ProviderRuntimeCapabilities.appleModel,
            shortcutsAvailable: ProviderRuntimeCapabilities.shortcutsAvailable,
            adapterFor: AdapterSettings.get,
            cloudAllowed: authorizationPolicy.cloudAllowed,
            qualifications: qualifications,
            requirements: requirements,
            activity: .workspaceIdle,
            deviceProfileSHA256: ProviderQualificationStore.deviceProfileSHA256(),
            configurationSHA256: ProviderQualificationStore.configurationSHA256(policy: authorizationPolicy),
            savedStrategy: savedStrategy
        )
        guard resolved.provider == .apple,
              resolved.decision == .onDeviceApple,
              resolved.evidence == routingEvidence else {
            throw SandboxError.blocked("PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK")
        }
    }

    private func makeContinuationValidator(
        policy: ResourcePolicy,
        authorizationPolicy: ResourcePolicy,
        taskOrigin: ProviderTaskOrigin,
        routingEvidence: ProviderRoutingEvidence,
        executionGeneration: ExecutionContinuationGate.Generation
    ) -> ExecutionContinuationValidator {
        ExecutionContinuationValidator {
            try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)
            try SavedExecutionAuthorization.requireExact(authorizationPolicy)
            try self.validateCurrentAppleRoute(
                policy: policy,
                authorizationPolicy: authorizationPolicy,
                taskOrigin: taskOrigin,
                routingEvidence: routingEvidence
            )
        }
    }

    private func execute(goal: String, policy: ResourcePolicy, authorizationPolicy: ResourcePolicy,
                         taskOrigin: ProviderTaskOrigin, routingEvidence: ProviderRoutingEvidence,
                         contract: GoalContract?, checkpoint: RunCheckpoint?,
                         continuationValidator: ExecutionContinuationValidator,
                         systemManaged: Bool,
                         cancellationDisposition: @escaping @Sendable () -> AgentRunCancellationDisposition?,
                         onProgress: @escaping (String) -> Void,
                         onHeartbeat: @escaping (String) -> Void) async throws -> RunReceipt {
        try continuationValidator.beforePlanningContinuation()
        running = true
        cancelled = false
        systemInterruptionReason = nil
        defer {
            running = false
            generation = nil
            systemInterruptionReason = nil
        }
        let id = checkpoint?.runID ?? UUID().uuidString
        let start = checkpoint?.startedAt ?? Date()
        let initialBattery = checkpoint?.initialBattery ?? DeviceSnapshot.read().battery
        var trace = checkpoint?.trace ?? []
        var failures = checkpoint?.failures ?? 0
        var steps = checkpoint?.nextStep ?? 0
        var lastFailure = checkpoint?.lastFailure ?? ""
        var repeated = checkpoint?.repeated ?? 0
        var unresolvedFailure = !lastFailure.isEmpty
        var latest = checkpoint?.lastResult ?? "No tools executed."
        var latestResult = checkpoint?.latestResult
        var authorizedRead: ToolEvidence?
        if let latestResult, latestResult.tool == ToolName.read.rawValue,
           latestResult.isCompleteInPrompt(maxCharacters: latestPromptBudget(limit: min(policy.contextChars, 6000))) {
            authorizedRead = latestResult.evidence
        }
        var assertionEvidence: [AssertionEvidence] = []
        var capsule = checkpoint?.capsule ?? ("Goal accepted. No actions complete." + (contract.map { " Verification: " + $0.promptDescription } ?? " Verification contract: none; completion cannot be marked verified."))
        var status: RunStatus = .blocked
        var summary = "STEP_BUDGET_EXHAUSTED"
        let provider: any StepProvider
        switch policy.provider {
        case "apple": provider = AppleProvider()
        default: throw SandboxError.blocked("RUN_LOCAL_PROVIDER_THROUGH_SHORTCUTS")
        }

        func savedCheckpoint(nextStep: Int, phase: String) -> RunCheckpoint {
            RunCheckpoint(
                runID: id,
                goal: goal,
                nextStep: nextStep,
                capsule: capsule,
                lastResult: latest,
                phase: phase,
                contract: contract,
                latestResult: latestResult,
                policy: policy,
                authorizationPolicy: authorizationPolicy,
                taskOrigin: taskOrigin,
                routingEvidence: routingEvidence,
                trace: trace,
                failures: failures,
                repeated: repeated,
                lastFailure: lastFailure,
                initialBattery: initialBattery,
                startedAt: start
            )
        }

        func throwIfSystemDeferred(_ fallback: String) throws {
            if let reason = systemInterruptionReason { throw AgentRunInterruption.systemDeferred(reason) }
            let disposition = cancellationDisposition()
            if case .systemDeferred(let reason) = disposition {
                throw AgentRunInterruption.systemDeferred(reason)
            }
            if disposition == .userCancelled { return }
            if systemManaged && Task.isCancelled { throw AgentRunInterruption.systemDeferred(fallback) }
        }

        func userCancelled() -> Bool {
            cancellationDisposition() == .userCancelled
        }

        for step in steps..<policy.maxSteps {
            steps = step + 1
            try throwIfSystemDeferred(BackgroundExecutionReason.taskExpired.rawValue)
            if cancelled || userCancelled() || Task.isCancelled { status = .cancelled; summary = "Cancelled by user."; break }
            if let reason = DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) {
                if systemManaged { throw AgentRunInterruption.systemDeferred(reason) }
                summary = reason
                break
            }
            do {
                try continuationValidator.beforePlanningContinuation()
                try continuationValidator.beforePersistence()
                try SandboxStore.shared.save(savedCheckpoint(nextStep: step, phase: "planning"), path: "state/active.json")
                onProgress("Planning step \(step + 1) of \(policy.maxSteps)")
                let pending = Task { @MainActor in
                    try continuationValidator.requireCurrent()
                    try Task.checkCancellation()
                    return try await provider.step(goal: goal, capsule: capsule, latest: latest, policy: policy)
                }
                generation = pending
                let monitor = Task { @MainActor in
                    var elapsedSeconds = 0
                    while !Task.isCancelled {
                        try? await Task.sleep(nanoseconds: 1_000_000_000)
                        if Task.isCancelled { break }
                        do { try continuationValidator.afterAwait() }
                        catch { pending.cancel(); break }
                        elapsedSeconds += 1
                        if elapsedSeconds.isMultiple(of: 5) {
                            onHeartbeat("Apple Intelligence is still working · step \(step + 1) of \(policy.maxSteps)")
                        }
                        if DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) != nil || self.cancelled { pending.cancel(); break }
                    }
                }
                let text: String
                do {
                    text = try await continuationValidator.validatedAwait {
                        try await withTaskCancellationHandler {
                            try await pending.value
                        } onCancel: {
                            pending.cancel()
                        }
                    }
                    monitor.cancel()
                }
                catch { monitor.cancel(); throw error }
                try throwIfSystemDeferred(BackgroundExecutionReason.taskExpired.rawValue)
                if let reason = DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) {
                    if systemManaged { throw AgentRunInterruption.systemDeferred(reason) }
                    summary = reason
                    break
                }
                if cancelled || userCancelled() { status = .cancelled; summary = "Cancelled by user."; break }
                switch try AgentAction.parse(text) {
                case .final(let message):
                    summary = message
                    if unresolvedFailure {
                        status = .blocked
                        summary = "An unresolved failure prevents verification. " + message
                    } else if let contract {
                        assertionEvidence = GoalVerifier.verify(contract)
                        status = assertionEvidence.allSatisfy(\.passed) ? .verified : .completed
                        if status != .verified { summary = "Completed, but independent goal verification failed. " + message }
                    } else {
                        status = .completed
                        summary = "Completed without an approved verification contract. " + message
                    }
                case .tool(let call):
                    onProgress("Executing \(call.tool.rawValue)")
                    try continuationValidator.beforePersistence()
                    try SandboxStore.shared.save(savedCheckpoint(nextStep: step, phase: "executing"), path: "state/active.json")
                    let value = try await Dispatcher.shared.execute(
                        call,
                        callID: "\(id)-\(step)",
                        policy: policy,
                        authorizedRead: authorizedRead,
                        beforeSideEffect: continuationValidator.beforeDispatcherSideEffect
                    )
                    unresolvedFailure = false
                    lastFailure = ""
                    repeated = 0
                    let promptBudget = latestPromptBudget(limit: min(policy.contextChars, 6000))
                    latest = value.promptJSON(maxCharacters: promptBudget)
                    latestResult = value
                    authorizedRead = call.tool == .read && value.isCompleteInPrompt(maxCharacters: promptBudget) ? value.evidence : nil
                    trace.append(.receiptSuccess(value))
                    capsule = "Goal: \(goal.prefix(700)). Completed \(trace.count) calls. Last: \(call.tool.rawValue). Failures: \(failures). Continue from the last result. Reread before any edit."
                    try continuationValidator.beforePersistence()
                    try SandboxStore.shared.save(savedCheckpoint(nextStep: step + 1, phase: "ready"), path: "state/active.json")
                    continue
                }
                break
            } catch {
                try throwIfSystemDeferred(BackgroundExecutionReason.taskExpired.rawValue)
                // A retired continuation is authorization loss, not a provider failure.
                try continuationValidator.requireCurrent()
                if cancelled || userCancelled() || Task.isCancelled { status = .cancelled; summary = "Cancelled by user."; break }
                if let reason = DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) {
                    if systemManaged { throw AgentRunInterruption.systemDeferred(reason) }
                    summary = reason
                    break
                }
                unresolvedFailure = true
                authorizedRead = nil
                failures += 1
                let message = error.localizedDescription
                trace.append(.receiptError(tool: "step", message: message))
                repeated = message == lastFailure ? repeated + 1 : 1
                lastFailure = message
                latest = "ERROR: \(message). Repair invalid JSON once. Reread for patch or hash conflicts. Do not repeat an uncertain mutation."
                summary = message
                if let typed = error as? SandboxError, case .blocked = typed { break }
                if failures >= policy.maxFailures || repeated >= 2 { break }
            }
        }
        let environment = ReceiptEnvironment(appVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown", build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown", os: UIDevice.current.systemVersion, device: UIDevice.current.model)
        let policyDigest = SandboxStore.hash(String(decoding: try JSONEncoder.sorted.encode(policy), as: UTF8.self))
        let receipt = try RunReceipt(id: id, goal: goal, status: status, origin: "native", summary: String(summary.prefix(3000)), steps: steps, failures: failures, durationMs: Date().timeIntervalSince(start) * 1000, createdAt: ISO8601DateFormatter().string(from: Date()), trace: trace, contract: contract, assertions: assertionEvidence, provider: policy.provider, policyDigest: policyDigest, workspaceID: SandboxStore.shared.workspaceID, environment: environment, taskOrigin: taskOrigin, routingEvidence: routingEvidence)
        try continuationValidator.beforePersistence()
        try SandboxStore.shared.saveReceipt(receipt, path: "logs/\(id).json")
        capsule = summary
        try continuationValidator.beforePersistence()
        try SandboxStore.shared.save(savedCheckpoint(nextStep: steps, phase: status.rawValue), path: "state/active.json")
        if policy.notifications {
            let content = UNMutableNotificationContent(); content.title = "Local Sandbox · \(status.rawValue)"; content.body = ReceiptPrivacy.safeSummary(status: status)
            do {
                try await continuationValidator.validatedAwait {
                    try continuationValidator.beforeDispatcherSideEffect()
                    try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
                }
            } catch {
                // Notification delivery remains best-effort, but lock retirement does not.
                try continuationValidator.requireCurrent()
            }
        }
        try continuationValidator.requireCurrent()
        return receipt
    }
}
