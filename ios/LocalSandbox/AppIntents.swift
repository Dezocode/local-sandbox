import AppIntents
import Foundation

@available(iOS 27.0, *)
private final class LongIntentCancellationState: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: AgentRunCancellationDisposition?

    func record(_ reason: IntentCancellationReason) {
        lock.lock()
        stored = reason == .userCancelled
            ? .userCancelled
            : .systemDeferred(reason == .timeout ? "APP_INTENT_LONG_RUN_TIMEOUT" : "APP_INTENT_LONG_RUN_SYSTEM_CANCELLED")
        lock.unlock()
    }

    func current() -> AgentRunCancellationDisposition? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}

extension ProviderSelection: AppEnum {
    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "Provider")
    static let caseDisplayRepresentations: [ProviderSelection: DisplayRepresentation] = [
        .saved: "Saved provider",
        .bestLocal: "Best local",
        .apple: "Apple Intelligence on device",
        .local: "Locally",
        .chatgpt: "ChatGPT",
        .grok: "Grok",
        .grokbot: "Grokbot",
        .claude: "Claude"
    ]
}

@MainActor
private func authenticateSensitiveIntent() async throws -> ExecutionContinuationGate.Generation {
    let executionGeneration=ExecutionContinuationGate.shared.capture()
    let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
    let localAccessLease=try await continuationValidator.validatedAwait {
        try await LocalAccess.authenticate(executionGeneration:executionGeneration)
    }
    try localAccessLease.requireCurrent()
    return executionGeneration
}

@MainActor
private func executeProviderTask(
    goal: String,
    policy: ResourcePolicy,
    providerSelection: ProviderSelection,
    contract: GoalContract,
    executionGeneration: ExecutionContinuationGate.Generation,
    systemManaged: Bool = false,
    cancellationDisposition: @escaping @Sendable () -> AgentRunCancellationDisposition? = { nil },
    onProgress: @escaping (String) -> Void = { _ in },
    onHeartbeat: @escaping (String) -> Void = { _ in }
) async throws -> String {
    let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
    try continuationValidator.requireCurrent()
    if let checkpoint=try? SandboxStore.shared.load(RunCheckpoint.self,path:"state/active.json"),
       ["planning","executing","ready"].contains(checkpoint.phase) {
        throw SandboxError.blocked("Review the interrupted run in Local Sandbox before continuing.")
    }
    let route=try ProviderRuntimeCapabilities.resolve(selection:providerSelection,policy:policy,unattended:true)
    switch route.decision {
    case .onDeviceApple:
        guard let routingEvidence=route.evidence else {throw SandboxError.blocked("ROUTING_EVIDENCE_NOT_COMMITTABLE")}
        var directPolicy=policy
        directPolicy.provider=AppProvider.apple.rawValue
        let receipt=try await continuationValidator.validatedAwait {
            try await AgentRunner.shared.run(
                goal:goal,
                policy:try directPolicy.validated(),
                contract:contract,
                authorizationPolicy:policy,
                taskOrigin:.appIntent,
                routingEvidence:routingEvidence,
                executionGeneration:executionGeneration,
                systemManaged:systemManaged,
                cancellationDisposition:cancellationDisposition,
                onProgress:onProgress,
                onHeartbeat:onHeartbeat
            )
        }
        let payload=String(decoding:try receipt.encodedWireData(),as:UTF8.self)
        try continuationValidator.requireCurrent()
        return try AppIntentTaskOutput.terminalAppleReceipt(selection:providerSelection,phase:receipt.status,payload:payload).json
    case .shortcut:
        let prompt=try ShortcutCoordinator.shared.begin(
            goal:goal,
            policy:policy,
            contract:contract,
            providerSelection:providerSelection,
            origin:.appIntent,
            resolvedRoute:route,
            executionGeneration:executionGeneration
        )
        return try ShortcutCoordinator.shared.appIntentOutput(payload:prompt,executionGeneration:executionGeneration)
    case .blocked(let reason):
        throw SandboxError.blocked(reason)
    }
}

struct RunSandboxIntent: AppIntent {
    static let title: LocalizedStringResource = "Run Bounded Task"
    static let description = IntentDescription("Run on-device Apple Intelligence or begin a reviewed provider Shortcut with the saved Local Sandbox authorization.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]
    @Parameter(title: "Goal") var goal: String
    @Parameter(title: "Provider", default: .saved) var provider: ProviderSelection
    @Parameter(title: "Verification mode", default: "exactText") var verificationMode: String
    @Parameter(title: "Verification path", default: "workspace/test.txt") var verificationPath: String
    @Parameter(title: "Expected value", default: "Status: verified") var expectedValue: String
    static var parameterSummary: some ParameterSummary {
        Summary("Run \(\.$goal) with \(\.$provider)") {
            \.$verificationMode
            \.$verificationPath
            \.$expectedValue
        }
    }
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard let data=UserDefaults.standard.data(forKey:"policy") else {throw SandboxError.blocked("Save authorization in Local Sandbox first.")}
        let policy=try JSONDecoder().decode(ResourcePolicy.self,from:data).validated()
        let contract=try filesystemGoalContract(mode:verificationMode,path:verificationPath,expected:expectedValue)
        let output=try await continuationValidator.validatedAwait {
            try await executeProviderTask(goal:goal,policy:policy,providerSelection:provider,contract:contract,executionGeneration:executionGeneration)
        }
        return .result(value:output)
    }
}

@available(iOS 27.0, *)
struct RunLongAppleTaskIntent: LongRunningIntent, CancellableIntent {
    static let title: LocalizedStringResource = "Run Long Apple Task"
    static let description = IntentDescription("Run a bounded Apple Intelligence task with extended execution, progress, cancellation, and checkpoint recovery.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]
    @Parameter(title: "Goal") var goal: String
    @Parameter(title: "Verification mode", default: "exactText") var verificationMode: String
    @Parameter(title: "Verification path", default: "workspace/test.txt") var verificationPath: String
    @Parameter(title: "Expected value", default: "Status: verified") var expectedValue: String
    static var parameterSummary: some ParameterSummary {
        Summary("Run \(\.$goal) with Apple Intelligence") {
            \.$verificationMode
            \.$verificationPath
            \.$expectedValue
        }
    }
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard let data=UserDefaults.standard.data(forKey:"policy") else {throw SandboxError.blocked("Save authorization in Local Sandbox first.")}
        let policy=try JSONDecoder().decode(ResourcePolicy.self,from:data).validated()
        let contract=try filesystemGoalContract(mode:verificationMode,path:verificationPath,expected:expectedValue)
        let totalUnits=Int64(policy.maxSteps * 2 + 1)
        progress.totalUnitCount=totalUnits
        progress.localizedDescription="Running with Apple Intelligence"
        progress.localizedAdditionalDescription="Checking the saved authorization"
        let cancellationState=LongIntentCancellationState()
        let output=try await continuationValidator.validatedAwait {
            try await performBackgroundTask { @Sendable in
                try Task.checkCancellation()
                let value=try await executeProviderTask(
                    goal:goal,
                    policy:policy,
                    providerSelection:.apple,
                    contract:contract,
                    executionGeneration:executionGeneration,
                    systemManaged:true,
                    cancellationDisposition:{cancellationState.current()}
                ) { message in
                    progress.completedUnitCount=min(totalUnits - 1,progress.completedUnitCount + 1)
                    progress.localizedAdditionalDescription=message
                } onHeartbeat: { message in
                    progress.localizedAdditionalDescription=message
                }
                try Task.checkCancellation()
                progress.completedUnitCount=totalUnits
                progress.localizedAdditionalDescription="Run finished"
                return value
            } onCancel: { reason in
                cancellationState.record(reason)
            }
        }
        return .result(value:output)
    }
}

struct PlanOneStepIntent: AppIntent {
    static let title: LocalizedStringResource = "Plan One Step"
    static let description = IntentDescription("Ask Apple Intelligence for one tool proposal. This action does not execute it.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]
    @Parameter(title: "Goal") var goal:String
    @Parameter(title: "State",default: "No actions executed.") var state:String
    @Parameter(title: "Last result",default: "None") var latest:String
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        let policy:ResourcePolicy
        if let data=UserDefaults.standard.data(forKey:"policy"){policy=try JSONDecoder().decode(ResourcePolicy.self,from:data).validated()}else{throw SandboxError.blocked("Save authorization in the app first.")}
        let snapshot=DeviceSnapshot.read()
        if let reason=snapshot.stopReason(policy:policy,initialBattery:snapshot.battery){throw SandboxError.blocked(reason)}
        let text=try await continuationValidator.validatedAwait {
            try await AppleProvider().step(goal:goal,capsule:state,latest:latest,policy:policy)
        }
        _=try AgentAction.parse(text)
        try continuationValidator.requireCurrent()
        return .result(value:text)
    }
}
struct OpenSandboxIntent: AppIntent {
    static let title:LocalizedStringResource="Open Local Sandbox"
    static let authenticationPolicy:IntentAuthenticationPolicy = .alwaysAllowed
    static let supportedModes:IntentModes=[.foreground(.immediate)]
    func perform() async throws -> some IntentResult { .result() }
}

private struct ProviderQualificationIntentOutput: Encodable {
    let recordType = "provider-qualification-challenge"
    let schemaVersion = 1
    let provider: AppProvider
    let probe: ProviderQualificationProbe
    let attemptID: String
    let adapterName: String
    let payload: String
}

struct BeginProviderQualificationIntent: AppIntent {
    static let title: LocalizedStringResource = "Begin Provider Check"
    static let description = IntentDescription("Start one measured, device-local provider check. The returned payload goes only to the exact configured provider Shortcut.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]
    @Parameter(title: "Provider", default: .local) var provider: ProviderSelection

    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard SandboxStore.shared.connected else { throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST") }
        guard let exact = provider.explicitProvider, exact != .apple else {
            throw SandboxError.blocked("Choose Locally, ChatGPT, Grok, Grokbot, or Claude. Run Apple checks from Local Sandbox.")
        }
        try continuationValidator.beforePersistence()
        let challenge = try ProviderQualificationStore.externalChallenge(provider: exact, appIntentTransportObserved: true)
        let output = ProviderQualificationIntentOutput(
            provider: exact,
            probe: challenge.probe,
            attemptID: challenge.attemptID,
            adapterName: challenge.adapterName ?? "",
            payload: challenge.prompt
        )
        try continuationValidator.requireCurrent()
        return .result(value: String(decoding: try JSONEncoder.sorted.encode(output), as: UTF8.self))
    }
}

struct RecordProviderQualificationIntent: AppIntent {
    static let title: LocalizedStringResource = "Record Provider Check"
    static let description = IntentDescription("Validate raw response text against the pending device-local check and record that it reached this App Intent. Provider output is not retained. This does not prove unattended execution, provider identity, account state, or model provenance.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]
    @Parameter(title: "Provider", default: .local) var provider: ProviderSelection
    @Parameter(title: "Attempt ID") var attemptID: String
    @Parameter(title: "Raw provider response") var response: String

    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard let exact = provider.explicitProvider, exact != .apple else {
            throw SandboxError.blocked("Choose the exact external provider used for this check.")
        }
        try continuationValidator.beforePersistence()
        let result = try ProviderQualificationStore.complete(attemptID: attemptID, provider: exact, response: response, appIntentTransportObserved: true)
        let snapshot = try ProviderQualificationStore.snapshots()[exact]
        let verified = snapshot?.verifiedCount ?? 0
        let measured = snapshot?.sampleCount ?? 0
        try continuationValidator.requireCurrent()
        return .result(value: "\(exact.title) \(result.probe.rawValue): \(result.outcome.rawValue). \(verified)/\(measured) exact assertions passed; five distinct probe types are required.")
    }
}

struct QualifyAppleProviderIntent: AppIntent {
    static let title: LocalizedStringResource = "Qualify Apple Intelligence"
    static let description = IntentDescription("Run all five Apple Intelligence checks through this App Intent so transport evidence comes from an actual App Intent execution.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]

    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard SandboxStore.shared.connected else {
            throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST")
        }
        guard let data = UserDefaults.standard.data(forKey: "policy") else {
            throw SandboxError.blocked("Save authorization in Local Sandbox first.")
        }
        let policy = try JSONDecoder().decode(ResourcePolicy.self, from: data).validated()
        let snapshot = try await continuationValidator.validatedAwait {
            try await ProviderQualificationStore.runAppleSuiteFromAppIntent(
                policy: policy,
                executionGeneration: executionGeneration
            )
        }
        try continuationValidator.requireCurrent()
        return .result(value: "Apple Intelligence: \(snapshot.verifiedCount)/\(snapshot.sampleCount) verified checks across \(snapshot.distinctProbeCount)/5 probe types. Return to Apps & Shortcuts to review routing status.")
    }
}

struct ConfigureOracleRoutingIntent: AppIntent {
    static let title: LocalizedStringResource = "Apply Oracle Recommendation"
    static let description = IntentDescription("Pin the best currently qualified provider using saved privacy, context, tool-return, reliability, quality, and comparable-timing rules.")
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes: IntentModes = [.foreground(.immediate)]

    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard SandboxStore.shared.connected else { throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST") }
        guard let data = UserDefaults.standard.data(forKey: "policy") else {
            throw SandboxError.blocked("Save authorization in Local Sandbox first.")
        }
        var policy = try JSONDecoder().decode(ResourcePolicy.self, from: data).validated()
        let recommendation = try ProviderRuntimeCapabilities.oracleRecommendation(policy: policy)
        policy.provider = recommendation.rawValue
        policy = try policy.validated()
        try continuationValidator.beforePersistence()
        try ProviderQualificationStore.recordRecommendation(provider: recommendation, policy: policy)
        try continuationValidator.beforePersistence()
        try SandboxStore.shared.save(policy, path: "config/policy.json")
        try continuationValidator.beforePersistence()
        UserDefaults.standard.set(try JSONEncoder().encode(policy), forKey: "policy")
        try continuationValidator.beforeDispatcherSideEffect()
        LocalSandboxShortcuts.updateAppShortcutParameters()
        try continuationValidator.requireCurrent()
        return .result(value: "Saved provider is now \(recommendation.title). The next run resolves again only before its first action; it never switches provider mid-run.")
    }
}

struct LocalSandboxShortcuts: AppShortcutsProvider {
    static var appShortcuts:[AppShortcut] {
        AppShortcut(intent:BeginOracleTaskIntent(),phrases:["Begin an Oracle task with \(\.$provider) in \(.applicationName)"],shortTitle:"Begin Oracle task",systemImageName:"paperplane")
        AppShortcut(intent:ApplyValidatedActionIntent(),phrases:["Return a response to \(.applicationName)"],shortTitle:"Apply validated action",systemImageName:"checkmark.shield")
        AppShortcut(intent:PrepareWorkspaceIntent(),phrases:["Prepare my workspace in \(.applicationName)"],shortTitle:"Prepare workspace",systemImageName:"folder.badge.gearshape")
        AppShortcut(intent:RunSandboxIntent(),phrases:["Run a task with \(\.$provider) in \(.applicationName)"],shortTitle:"Run bounded task",systemImageName:"square.stack.3d.up")
        AppShortcut(intent:BeginProviderQualificationIntent(),phrases:["Begin a provider check in \(.applicationName)"],shortTitle:"Begin provider check",systemImageName:"gauge.with.dots.needle.67percent")
        AppShortcut(intent:RecordProviderQualificationIntent(),phrases:["Record a provider check in \(.applicationName)"],shortTitle:"Record provider check",systemImageName:"checkmark.seal")
        AppShortcut(intent:QualifyAppleProviderIntent(),phrases:["Qualify Apple Intelligence in \(.applicationName)"],shortTitle:"Qualify Apple Intelligence",systemImageName:"apple.intelligence")
        AppShortcut(intent:ConfigureOracleRoutingIntent(),phrases:["Apply the Oracle recommendation in \(.applicationName)"],shortTitle:"Apply Oracle route",systemImageName:"point.3.connected.trianglepath.dotted")
        AppShortcut(intent:OpenSandboxIntent(),phrases:["Open \(.applicationName)"],shortTitle:"Open sandbox",systemImageName:"folder")
        if #available(iOS 27.0, *) {
            AppShortcut(intent:RunLongAppleTaskIntent(),phrases:["Run a long Apple task in \(.applicationName)"],shortTitle:"Run long Apple task",systemImageName:"sparkles")
        }
    }
}

struct BeginOracleTaskIntent: AppIntent {
    static let title:LocalizedStringResource="Begin Oracle Task"
    static let description=IntentDescription("Select the saved provider, the best available local route, or a specific configured provider. Apple runs on device; other providers compose through Shortcuts.")
    static let authenticationPolicy:IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes:IntentModes=[.foreground(.immediate)]
    @Parameter(title:"Goal") var goal:String
    @Parameter(title:"Provider",default:.saved) var provider:ProviderSelection
    @Parameter(title:"Verification mode",default:"exactText") var verificationMode:String
    @Parameter(title:"Verification path",default:"workspace/test.txt") var verificationPath:String
    @Parameter(title:"Expected value",default:"Status: verified") var expectedValue:String
    static var parameterSummary: some ParameterSummary {
        Summary("Begin \(\.$goal) with \(\.$provider)") {
            \.$verificationMode
            \.$verificationPath
            \.$expectedValue
        }
    }
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard let data=UserDefaults.standard.data(forKey:"policy") else{throw SandboxError.blocked("Save authorization in Local Sandbox first.")}
        let policy=try JSONDecoder().decode(ResourcePolicy.self,from:data).validated()
        let contract=try filesystemGoalContract(mode:verificationMode,path:verificationPath,expected:expectedValue)
        let output=try await continuationValidator.validatedAwait {
            try await executeProviderTask(goal:goal,policy:policy,providerSelection:provider,contract:contract,executionGeneration:executionGeneration)
        }
        return .result(value:output)
    }
}
struct ApplyValidatedActionIntent: AppIntent {
    static let title:LocalizedStringResource="Apply Validated Action"
    static let description=IntentDescription("Validate and execute one returned action inside the active task's saved authorization. Reaching this App Intent does not prove the response's provider, account, model, or unattended origin. The action is not displayed for a separate content review. Returns a JSON envelope with phase and payload. This action can edit files.")
    static let authenticationPolicy:IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes:IntentModes=[.foreground(.immediate)]
    @Parameter(title:"Response") var response:String
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        let output=try await continuationValidator.validatedAwait {
            try await ShortcutCoordinator.shared.accept(response,executionGeneration:executionGeneration)
        }
        let envelope=try ShortcutCoordinator.shared.appIntentOutput(payload:output,executionGeneration:executionGeneration)
        try continuationValidator.requireCurrent()
        return .result(value:envelope)
    }
}
struct PrepareWorkspaceIntent: AppIntent {
    static let title:LocalizedStringResource="Prepare Workspace"
    static let authenticationPolicy:IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    static let supportedModes:IntentModes=[.foreground(.immediate)]
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let executionGeneration=try await authenticateSensitiveIntent()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try SandboxStore.shared.restore()
        guard SandboxStore.shared.connected else{throw SandboxError.blocked("Choose your iCloud folder in Local Sandbox Settings first.")}
        try continuationValidator.beforePersistence()
        _ = try WorkspacePreparationService.live.prepare(defaultPolicy:ResourcePolicy())
        try continuationValidator.requireCurrent()
        return .result(value:"Local Sandbox folders and policy are ready. Existing files were preserved.")
    }
}
