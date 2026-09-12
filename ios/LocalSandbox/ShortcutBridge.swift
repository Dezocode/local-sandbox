import Foundation
import UIKit
import FoundationModels
import UserNotifications

@MainActor
enum ProviderRuntimeCapabilities {
    static var appleModel: AppleModelAvailability {
        switch SystemLanguageModel.default.availability {
        case .available:
            return .available
        case .unavailable(let reason):
            return .unavailable(String(describing: reason))
        @unknown default:
            return .unavailable("Availability could not be determined")
        }
    }

    static var shortcutsAvailable: Bool {
        guard let url = URL(string: "shortcuts://") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }

    static var activity: ProviderActivitySignal {
        if ProviderQualificationStore.qualificationActive { return .providerQualificationActive }
        if AgentRunner.shared.running { return .nativeRunActive }
        if let session = ShortcutCoordinator.shared.current() {
            if session.phase == "applying" { return .applyingProviderResponse }
            if session.phase == "awaiting_response" { return .providerResponsePending }
        }
        return .workspaceIdle
    }

    static func resolve(selection: ProviderSelection, policy: ResourcePolicy, unattended: Bool = false) throws -> ResolvedProviderRoute {
        guard let savedProvider = AppProvider(rawValue: policy.provider) else {
            throw SandboxError.invalid("INVALID_POLICY_PROVIDER")
        }
        guard UIApplication.shared.isProtectedDataAvailable else {
            throw SandboxError.blocked("PROTECTED_WORKSPACE_LOCKED")
        }
        let currentActivity = activity
        guard currentActivity == .workspaceIdle else {
            throw SandboxError.blocked("ANOTHER_TASK_IS_ACTIVE")
        }
        let qualifications: [AppProvider: ProviderQualificationSnapshot]
        do {
            qualifications = try ProviderQualificationStore.snapshots()
        } catch {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_LEDGER_UNREADABLE: Review or reset this device's protected provider checks before routing a task. \(error.localizedDescription)")
        }
        let requirements = OracleTaskRequirements.filesystem(
            policyContextCharacters: min(policy.contextChars, ProviderQualificationSnapshot.maximumSupportedContextCharacters),
            localOnly: selection == .bestLocal,
            unattended: unattended
        )
        let route=ProviderRoutingPolicy.resolve(
            selection: selection,
            savedProvider: savedProvider,
            appleAvailability: appleModel,
            shortcutsAvailable: shortcutsAvailable,
            adapterFor: AdapterSettings.get,
            cloudAllowed: policy.cloudAllowed,
            qualifications: qualifications,
            requirements: requirements,
            activity: currentActivity,
            deviceProfileSHA256: ProviderQualificationStore.deviceProfileSHA256(),
            configurationSHA256: ProviderQualificationStore.configurationSHA256(policy: policy),
            savedStrategy: selection == .saved && ProviderQualificationStore.hasCurrentRecommendation(provider: savedProvider, policy: policy) ? .oracleRecommendation : .savedPinned
        )
        if route.provider == .apple,
           route.decision.isRunnable,
           policy.contextChars > ProviderQualificationSnapshot.appleMaximumContextCharacters {
            return ResolvedProviderRoute(
                selection: route.selection,
                provider: route.provider,
                decision: .blocked("APPLE_CONTEXT_CAP_EXCEEDED: Lower the saved prompt cap to 6000 or select a qualified external provider."),
                evidence: nil
            )
        }
        return route
    }

    static func oracleRecommendation(policy: ResourcePolicy) throws -> AppProvider {
        guard UIApplication.shared.isProtectedDataAvailable else { throw SandboxError.blocked("PROTECTED_WORKSPACE_LOCKED") }
        guard activity == .workspaceIdle else { throw SandboxError.blocked("ANOTHER_TASK_IS_ACTIVE") }
        let requirements = OracleTaskRequirements.filesystem(
            policyContextCharacters: min(policy.contextChars, ProviderQualificationSnapshot.maximumSupportedContextCharacters),
            localOnly: !policy.cloudAllowed,
            unattended: true
        )
        guard let provider = ProviderRoutingPolicy.recommend(
            providers: AppProvider.allCases,
            appleAvailability: appleModel,
            shortcutsAvailable: shortcutsAvailable,
            adapterFor: AdapterSettings.get,
            cloudAllowed: policy.cloudAllowed,
            qualifications: try ProviderQualificationStore.snapshots(),
            requirements: requirements
        ) else {
            throw SandboxError.blocked("ORACLE_RECOMMENDATION_NEEDS_FRESH_CHECKS: Qualify at least one eligible provider with all five probe types, at least 80 percent locally schema-valid responses, at least 80 percent exact assertion passes, sufficient tested context and tool probes, zero integrity faults, and an observed App Intent return path for Siri. Confirm unattended provider and model operation on the physical device.")
        }
        return provider
    }

    static func validateActiveExternalRoute(_ session: ShortcutSession) throws {
        let expectedActivity: ProviderActivitySignal = session.phase == "applying" ? .applyingProviderResponse : .providerResponsePending
        guard activity == expectedActivity else {
            throw SandboxError.blocked("PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK")
        }
        guard let provider = AppProvider(rawValue: session.policy.provider), provider != .apple,
              session.routingEvidence.provider == provider,
              session.routingEvidence.selection == session.providerSelection else {
            throw SandboxError.blocked("PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK")
        }
        guard UIApplication.shared.isProtectedDataAvailable else {
            throw SandboxError.blocked("PROTECTED_WORKSPACE_LOCKED")
        }
        let savedPolicy = try session.authorizationPolicy.validated()
        let requirements = OracleTaskRequirements.filesystem(
            policyContextCharacters: min(session.policy.contextChars, ProviderQualificationSnapshot.maximumSupportedContextCharacters),
            localOnly: session.providerSelection == .bestLocal,
            unattended: session.taskOrigin == .appIntent
        )
        let qualifications: [AppProvider: ProviderQualificationSnapshot]
        do {
            qualifications = try ProviderQualificationStore.snapshots()
        } catch {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_LEDGER_UNREADABLE_RESTART_TASK")
        }
        let adapter = AdapterSettings.get(provider)
        guard let authorizedProvider = AppProvider(rawValue: savedPolicy.provider),
              adapter.name == session.shortcutAdapterName else {
            throw SandboxError.blocked("PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK")
        }
        let savedStrategy: ProviderRoutingStrategy = session.providerSelection == .saved &&
            ProviderQualificationStore.hasCurrentRecommendation(provider: authorizedProvider, policy: savedPolicy)
            ? .oracleRecommendation : .savedPinned
        let resolved = ProviderRoutingPolicy.resolve(
            selection: session.providerSelection,
            savedProvider: authorizedProvider,
            appleAvailability: appleModel,
            shortcutsAvailable: shortcutsAvailable,
            adapterFor: AdapterSettings.get,
            cloudAllowed: savedPolicy.cloudAllowed,
            qualifications: qualifications,
            requirements: requirements,
            activity: .workspaceIdle,
            deviceProfileSHA256: ProviderQualificationStore.deviceProfileSHA256(),
            configurationSHA256: ProviderQualificationStore.configurationSHA256(policy: savedPolicy),
            savedStrategy: savedStrategy
        )
        guard resolved.provider == provider,
              resolved.decision == .shortcut(name: session.shortcutAdapterName),
              resolved.evidence == session.routingEvidence else {
            throw SandboxError.blocked("PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK")
        }
    }
}

extension AppProvider {
    @MainActor var unavailableReason: String? {
        if self == .apple {
            switch ProviderRuntimeCapabilities.appleModel {
            case .available: return nil
            case .unavailable(let reason): return "Apple Intelligence is not available on this device: \(reason). Choose another provider only after Local Sandbox shows its Shortcut route is configured and currently qualified."
            }
        }
        guard ProviderRuntimeCapabilities.shortcutsAvailable else { return "Install Apple Shortcuts to use this provider." }
        return nil
    }
}
@MainActor enum AdapterSettings {
    static func deviceReport() -> String {
        let reason=AppProvider.apple.unavailableReason
        let report:[String:Any]=["version":1,"name":UIDevice.current.model,"os":"iOS \(UIDevice.current.systemVersion)","appleAvailable":reason==nil,"appleReason":reason ?? "Available","reportedAt":ISO8601DateFormatter().string(from:Date())]
        return (try? String(decoding:JSONSerialization.data(withJSONObject:report,options:[.sortedKeys]),as:UTF8.self)) ?? "{}"
    }
    static func get(_ provider: AppProvider) -> ShortcutAdapter {
        if let data=UserDefaults.standard.data(forKey:"adapter.\(provider.rawValue)"),let value=try? JSONDecoder().decode(ShortcutAdapter.self,from:data){return value}
        if SandboxStore.shared.connected,let values=try? SandboxStore.shared.load([String:ShortcutAdapter].self,path:"config/app-adapters.json"),var value=values[provider.rawValue]{value.tested=false;return value}
        return ShortcutAdapter(name:provider.shortcut)
    }
    static func save(_ value:ShortcutAdapter,for provider:AppProvider) throws {
        guard !value.name.isEmpty,value.name.count<=80,["action","manual"].contains(value.mode) else {throw SandboxError.invalid("Invalid Shortcut configuration.")}
        if !value.installURL.isEmpty {guard let url=URL(string:value.installURL),url.scheme=="https",url.host=="www.icloud.com",url.path.range(of:"^/shortcuts/[a-fA-F0-9]{32}$",options:.regularExpression) != nil else {throw SandboxError.invalid("Use a shared iCloud Shortcut link.")}}
        let previous=get(provider)
        var stored=value
        if ProviderQualificationStore.adapterSHA256(previous) != ProviderQualificationStore.adapterSHA256(value) || !previous.tested {
            stored.tested=false
        }
        try persist(stored,for:provider)
    }
    static func markMeasuredRoundTrip(for provider:AppProvider) throws {
        guard provider != .apple else{return}
        var value=get(provider);value.tested=true
        try persist(value,for:provider)
    }
    static func invalidateMeasuredRoundTrip(for provider:AppProvider) throws {
        guard provider != .apple else{return}
        var value=get(provider);value.tested=false
        try persist(value,for:provider)
    }
    private static func persist(_ value:ShortcutAdapter,for provider:AppProvider) throws {
        if SandboxStore.shared.connected {
            let store=SandboxStore.shared;let path=try SandboxPath("config/app-adapters.json")
            let exists=try store.list("config").contains(path.value)
            let before=exists ? try store.read(path):nil
            var values=try before.map{try JSONDecoder().decode([String:ShortcutAdapter].self,from:Data($0.utf8))} ?? [:]
            values[provider.rawValue]=value
            try store.write(path,content:String(decoding:JSONEncoder.sorted.encode(values),as:UTF8.self),createOnly:!exists,expectedSHA256:before.map{SandboxStore.hash($0)})
        }
        UserDefaults.standard.set(try JSONEncoder().encode(value),forKey:"adapter.\(provider.rawValue)")
        LocalSandboxShortcuts.updateAppShortcutParameters()
    }
    static func runURL(name:String,input:String)->URL? {
        var url=URLComponents();url.scheme="shortcuts";url.host="run-shortcut";url.queryItems=[URLQueryItem(name:"name",value:name),URLQueryItem(name:"input",value:"text"),URLQueryItem(name:"text",value:input)];return url.url
    }
}
@MainActor final class ShortcutCoordinator {
    static let shared=ShortcutCoordinator()
    private let store=SandboxStore.shared
    private var applying=false
    func current()->ShortcutSession? {try? store.load(ShortcutSession.self,path:"state/shortcut-session.json")}
    func begin(
        goal:String,
        policy:ResourcePolicy,
        contract:GoalContract?=nil,
        providerSelection:ProviderSelection = .saved,
        origin:ProviderTaskOrigin = .app,
        resolvedRoute:ResolvedProviderRoute? = nil,
        executionGeneration providedExecutionGeneration:ExecutionContinuationGate.Generation? = nil
    ) throws -> String {
        let executionGeneration=providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try continuationValidator.requireCurrent()
        guard !AgentRunner.shared.running,!applying else {throw SandboxError.blocked("Another task is active.")}
        let savedPolicy=try policy.validated()
        try SavedExecutionAuthorization.requireExact(savedPolicy)
        guard !goal.isEmpty,goal.count<=2000 else {throw SandboxError.invalid("Enter a task up to 2,000 characters.")}
        guard store.connected else{throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST")}
        try ExecutionAdmission.ensureCanStart()
        let route:ResolvedProviderRoute
        if let resolvedRoute{route=resolvedRoute}else{route=try ProviderRuntimeCapabilities.resolve(selection:providerSelection,policy:savedPolicy)}
        guard route.selection == providerSelection else {throw SandboxError.invalid("RESOLVED_PROVIDER_SELECTION_MISMATCH")}
        let adapterName:String
        switch route.decision {
        case .onDeviceApple:
            throw SandboxError.blocked("This selection uses the on-device Apple model. Run the Bounded Task App Shortcut to complete it directly.")
        case .shortcut(let name):
            adapterName=name
        case .blocked(let reason):
            throw SandboxError.blocked(reason)
        }
        guard let routingEvidence=route.evidence else {throw SandboxError.blocked("ROUTING_EVIDENCE_NOT_COMMITTABLE")}
        var resolvedPolicy=savedPolicy
        resolvedPolicy.provider=route.provider.rawValue
        resolvedPolicy=try resolvedPolicy.validated()
        let snapshot=DeviceSnapshot.read();if let reason=snapshot.stopReason(policy:resolvedPolicy,initialBattery:snapshot.battery){throw SandboxError.blocked(reason)}
        var session=ShortcutSession(id:UUID().uuidString,goal:goal,policy:resolvedPolicy,authorizationPolicy:savedPolicy,started:Date(),initialBattery:snapshot.battery,contract:contract,providerSelection:providerSelection,taskOrigin:origin,shortcutAdapterName:adapterName,routingEvidence:routingEvidence)
        let firstPrompt=prompt(session)
        session.trace.append(try ProviderHandoffTrace.outbound(provider:route.provider,selection:providerSelection,origin:origin,adapterName:adapterName,actionIndex:session.step,prompt:firstPrompt))
        try continuationValidator.beforePersistence()
        try store.save(session,path:"state/shortcut-session.json")
        try continuationValidator.requireCurrent()
        return firstPrompt
    }
    func appIntentOutput(payload:String,executionGeneration:ExecutionContinuationGate.Generation) throws -> String {
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try continuationValidator.requireCurrent()
        guard let session=current(),session.taskOrigin == .appIntent,
              let provider=AppProvider(rawValue:session.policy.provider),provider != .apple,
              !session.shortcutAdapterName.isEmpty else {
            throw SandboxError.blocked("APP_INTENT_HANDOFF_METADATA_MISSING_RESTART_TASK")
        }
        let output:AppIntentTaskOutput
        if session.phase == "awaiting_response" {
            output = .providerHandoffPrompt(provider:provider,selection:session.providerSelection,adapterName:session.shortcutAdapterName,payload:payload)
        } else if let status=RunStatus(rawValue:session.phase) {
            output = .terminalProviderReceipt(provider:provider,selection:session.providerSelection,adapterName:session.shortcutAdapterName,phase:status,payload:payload)
        } else {
            throw SandboxError.blocked("APP_INTENT_HANDOFF_PHASE_INVALID")
        }
        try continuationValidator.requireCurrent()
        return try output.json
    }
    func prompt(_ session:ShortcutSession)->String {
        let reserved=max(500,session.policy.contextChars-nativeOraclePolicy.count-180)
        let verification=session.contract.map{" Verification: "+$0.promptDescription} ?? " Verification contract: none; completion cannot be marked verified."
        let provider=AppProvider(rawValue:session.policy.provider) ?? .local
        let header=ProviderHandoffPromptHeader(provider:provider,selection:session.providerSelection,origin:session.taskOrigin).jsonLine
        return String((header+"\n"+nativeOraclePolicy+"\nRun: \(session.id). Step: \(session.step). Return only one action JSON.\n"+boundedPrompt(goal:session.goal,capsule:"\(session.step) steps, \(session.failures) failures. Latest result is authoritative."+verification,latest:session.latest,limit:reserved)).prefix(session.policy.contextChars))
    }
    func accept(_ response:String,executionGeneration providedExecutionGeneration:ExecutionContinuationGate.Generation? = nil) async throws -> String {
        let executionGeneration=providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try continuationValidator.requireCurrent()
        try AgentAction.requireBoundedResponse(response)
        guard !applying,!AgentRunner.shared.running else {throw SandboxError.blocked("Another action is active.")}
        applying=true;defer{applying=false}
        guard var session=current(),session.phase=="awaiting_response" else {throw SandboxError.blocked("No resumable app response is pending. Inspect the checkpoint if interrupted.")}
        guard !session.requiresLegacyRestart else {throw SandboxError.blocked("LEGACY_SHORTCUT_SESSION_RESTART_REQUIRED: Stop this handoff, then begin a new task so the current adapter, authorization, and qualification evidence are bound before execution.")}
        guard !session.shortcutAdapterName.isEmpty else {throw SandboxError.blocked("SHORTCUT_ADAPTER_METADATA_MISSING_RESTART_TASK")}
        guard let saved=UserDefaults.standard.data(forKey:"policy"),let current=try? JSONDecoder().decode(ResourcePolicy.self,from:saved) else {return try await finish(&session,status:.blocked,summary:"Authorization is missing. Save it again before starting a new task.",continuationValidator:continuationValidator)}
        if !session.authorizationMatches(current) {return try await finish(&session,status:.blocked,summary:"Authorization changed. Begin a new task with the saved policy.",continuationValidator:continuationValidator)}
        do {
            try ProviderRuntimeCapabilities.validateActiveExternalRoute(session)
        } catch {
            try continuationValidator.requireCurrent()
            return try await finish(&session,status:.blocked,summary:"Provider qualification or route evidence changed. Review the device checks and begin a new task.",continuationValidator:continuationValidator)
        }
        if let reason=DeviceSnapshot.read().stopReason(policy:session.policy,initialBattery:session.initialBattery){return try await finish(&session,status:.blocked,summary:reason,continuationValidator:continuationValidator)}
        guard session.step<session.policy.maxSteps else {return try await finish(&session,status:.blocked,summary:"Step budget exhausted.",continuationValidator:continuationValidator)}
        guard let actionIndex=try session.beginDistinctResponse(response) else{
            try continuationValidator.requireCurrent()
            return prompt(session)
        }
        guard let provider=AppProvider(rawValue:session.policy.provider) else {return try await finish(&session,status:.blocked,summary:"The saved provider route is invalid.",continuationValidator:continuationValidator)}
        session.trace.append(try ProviderHandoffTrace.inbound(provider:provider,selection:session.providerSelection,origin:session.taskOrigin,adapterName:session.shortcutAdapterName,actionIndex:actionIndex,response:response))
        do {
            let action=try AgentAction.parse(response)
            switch action {
            case .final(let summary):
                if !session.lastFailure.isEmpty{return try await finish(&session,status:.blocked,summary:"An unresolved failure prevents verification. "+summary,continuationValidator:continuationValidator)}
                if let contract=session.contract{let evidence=GoalVerifier.verify(contract);let verified=evidence.allSatisfy(\.passed);return try await finish(&session,status:verified ? .verified:.completed,summary:verified ? summary:"Completed, but independent goal verification failed. "+summary,continuationValidator:continuationValidator,assertions:evidence)}
                return try await finish(&session,status:.completed,summary:"Completed without an approved verification contract. "+summary,continuationValidator:continuationValidator)
            case .tool(let call):
                session.phase="applying"
                try continuationValidator.beforePersistence()
                try store.save(session,path:"state/shortcut-session.json")
                let result=try await continuationValidator.validatedAwait {
                    try await Dispatcher.shared.execute(
                        call,
                        callID:"\(session.id)-app-\(actionIndex)",
                        policy:session.policy,
                        authorizedRead:session.lastReadEvidence,
                        beforeSideEffect:{
                            try continuationValidator.beforeDispatcherSideEffect()
                            try SavedExecutionAuthorization.requireExact(session.authorizationPolicy)
                            try ProviderRuntimeCapabilities.validateActiveExternalRoute(session)
                        }
                    )
                }
                try continuationValidator.requireCurrent()
                let promptBudget=latestPromptBudget(limit:max(500,session.policy.contextChars-nativeOraclePolicy.count-180))
                session.latest=result.promptJSON(maxCharacters:promptBudget);session.latestResult=result;session.lastReadEvidence=call.tool == .read && result.isCompleteInPrompt(maxCharacters:promptBudget) ? result.evidence:nil;session.trace.append(.receiptSuccess(result))
                session.recordSuccessfulResponse()
            }
        } catch {
            try continuationValidator.requireCurrent()
            let privateMessage=error.localizedDescription
            let providerSafeCode=ReceiptPrivacy.errorCode(privateMessage)
            session.recordFailedResponse(providerSafeCode)
            if privateMessage.contains("UNCERTAIN") || session.failures>=session.policy.maxFailures || session.repeated>=2 {return try await finish(&session,status:.blocked,summary:providerSafeCode,continuationValidator:continuationValidator)}
        }
        session.phase="awaiting_response"
        if session.step>=session.policy.maxSteps{return try await finish(&session,status:.blocked,summary:"Step budget exhausted. Review the recorded results.",continuationValidator:continuationValidator)}
        let nextPrompt=prompt(session)
        session.trace.append(try ProviderHandoffTrace.outbound(provider:provider,selection:session.providerSelection,origin:session.taskOrigin,adapterName:session.shortcutAdapterName,actionIndex:session.step,prompt:nextPrompt))
        try continuationValidator.beforePersistence()
        try store.save(session,path:"state/shortcut-session.json")
        try continuationValidator.requireCurrent()
        return nextPrompt
    }
    func stop(
        executionGeneration providedExecutionGeneration:ExecutionContinuationGate.Generation? = nil
    ) async throws {
        let executionGeneration = providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()
        let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)
        try continuationValidator.requireCurrent()
        guard !applying else{throw SandboxError.blocked("Wait for the current action to finish before stopping.")}
        guard var session=current() else{return}
        if session.requiresLegacyRestart {
            let duration=max(0,min(86_400_000,Date().timeIntervalSince(session.started)*1000))
            let receipt=try RunReceipt(id:session.id,goal:session.goal,status:.cancelled,origin:"shortcut",summary:"Legacy handoff discarded without executing another action.",steps:session.step,failures:session.failures,durationMs:duration,createdAt:ISO8601DateFormatter().string(from:Date()),trace:session.trace,legacyTraceOnly:true)
            try continuationValidator.beforePersistence()
            try store.saveReceipt(receipt,path:"logs/\(session.id).json")
            try continuationValidator.beforePersistence()
            try store.delete(SandboxPath("state/shortcut-session.json"),expectedSHA256:nil)
            return
        }
        _ = try await finish(&session,status:.cancelled,summary:"Stopped by user. No pending action replayed.",continuationValidator:continuationValidator)
    }
    private func finish(_ session:inout ShortcutSession,status:RunStatus,summary:String,continuationValidator:ExecutionContinuationValidator,assertions:[AssertionEvidence]=[]) async throws -> String {
        try continuationValidator.beforePersistence()
        session.phase=status.rawValue
        try store.save(session,path:"state/shortcut-session.json")
        let environment=ReceiptEnvironment(appVersion:Bundle.main.object(forInfoDictionaryKey:"CFBundleShortVersionString") as? String ?? "unknown",build:Bundle.main.object(forInfoDictionaryKey:"CFBundleVersion") as? String ?? "unknown",os:UIDevice.current.systemVersion,device:UIDevice.current.model)
        let policyDigest=SandboxStore.hash(String(decoding:try JSONEncoder.sorted.encode(session.policy),as:UTF8.self))
        let receipt=try RunReceipt(id:session.id,goal:session.goal,status:status,origin:"shortcut",summary:summary,steps:session.step,failures:session.failures,durationMs:Date().timeIntervalSince(session.started)*1000,createdAt:ISO8601DateFormatter().string(from:Date()),trace:session.trace,contract:session.contract,assertions:assertions,provider:session.policy.provider,policyDigest:policyDigest,workspaceID:store.workspaceID,environment:environment,taskOrigin:session.taskOrigin,routingEvidence:session.routingEvidence)
        try continuationValidator.beforePersistence()
        let receiptData=try store.saveReceipt(receipt,path:"logs/\(session.id).json")
        if session.policy.notifications {
            let note=UNMutableNotificationContent();note.title="Local Sandbox · \(status.rawValue)";note.body=ReceiptPrivacy.safeSummary(status:status)
            do {
                try await continuationValidator.validatedAwait {
                    try continuationValidator.beforeDispatcherSideEffect()
                    try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier:session.id,content:note,trigger:nil))
                }
            } catch {
                // Notification delivery is best-effort, but a retired lock generation is not.
                try continuationValidator.requireCurrent()
            }
        }
        try continuationValidator.requireCurrent()
        return String(decoding:receiptData,as:UTF8.self)
    }
}
