import Foundation

enum AppProvider: String, CaseIterable, Codable, Identifiable {
    case local, chatgpt, grok, grokbot, claude, apple

    var id: String { rawValue }

    var title: String {
        switch self {
        case .local: return "Locally"
        case .chatgpt: return "ChatGPT"
        case .grok: return "Grok"
        case .grokbot: return "Grokbot"
        case .claude: return "Claude"
        case .apple: return "Apple Intelligence"
        }
    }

    var shortcut: String {
        switch self {
        case .local: return "Agent Step - Local"
        case .apple: return "Agent Step - Apple"
        default: return "Agent Step - \(title)"
        }
    }

    var usesCloud: Bool { self != .local && self != .apple }
}

enum ProviderSelection: String, CaseIterable, Codable, Identifiable, Sendable {
    case saved
    case bestLocal = "best-local"
    case apple
    case local
    case chatgpt
    case grok
    case grokbot
    case claude

    var id: String { rawValue }

    var title: String {
        switch self {
        case .saved: return "Saved provider"
        case .bestLocal: return "Best local"
        case .apple: return AppProvider.apple.title
        case .local: return AppProvider.local.title
        case .chatgpt: return AppProvider.chatgpt.title
        case .grok: return AppProvider.grok.title
        case .grokbot: return AppProvider.grokbot.title
        case .claude: return AppProvider.claude.title
        }
    }

    var explicitProvider: AppProvider? {
        switch self {
        case .saved, .bestLocal: return nil
        case .apple: return .apple
        case .local: return .local
        case .chatgpt: return .chatgpt
        case .grok: return .grok
        case .grokbot: return .grokbot
        case .claude: return .claude
        }
    }
}

enum ProviderQualificationProbe: String, CaseIterable, Codable {
    case strictJSON = "strict-json"
    case readTool = "read-tool"
    case listTool = "list-tool"
    case patchTool = "patch-tool"
    case boundedContext = "bounded-context"

    var isToolProbe: Bool {
        switch self {
        case .readTool, .listTool, .patchTool: return true
        case .strictJSON, .boundedContext: return false
        }
    }
}

enum ProviderQualificationVerifier {
    private struct ToolChallengeEnvelope {
        let challenge: String
        let action: AgentAction
    }

    static func validatesStrictSchema(response: String, probe: ProviderQualificationProbe) -> Bool {
        switch probe {
        case .readTool, .listTool:
            return parseToolChallengeEnvelope(response) != nil
        case .strictJSON, .patchTool, .boundedContext:
            return (try? AgentAction.parse(response)) != nil
        }
    }

    static func prompt(probe: ProviderQualificationProbe, token: String, contextCharacters: Int) -> String {
        switch probe {
        case .strictJSON:
            return "Local Sandbox qualification. Return exactly one JSON object and no markdown: {\"kind\":\"final\",\"summary\":\"\(token)\"}"
        case .readTool:
            return "Local Sandbox qualification. Propose one read without executing it. Return exactly {\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}}"
        case .listTool:
            return "Local Sandbox qualification. Propose one list without executing it. Return exactly {\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.list\",\"arguments\":{\"path\":\"workspace\"}}}"
        case .patchTool:
            let digest = NativeDigest.sha256("Status: pending")
            return "Local Sandbox qualification. Propose one guarded patch without executing it. Return exactly {\"kind\":\"tool\",\"tool\":\"file.patch\",\"arguments\":{\"path\":\"workspace/test.txt\",\"old\":\"Status: pending\",\"replacement\":\"Status: \(token)\",\"expectedSHA256\":\"\(digest)\"}}"
        case .boundedContext:
            let start = "Local Sandbox context qualification. Remember this device-unique code: \(token). Ignore all filler. "
            let end = " Return exactly one JSON object and no markdown. Set summary to the device-unique code stated before the filler: {\"kind\":\"final\",\"summary\":\"<device-unique-code>\"}"
            let target = min(max(contextCharacters, start.count + end.count), ProviderQualificationSnapshot.maximumSupportedContextCharacters)
            let fillerCount = max(0, target - start.count - end.count)
            let fillerUnit = "local-context-padding|"
            let body = start + String(repeating: fillerUnit, count: fillerCount / fillerUnit.count + 1)
            return String(body.prefix(target - end.count)) + end
        }
    }

    static func validate(response: String, probe: ProviderQualificationProbe, token: String) -> Bool {
        if probe == .readTool || probe == .listTool {
            guard let envelope = parseToolChallengeEnvelope(response), envelope.challenge == token,
                  case .tool(let call) = envelope.action else { return false }
            switch probe {
            case .readTool:
                return call.tool == .read && call.arguments == ["path": "workspace/test.txt"]
            case .listTool:
                return call.tool == .list && call.arguments == ["path": "workspace"]
            case .strictJSON, .patchTool, .boundedContext:
                return false
            }
        }
        guard let action = try? AgentAction.parse(response) else { return false }
        switch (probe, action) {
        case (.strictJSON, .final(let summary)), (.boundedContext, .final(let summary)):
            return hasExactFinalFields(response) && summary == token
        case (.patchTool, .tool(let call)):
            return call.tool == .patch && call.arguments == [
                "path": "workspace/test.txt",
                "old": "Status: pending",
                "replacement": "Status: \(token)",
                "expectedSHA256": NativeDigest.sha256("Status: pending")
            ]
        default:
            return false
        }
    }

    private static func parseToolChallengeEnvelope(_ response: String) -> ToolChallengeEnvelope? {
        guard let bytes = response.data(using: .utf8), bytes.count <= 16_000,
              let dictionary = try? StrictJSON.object(bytes, limits: .providerResponse),
              Set(dictionary.keys) == ["challenge", "action"],
              let challenge = dictionary["challenge"] as? String,
              challenge.range(of: "^[a-f0-9]{24}$", options: .regularExpression) != nil,
              let actionObject = dictionary["action"] as? [String: Any],
              JSONSerialization.isValidJSONObject(actionObject),
              let actionBytes = try? JSONSerialization.data(withJSONObject: actionObject, options: [.sortedKeys]),
              let actionText = String(data: actionBytes, encoding: .utf8),
              let action = try? AgentAction.parse(actionText) else { return nil }
        return ToolChallengeEnvelope(challenge: challenge, action: action)
    }

    private static func hasExactFinalFields(_ response: String) -> Bool {
        guard let bytes = response.data(using: .utf8),
              let dictionary = try? StrictJSON.object(bytes, limits: .providerResponse) else { return false }
        return Set(dictionary.keys) == ["kind", "summary"]
    }
}

struct ShortcutAdapter: Codable, Equatable {
    var name: String
    var installURL = ""
    var mode = "action"
    var tested = false
}

enum ProviderActivitySignal: String, Codable, Equatable {
    case workspaceIdle = "workspace-idle"
    case providerQualificationActive = "provider-qualification-active"
    case nativeRunActive = "native-run-active"
    case providerResponsePending = "provider-response-pending"
    case applyingProviderResponse = "applying-provider-response"
}

enum ProviderAccessEvidence: String, Codable, Equatable {
    case onDeviceRuntime = "on-device-runtime"
    case recentLocallyValidatedResponse = "recent-locally-validated-response"
    case configuredUnmeasured = "configured-unmeasured"
    case unavailable

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        if value == "recent-successful-round-trip" {
            self = .recentLocallyValidatedResponse
        } else if let decoded = Self(rawValue: value) {
            self = decoded
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unknown provider access evidence")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

enum ProviderRoutingStrategy: String, Codable, Equatable {
    case savedPinned = "saved-pinned"
    case explicitPinned = "explicit-pinned"
    case bestLocalColdStart = "best-local-cold-start"
    case bestLocalMeasured = "best-local-measured"
    case oracleRecommendation = "oracle-recommendation"
}

struct OracleTaskRequirements: Equatable {
    let minimumContextCharacters: Int
    let requiresToolCalling: Bool
    let requiresObservedAppIntentReturn: Bool
    let localOnly: Bool

    static func filesystem(policyContextCharacters: Int, localOnly: Bool, unattended: Bool) -> Self {
        Self(
            minimumContextCharacters: policyContextCharacters,
            requiresToolCalling: true,
            requiresObservedAppIntentReturn: unattended,
            localOnly: localOnly
        )
    }
}

enum ProviderRuntimeIdentity {
    static func operatingSystemDescriptor(version: OperatingSystemVersion, buildDescription: String) -> String {
        "os=\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)|build=\(buildDescription)"
    }
}

@MainActor
final class ExecutionContinuationGate {
    struct Generation: Equatable, Sendable {
        fileprivate let value: UInt64
    }

    static let shared = ExecutionContinuationGate()
    private var generation: UInt64 = 0

    func capture() -> Generation {
        Generation(value: generation)
    }

    func invalidate() {
        generation &+= 1
    }

    func requireCurrent(_ captured: Generation) throws {
        guard captured.value == generation else {
            throw SandboxError.blocked("LOCAL_SANDBOX_LOCKED")
        }
    }

    func validator(for captured: Generation) -> ExecutionContinuationValidator {
        ExecutionContinuationValidator {
            try self.requireCurrent(captured)
        }
    }
}

@MainActor
struct ExecutionContinuationValidator {
    private let validateCurrentState: @MainActor () throws -> Void

    init(validate: @escaping @MainActor () throws -> Void) {
        validateCurrentState = validate
    }

    func requireCurrent() throws {
        try validateCurrentState()
    }

    func beforePlanningContinuation() throws {
        try requireCurrent()
    }

    func afterAwait() throws {
        try requireCurrent()
    }

    func validatedAwait<Response>(
        _ response: @MainActor () async throws -> Response
    ) async throws -> Response {
        try requireCurrent()
        let value: Response
        do {
            value = try await response()
        } catch {
            // A retired generation takes precedence over an async operation's error so
            // callers cannot convert post-lock failures into state or accounting changes.
            try afterAwait()
            throw error
        }
        try afterAwait()
        return value
    }

    func beforeDispatcherSideEffect() throws {
        try requireCurrent()
    }

    func beforePersistence() throws {
        try requireCurrent()
    }
}

struct ProviderQualificationSnapshot: Codable, Equatable {
    static let requiredSamples = 5
    static let requiredDistinctProbes = 5
    static let requiredToolProbes = 3
    static let appleMaximumContextCharacters = 6_000
    static let maximumSupportedContextCharacters = 12_000

    let provider: AppProvider
    let epochSHA256: String
    let adapterSHA256: String?
    let sampleCount: Int
    let distinctProbeCount: Int
    let verifiedCount: Int
    let schemaPassCount: Int
    let assertionPassCount: Int
    let assertionCount: Int
    let toolProbePassCount: Int
    let maximumContextCharacters: Int
    let medianDurationBucketMilliseconds: Int
    let integrityFaultCount: Int
    let appIntentReturnObserved: Bool
    let lastSuccessfulAt: String?

    private enum CodingKeys: String, CodingKey {
        case provider, epochSHA256, adapterSHA256, sampleCount, distinctProbeCount, verifiedCount
        case schemaPassCount, assertionPassCount, assertionCount, toolProbePassCount
        case maximumContextCharacters, medianDurationBucketMilliseconds, integrityFaultCount
        case appIntentReturnObserved = "automatedReturn"
        case lastSuccessfulAt
    }

    var hasComparableEvidence: Bool {
        sampleCount >= Self.requiredSamples && distinctProbeCount >= Self.requiredDistinctProbes
    }

    var baseQualified: Bool {
        hasComparableEvidence &&
        integrityFaultCount == 0 &&
        schemaPassCount * 5 >= sampleCount * 4 &&
        assertionCount > 0 &&
        assertionPassCount * 5 >= assertionCount * 4
    }

    func qualifies(for requirements: OracleTaskRequirements) -> Bool {
        baseQualified &&
        (!requirements.requiresToolCalling || toolProbePassCount >= Self.requiredToolProbes) &&
        maximumContextCharacters >= requirements.minimumContextCharacters &&
        (!requirements.requiresObservedAppIntentReturn || appIntentReturnObserved) &&
        (!requirements.localOnly || !provider.usesCloud)
    }
}

struct ProviderRoutingEvidence: Codable, Equatable {
    let recordType = "provider-routing-decision"
    let schemaVersion = 2
    let selection: ProviderSelection
    let provider: AppProvider
    let authorizedProvider: AppProvider
    let strategy: ProviderRoutingStrategy
    let activity: ProviderActivitySignal
    let accessEvidence: ProviderAccessEvidence
    let deviceProfileSHA256: String
    let configurationSHA256: String
    let qualificationEpochSHA256: String?
    let sampleCount: Int
    let distinctProbeCount: Int
    let verifiedCount: Int
    let reliabilityBasisPoints: Int?
    let qualityBasisPoints: Int?
    let medianDurationBucketMilliseconds: Int?
    let testedContextCharacters: Int?
    let toolCallingQualified: Bool
    let integrityFaultCount: Int
    let appIntentReturnObserved: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case recordType, schemaVersion, selection, provider, authorizedProvider, strategy, activity, accessEvidence
        case deviceProfileSHA256, configurationSHA256, qualificationEpochSHA256, sampleCount, distinctProbeCount, verifiedCount
        case reliabilityBasisPoints, qualityBasisPoints, medianDurationBucketMilliseconds
        case testedContextCharacters, toolCallingQualified, integrityFaultCount
        case appIntentReturnObserved = "automatedReturnQualified"
    }

    init(
        selection: ProviderSelection,
        provider: AppProvider,
        authorizedProvider: AppProvider,
        strategy: ProviderRoutingStrategy,
        activity: ProviderActivitySignal,
        accessEvidence: ProviderAccessEvidence,
        deviceProfileSHA256: String,
        configurationSHA256: String,
        qualification: ProviderQualificationSnapshot?
    ) {
        self.selection = selection
        self.provider = provider
        self.authorizedProvider = authorizedProvider
        self.strategy = strategy
        self.activity = activity
        self.accessEvidence = accessEvidence
        self.deviceProfileSHA256 = deviceProfileSHA256
        self.configurationSHA256 = configurationSHA256
        qualificationEpochSHA256 = qualification?.epochSHA256
        sampleCount = qualification?.sampleCount ?? 0
        distinctProbeCount = qualification?.distinctProbeCount ?? 0
        verifiedCount = qualification?.verifiedCount ?? 0
        reliabilityBasisPoints = qualification.flatMap { value in
            value.sampleCount == 0 ? nil : value.schemaPassCount * 10_000 / value.sampleCount
        }
        qualityBasisPoints = qualification.flatMap { value in
            value.assertionCount == 0 ? nil : value.assertionPassCount * 10_000 / value.assertionCount
        }
        medianDurationBucketMilliseconds = qualification?.medianDurationBucketMilliseconds
        testedContextCharacters = qualification?.maximumContextCharacters
        toolCallingQualified = qualification.map { $0.toolProbePassCount >= ProviderQualificationSnapshot.requiredToolProbes } ?? false
        integrityFaultCount = qualification?.integrityFaultCount ?? 0
        appIntentReturnObserved = qualification?.appIntentReturnObserved ?? false
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: DynamicCodingKey.self)
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        let required = allowed.subtracting(["qualificationEpochSHA256", "reliabilityBasisPoints", "qualityBasisPoints", "medianDurationBucketMilliseconds", "testedContextCharacters"])
        guard required.isSubset(of: fields), fields.isSubset(of: allowed) else {
            throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_EVIDENCE_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(String.self, forKey: .recordType) == "provider-routing-decision",
              try container.decode(Int.self, forKey: .schemaVersion) == 2 else {
            throw SandboxError.invalid("UNSUPPORTED_PROVIDER_ROUTING_EVIDENCE")
        }
        selection = try container.decode(ProviderSelection.self, forKey: .selection)
        provider = try container.decode(AppProvider.self, forKey: .provider)
        authorizedProvider = try container.decode(AppProvider.self, forKey: .authorizedProvider)
        strategy = try container.decode(ProviderRoutingStrategy.self, forKey: .strategy)
        activity = try container.decode(ProviderActivitySignal.self, forKey: .activity)
        accessEvidence = try container.decode(ProviderAccessEvidence.self, forKey: .accessEvidence)
        deviceProfileSHA256 = try container.decode(String.self, forKey: .deviceProfileSHA256)
        configurationSHA256 = try container.decode(String.self, forKey: .configurationSHA256)
        qualificationEpochSHA256 = try Self.decodeOptionalNonNullString(container, forKey: .qualificationEpochSHA256)
        sampleCount = try container.decode(Int.self, forKey: .sampleCount)
        distinctProbeCount = try container.decode(Int.self, forKey: .distinctProbeCount)
        verifiedCount = try container.decode(Int.self, forKey: .verifiedCount)
        reliabilityBasisPoints = try Self.decodeOptionalNonNullInt(container, forKey: .reliabilityBasisPoints)
        qualityBasisPoints = try Self.decodeOptionalNonNullInt(container, forKey: .qualityBasisPoints)
        medianDurationBucketMilliseconds = try Self.decodeOptionalNonNullInt(container, forKey: .medianDurationBucketMilliseconds)
        testedContextCharacters = try Self.decodeOptionalNonNullInt(container, forKey: .testedContextCharacters)
        toolCallingQualified = try container.decode(Bool.self, forKey: .toolCallingQualified)
        integrityFaultCount = try container.decode(Int.self, forKey: .integrityFaultCount)
        appIntentReturnObserved = try container.decode(Bool.self, forKey: .appIntentReturnObserved)
        try validate()
    }

    private static func decodeOptionalNonNullString(
        _ container: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> String? {
        guard container.contains(key) else { return nil }
        guard try !container.decodeNil(forKey: key) else {
            throw SandboxError.invalid("NULL_PROVIDER_ROUTING_OPTIONAL_FIELD")
        }
        return try container.decode(String.self, forKey: key)
    }

    private static func decodeOptionalNonNullInt(
        _ container: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> Int? {
        guard container.contains(key) else { return nil }
        guard try !container.decodeNil(forKey: key) else {
            throw SandboxError.invalid("NULL_PROVIDER_ROUTING_OPTIONAL_FIELD")
        }
        return try container.decode(Int.self, forKey: key)
    }

    func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(recordType, forKey: .recordType)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(selection, forKey: .selection)
        try container.encode(provider, forKey: .provider)
        try container.encode(authorizedProvider, forKey: .authorizedProvider)
        try container.encode(strategy, forKey: .strategy)
        try container.encode(activity, forKey: .activity)
        try container.encode(accessEvidence, forKey: .accessEvidence)
        try container.encode(deviceProfileSHA256, forKey: .deviceProfileSHA256)
        try container.encode(configurationSHA256, forKey: .configurationSHA256)
        try container.encodeIfPresent(qualificationEpochSHA256, forKey: .qualificationEpochSHA256)
        try container.encode(sampleCount, forKey: .sampleCount)
        try container.encode(distinctProbeCount, forKey: .distinctProbeCount)
        try container.encode(verifiedCount, forKey: .verifiedCount)
        try container.encodeIfPresent(reliabilityBasisPoints, forKey: .reliabilityBasisPoints)
        try container.encodeIfPresent(qualityBasisPoints, forKey: .qualityBasisPoints)
        try container.encodeIfPresent(medianDurationBucketMilliseconds, forKey: .medianDurationBucketMilliseconds)
        try container.encodeIfPresent(testedContextCharacters, forKey: .testedContextCharacters)
        try container.encode(toolCallingQualified, forKey: .toolCallingQualified)
        try container.encode(integrityFaultCount, forKey: .integrityFaultCount)
        try container.encode(appIntentReturnObserved, forKey: .appIntentReturnObserved)
    }

    func validate() throws {
        let validDigest: (String) -> Bool = { $0.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil }
        guard validDigest(deviceProfileSHA256), validDigest(configurationSHA256),
              qualificationEpochSHA256 == nil || validDigest(qualificationEpochSHA256!),
              (0...20).contains(sampleCount), (0...min(sampleCount, ProviderQualificationSnapshot.requiredDistinctProbes)).contains(distinctProbeCount),
              (0...sampleCount).contains(verifiedCount), (0...sampleCount).contains(integrityFaultCount),
              reliabilityBasisPoints == nil || (0...10_000).contains(reliabilityBasisPoints!),
              qualityBasisPoints == nil || (0...10_000).contains(qualityBasisPoints!),
              medianDurationBucketMilliseconds == nil || (0...300_000).contains(medianDurationBucketMilliseconds!),
              testedContextCharacters == nil || (0...12_000).contains(testedContextCharacters!) else {
            throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_EVIDENCE")
        }
        guard activity == .workspaceIdle else {
            throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_ACTIVITY")
        }
        if sampleCount == 0 {
            guard distinctProbeCount == 0, verifiedCount == 0, integrityFaultCount == 0,
                  qualificationEpochSHA256 == nil,
                  reliabilityBasisPoints == nil,
                  qualityBasisPoints == nil,
                  medianDurationBucketMilliseconds == nil,
                  testedContextCharacters == nil,
                  !toolCallingQualified, !appIntentReturnObserved else {
                throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_METRICS")
            }
        } else {
            guard qualificationEpochSHA256 != nil,
                  reliabilityBasisPoints != nil,
                  qualityBasisPoints != nil,
                  medianDurationBucketMilliseconds != nil,
                  testedContextCharacters != nil else {
                throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_METRICS")
            }
        }
        switch accessEvidence {
        case .onDeviceRuntime:
            guard provider == .apple else { throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_ACCESS") }
        case .recentLocallyValidatedResponse:
            guard provider != .apple, verifiedCount > 0 else { throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_ACCESS") }
        case .configuredUnmeasured:
            guard provider != .apple else { throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_ACCESS") }
        case .unavailable:
            break
        }
        if sampleCount > 0 {
            guard qualityBasisPoints == verifiedCount * 10_000 / sampleCount,
                  let reliabilityBasisPoints,
                  let representedSchemaPasses = (0...sampleCount).first(where: { $0 * 10_000 / sampleCount == reliabilityBasisPoints }),
                  representedSchemaPasses >= verifiedCount,
                  verifiedCount == 0 ? testedContextCharacters == 0 : (testedContextCharacters ?? 0) > 0,
                  !toolCallingQualified || verifiedCount >= ProviderQualificationSnapshot.requiredToolProbes else {
                throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_METRICS")
            }
        }
        switch strategy {
        case .savedPinned:
            guard selection == .saved, provider == authorizedProvider else { throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_STRATEGY") }
        case .oracleRecommendation:
            guard selection == .saved, provider == authorizedProvider else { throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_STRATEGY") }
        case .explicitPinned:
            guard selection.explicitProvider == provider else { throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_SELECTION") }
        case .bestLocalColdStart:
            throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_STRATEGY")
        case .bestLocalMeasured:
            guard selection == .bestLocal, provider == .apple || provider == .local else {
                throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_SELECTION")
            }
        }
        guard sampleCount >= ProviderQualificationSnapshot.requiredSamples,
              distinctProbeCount >= ProviderQualificationSnapshot.requiredDistinctProbes,
              verifiedCount * 5 >= sampleCount * 4,
              (reliabilityBasisPoints ?? -1) >= 8_000,
              (qualityBasisPoints ?? -1) >= 8_000,
              (testedContextCharacters ?? 0) >= 2_000,
              integrityFaultCount == 0,
              toolCallingQualified,
              provider == .apple || accessEvidence == .recentLocallyValidatedResponse else {
            throw SandboxError.invalid("INVALID_PROVIDER_ROUTING_QUALIFICATION")
        }
    }

    private struct DynamicCodingKey: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
}

enum AppleModelAvailability: Equatable {
    case available
    case unavailable(String)
}

enum ProviderRoutingDecision: Equatable {
    case onDeviceApple
    case shortcut(name: String)
    case blocked(String)
}

struct ResolvedProviderRoute: Equatable {
    let selection: ProviderSelection
    let provider: AppProvider
    let decision: ProviderRoutingDecision
    let evidence: ProviderRoutingEvidence?
}

enum AppIntentTaskOutputKind: String, Codable {
    case terminalAppleReceipt = "terminal-apple-receipt"
    case providerHandoffPrompt = "provider-handoff-prompt"
    case terminalProviderReceipt = "terminal-provider-receipt"
}

enum AppIntentTaskDecision: String, Codable {
    case onDeviceApple = "on-device-apple"
    case appShortcut = "app-shortcut"
}

enum AppIntentTaskOutput: Codable, Equatable {
    case terminalAppleReceipt(selection: ProviderSelection, phase: RunStatus, payload: String)
    case providerHandoffPrompt(provider: AppProvider, selection: ProviderSelection, adapterName: String, payload: String)
    case terminalProviderReceipt(provider: AppProvider, selection: ProviderSelection, adapterName: String, phase: RunStatus, payload: String)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case recordType, schemaVersion, decision, kind, phase, provider, selection, origin, adapterName, payload
    }

    private struct DynamicCodingKey: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    var kind: AppIntentTaskOutputKind {
        switch self {
        case .terminalAppleReceipt: return .terminalAppleReceipt
        case .providerHandoffPrompt: return .providerHandoffPrompt
        case .terminalProviderReceipt: return .terminalProviderReceipt
        }
    }

    var decision: AppIntentTaskDecision {
        switch self {
        case .terminalAppleReceipt: return .onDeviceApple
        case .providerHandoffPrompt, .terminalProviderReceipt: return .appShortcut
        }
    }

    var provider: AppProvider {
        switch self {
        case .terminalAppleReceipt: return .apple
        case .providerHandoffPrompt(let provider, _, _, _), .terminalProviderReceipt(let provider, _, _, _, _): return provider
        }
    }

    var selection: ProviderSelection {
        switch self {
        case .terminalAppleReceipt(let selection, _, _), .providerHandoffPrompt(_, let selection, _, _), .terminalProviderReceipt(_, let selection, _, _, _): return selection
        }
    }

    var phase: String {
        switch self {
        case .terminalAppleReceipt(_, let phase, _), .terminalProviderReceipt(_, _, _, let phase, _): return phase.rawValue
        case .providerHandoffPrompt: return "awaiting_response"
        }
    }

    var adapterName: String? {
        switch self {
        case .terminalAppleReceipt: return nil
        case .providerHandoffPrompt(_, _, let adapterName, _), .terminalProviderReceipt(_, _, let adapterName, _, _): return adapterName
        }
    }

    var payload: String {
        switch self {
        case .terminalAppleReceipt(_, _, let payload), .providerHandoffPrompt(_, _, _, let payload), .terminalProviderReceipt(_, _, _, _, let payload): return payload
        }
    }

    var json: String {
        get throws {
            try validate()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            return String(decoding: try encoder.encode(self), as: UTF8.self)
        }
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: DynamicCodingKey.self)
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let baseFields = Set(["recordType", "schemaVersion", "decision", "kind", "phase", "provider", "selection", "origin", "payload"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(String.self, forKey: .recordType) == "app-intent-task-output",
              try container.decode(Int.self, forKey: .schemaVersion) == 1,
              try container.decode(ProviderTaskOrigin.self, forKey: .origin) == .appIntent else {
            throw SandboxError.invalid("UNSUPPORTED_APP_INTENT_OUTPUT")
        }
        let decision = try container.decode(AppIntentTaskDecision.self, forKey: .decision)
        let kind = try container.decode(AppIntentTaskOutputKind.self, forKey: .kind)
        let provider = try container.decode(AppProvider.self, forKey: .provider)
        let selection = try container.decode(ProviderSelection.self, forKey: .selection)
        let phase = try container.decode(String.self, forKey: .phase)
        let payload = try container.decode(String.self, forKey: .payload)
        switch kind {
        case .terminalAppleReceipt:
            guard fields == baseFields, decision == .onDeviceApple, provider == .apple, let status = RunStatus(rawValue: phase) else {
                throw SandboxError.invalid("INVALID_TERMINAL_APPLE_OUTPUT")
            }
            self = .terminalAppleReceipt(selection: selection, phase: status, payload: payload)
        case .providerHandoffPrompt:
            guard fields == baseFields.union(["adapterName"]), decision == .appShortcut, phase == "awaiting_response" else {
                throw SandboxError.invalid("INVALID_PROVIDER_HANDOFF_OUTPUT")
            }
            self = .providerHandoffPrompt(provider: provider, selection: selection, adapterName: try container.decode(String.self, forKey: .adapterName), payload: payload)
        case .terminalProviderReceipt:
            guard fields == baseFields.union(["adapterName"]), decision == .appShortcut, let status = RunStatus(rawValue: phase) else {
                throw SandboxError.invalid("INVALID_TERMINAL_PROVIDER_OUTPUT")
            }
            self = .terminalProviderReceipt(provider: provider, selection: selection, adapterName: try container.decode(String.self, forKey: .adapterName), phase: status, payload: payload)
        }
        try validate()
    }

    func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("app-intent-task-output", forKey: .recordType)
        try container.encode(1, forKey: .schemaVersion)
        try container.encode(decision, forKey: .decision)
        try container.encode(kind, forKey: .kind)
        try container.encode(phase, forKey: .phase)
        try container.encode(provider, forKey: .provider)
        try container.encode(selection, forKey: .selection)
        try container.encode(ProviderTaskOrigin.appIntent, forKey: .origin)
        try container.encodeIfPresent(adapterName, forKey: .adapterName)
        try container.encode(payload, forKey: .payload)
    }

    private func validate() throws {
        guard !payload.isEmpty, payload.utf8.count <= 128_000, routeMatchesSelection else {
            throw SandboxError.invalid("INVALID_APP_INTENT_OUTPUT")
        }
        switch self {
        case .terminalAppleReceipt:
            guard provider == .apple else { throw SandboxError.invalid("INVALID_TERMINAL_APPLE_OUTPUT") }
        case .providerHandoffPrompt(let provider, _, let adapterName, _), .terminalProviderReceipt(let provider, _, let adapterName, _, _):
            guard provider != .apple,
                  !adapterName.isEmpty,
                  adapterName.count <= 80,
                  !adapterName.contains("\n") && !adapterName.contains("\r") else {
                throw SandboxError.invalid("INVALID_PROVIDER_ADAPTER_OUTPUT")
            }
        }
    }

    private var routeMatchesSelection: Bool {
        switch selection {
        case .saved: return true
        case .bestLocal: return provider == .apple || provider == .local
        case .apple, .local, .chatgpt, .grok, .grokbot, .claude: return selection.explicitProvider == provider
        }
    }
}

enum ProviderRoutingPolicy {
    static func resolve(
        selection: ProviderSelection,
        savedProvider: AppProvider,
        appleAvailability: AppleModelAvailability,
        shortcutsAvailable: Bool,
        adapterFor: (AppProvider) -> ShortcutAdapter,
        cloudAllowed: Bool,
        qualifications: [AppProvider: ProviderQualificationSnapshot] = [:],
        requirements: OracleTaskRequirements = .filesystem(policyContextCharacters: 6_000, localOnly: false, unattended: false),
        activity: ProviderActivitySignal = .workspaceIdle,
        deviceProfileSHA256: String = String(repeating: "0", count: 64),
        configurationSHA256: String = String(repeating: "0", count: 64),
        savedStrategy: ProviderRoutingStrategy = .savedPinned
    ) -> ResolvedProviderRoute {
        let provider: AppProvider
        let strategy: ProviderRoutingStrategy
        switch selection {
        case .saved:
            provider = savedProvider
            strategy = savedStrategy
        case .bestLocal:
            let localProviders: [AppProvider] = [.apple, .local]
            let comparable = localProviders.filter { qualifications[$0]?.hasComparableEvidence == true }
            if !comparable.isEmpty {
                let candidates = comparable.filter { candidate in
                    guard let qualification = qualifications[candidate], qualification.qualifies(for: requirements) else { return false }
                    return resolve(
                        provider: candidate,
                        appleAvailability: appleAvailability,
                        shortcutsAvailable: shortcutsAvailable,
                        adapter: adapterFor(candidate),
                        cloudAllowed: false
                    ).isRunnable
                }
                provider = ranked(candidates, qualifications: qualifications).first
                    ?? ranked(comparable, qualifications: qualifications).first
                    ?? (appleAvailability == .available ? .apple : .local)
                strategy = .bestLocalMeasured
            } else {
                provider = appleAvailability == .available ? .apple : .local
                strategy = .bestLocalColdStart
            }
        case .apple, .local, .chatgpt, .grok, .grokbot, .claude:
            provider = selection.explicitProvider ?? savedProvider
            strategy = .explicitPinned
        }
        let resolvedAdapter = adapterFor(provider)
        var decision = resolve(
            provider: provider,
            appleAvailability: appleAvailability,
            shortcutsAvailable: shortcutsAvailable,
            adapter: resolvedAdapter,
            cloudAllowed: cloudAllowed
        )
        if activity != .workspaceIdle, decision.isRunnable {
            decision = .blocked("ANOTHER_TASK_IS_ACTIVE")
        }
        if decision.isRunnable,
           qualifications[provider]?.qualifies(for: requirements) != true {
            let transport = provider == .apple ? "on-device Apple model" : "provider action"
            decision = .blocked("PROVIDER_QUALIFICATION_REQUIRED: This exact \(transport) needs all five fresh probe types, at least 80 percent schema reliability and assertion quality, sufficient context and tool results, zero integrity faults, and an observed App Intent return path when invoked by Siri. The observation does not prove unattended provider or model provenance.")
        }
        if strategy == .oracleRecommendation,
           decision.isRunnable,
           qualifications[provider]?.qualifies(for: requirements) != true {
            decision = .blocked("ORACLE_RECOMMENDATION_REQUALIFICATION_REQUIRED")
        }
        if selection == .bestLocal,
           strategy == .bestLocalMeasured,
           (qualifications[provider]?.qualifies(for: requirements) != true || !decision.isRunnable) {
            decision = .blocked("BEST_LOCAL_REQUALIFICATION_REQUIRED: Run a fresh five-probe suite for Apple Intelligence and/or Locally. Only a task-qualified measured local candidate can run, and Best Local never falls back to cloud.")
        }
        if requirements.requiresObservedAppIntentReturn,
           provider != .apple,
           resolvedAdapter.mode == "manual" {
            decision = .blocked("MANUAL_PROVIDER_RETURN_REQUIRES_USER")
        }
        let qualification = qualifications[provider]
        let access: ProviderAccessEvidence
        if provider == .apple {
            access = appleAvailability == .available ? .onDeviceRuntime : .unavailable
        } else if let qualification,
                  qualification.verifiedCount > 0,
                  qualification.integrityFaultCount == 0 {
            access = .recentLocallyValidatedResponse
        } else if resolvedAdapter.tested {
            access = .configuredUnmeasured
        } else {
            access = .unavailable
        }
        let evidence: ProviderRoutingEvidence?
        if decision.isRunnable {
            let candidate = ProviderRoutingEvidence(
                selection: selection,
                provider: provider,
                authorizedProvider: savedProvider,
                strategy: strategy,
                activity: activity,
                accessEvidence: access,
                deviceProfileSHA256: deviceProfileSHA256,
                configurationSHA256: configurationSHA256,
                qualification: qualification
            )
            do {
                try candidate.validate()
                evidence = candidate
            } catch {
                decision = .blocked("ROUTING_EVIDENCE_NOT_COMMITTABLE")
                evidence = nil
            }
        } else {
            evidence = nil
        }
        return ResolvedProviderRoute(selection: selection, provider: provider, decision: decision, evidence: evidence)
    }

    static func recommend(
        providers: [AppProvider],
        appleAvailability: AppleModelAvailability,
        shortcutsAvailable: Bool,
        adapterFor: (AppProvider) -> ShortcutAdapter,
        cloudAllowed: Bool,
        qualifications: [AppProvider: ProviderQualificationSnapshot],
        requirements: OracleTaskRequirements
    ) -> AppProvider? {
        let eligible = providers.filter { provider in
            guard (!requirements.localOnly || !provider.usesCloud),
                  let qualification = qualifications[provider],
                  qualification.qualifies(for: requirements),
                  resolve(
                    provider: provider,
                    appleAvailability: appleAvailability,
                    shortcutsAvailable: shortcutsAvailable,
                    adapter: adapterFor(provider),
                    cloudAllowed: cloudAllowed
                  ).isRunnable else { return false }
            return true
        }
        return ranked(eligible, qualifications: qualifications).first
    }

    private static func ranked(
        _ providers: [AppProvider],
        qualifications: [AppProvider: ProviderQualificationSnapshot]
    ) -> [AppProvider] {
        providers.sorted { lhs, rhs in
            guard let left = qualifications[lhs], let right = qualifications[rhs] else {
                return lhs.rawValue < rhs.rawValue
            }
            let reliabilityLeft = left.schemaPassCount * max(1, right.sampleCount)
            let reliabilityRight = right.schemaPassCount * max(1, left.sampleCount)
            if reliabilityLeft != reliabilityRight { return reliabilityLeft > reliabilityRight }
            let qualityLeft = left.assertionPassCount * max(1, right.assertionCount)
            let qualityRight = right.assertionPassCount * max(1, left.assertionCount)
            if qualityLeft != qualityRight { return qualityLeft > qualityRight }
            let timingIsComparable = (lhs == .apple) == (rhs == .apple)
            if timingIsComparable && left.medianDurationBucketMilliseconds != right.medianDurationBucketMilliseconds {
                return left.medianDurationBucketMilliseconds < right.medianDurationBucketMilliseconds
            }
            let fixedOrder: [AppProvider] = [.apple, .local, .chatgpt, .claude, .grok, .grokbot]
            return (fixedOrder.firstIndex(of: lhs) ?? fixedOrder.count) < (fixedOrder.firstIndex(of: rhs) ?? fixedOrder.count)
        }
    }

    static func resolve(
        provider: AppProvider,
        appleAvailability: AppleModelAvailability,
        shortcutsAvailable: Bool,
        adapter: ShortcutAdapter,
        cloudAllowed: Bool
    ) -> ProviderRoutingDecision {
        if provider == .apple {
            switch appleAvailability {
            case .available:
                return .onDeviceApple
            case .unavailable(let reason):
                return .blocked("Apple Intelligence is not available on this device: \(reason). Choose another provider only after Local Sandbox shows its Shortcut route is configured and currently qualified.")
            }
        }

        guard shortcutsAvailable else {
            return .blocked("Install Apple Shortcuts to use this provider.")
        }
        guard !provider.usesCloud || cloudAllowed else {
            return .blocked("Authorize cloud app handoffs in Settings first.")
        }
        guard !adapter.name.isEmpty,
              adapter.name.count <= 80,
              ["action", "manual"].contains(adapter.mode) else {
            return .blocked("Invalid Shortcut configuration.")
        }
        guard adapter.tested else {
            return .blocked("This provider Shortcut has not passed setup. Save it in Shortcuts and complete the read-only round-trip in Settings first.")
        }
        return .shortcut(name: adapter.name)
    }
}

extension ProviderRoutingDecision {
    var isRunnable: Bool {
        switch self {
        case .onDeviceApple, .shortcut: return true
        case .blocked: return false
        }
    }
}

struct ProviderHandoffPromptHeader: Equatable {
    let provider: AppProvider
    let selection: ProviderSelection
    let origin: ProviderTaskOrigin

    var jsonLine: String {
        "{\"recordType\":\"provider-handoff-prompt\",\"schemaVersion\":1,\"kind\":\"handoff-prompt\",\"provider\":\"\(provider.rawValue)\",\"selection\":\"\(selection.rawValue)\",\"origin\":\"\(origin.rawValue)\"}"
    }
}

private struct ProviderOutboundHandoff: Encodable, Equatable {
    let recordType = "provider-handoff"
    let schemaVersion = 2
    let direction = "outbound"
    let transport = "app-shortcut"
    let provider: AppProvider
    let selection: ProviderSelection
    let origin: ProviderTaskOrigin
    let adapterSHA256: String
    let actionIndex: Int
    let promptSHA256: String
}

private struct ProviderInboundReturn: Encodable, Equatable {
    let recordType = "provider-handoff"
    let schemaVersion = 2
    let direction = "inbound"
    let transport = "app-shortcut"
    let provider: AppProvider
    let selection: ProviderSelection
    let origin: ProviderTaskOrigin
    let adapterSHA256: String
    let actionIndex: Int
    let responseSHA256: String
}

enum ProviderHandoffTrace {
    static func outbound(
        provider: AppProvider,
        selection: ProviderSelection,
        origin: ProviderTaskOrigin,
        adapterName: String,
        actionIndex: Int,
        prompt: String
    ) throws -> TraceEntry {
        try entry(
            tool: "provider.handoff.outbound",
            event: ProviderOutboundHandoff(
                provider: provider,
                selection: selection,
                origin: origin,
                adapterSHA256: NativeDigest.sha256(adapterName),
                actionIndex: actionIndex,
                promptSHA256: NativeDigest.sha256(prompt)
            )
        )
    }

    static func inbound(
        provider: AppProvider,
        selection: ProviderSelection,
        origin: ProviderTaskOrigin,
        adapterName: String,
        actionIndex: Int,
        response: String
    ) throws -> TraceEntry {
        try entry(
            tool: "provider.handoff.inbound",
            event: ProviderInboundReturn(
                provider: provider,
                selection: selection,
                origin: origin,
                adapterSHA256: NativeDigest.sha256(adapterName),
                actionIndex: actionIndex,
                responseSHA256: NativeDigest.sha256(response)
            )
        )
    }

    private static func entry<Event: Encodable>(tool: String, event: Event) throws -> TraceEntry {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return TraceEntry(tool: tool, status: "ok", detail: String(decoding: try encoder.encode(event), as: UTF8.self))
    }
}
