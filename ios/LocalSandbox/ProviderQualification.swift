import CryptoKit
import Foundation
import Security

enum ProviderQualificationOutcome: String, Codable {
    case started, verified, failed, timedOut = "timed-out", integrityFault = "integrity-fault"
}

struct ProviderQualificationChallenge: Equatable {
    let attemptID: String
    let provider: AppProvider
    let probe: ProviderQualificationProbe
    let adapterName: String?
    let prompt: String
}

struct ProviderQualificationAttempt: Codable, Equatable {
    let attemptID: String
    let provider: AppProvider
    let epochSHA256: String
    let adapterSHA256: String?
    let probe: ProviderQualificationProbe
    var outcome: ProviderQualificationOutcome
    var schemaPassCount: Int?
    var assertionPassCount: Int
    let assertionCount: Int
    let promptCharacterCount: Int
    var durationBucketMilliseconds: Int
    var appIntentReturnObserved: Bool
    var adapterStateReconciled: Bool?
    let startedAt: Date
    var finishedAt: Date?
    private var encodedSchemaPassCountPresent: Bool
    private var encodedAdapterStateReconciledPresent: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case attemptID, provider, epochSHA256, adapterSHA256, probe, outcome, schemaPassCount
        case assertionPassCount, assertionCount, promptCharacterCount, durationBucketMilliseconds
        case appIntentReturnObserved = "automatedReturn"
        case adapterStateReconciled
        case startedAt, finishedAt
    }

    init(
        attemptID: String,
        provider: AppProvider,
        epochSHA256: String,
        adapterSHA256: String?,
        probe: ProviderQualificationProbe,
        outcome: ProviderQualificationOutcome,
        schemaPassCount: Int?,
        assertionPassCount: Int,
        assertionCount: Int,
        promptCharacterCount: Int,
        durationBucketMilliseconds: Int,
        appIntentReturnObserved: Bool,
        adapterStateReconciled: Bool? = true,
        startedAt: Date,
        finishedAt: Date?
    ) {
        self.attemptID = attemptID
        self.provider = provider
        self.epochSHA256 = epochSHA256
        self.adapterSHA256 = adapterSHA256
        self.probe = probe
        self.outcome = outcome
        self.schemaPassCount = schemaPassCount
        self.assertionPassCount = assertionPassCount
        self.assertionCount = assertionCount
        self.promptCharacterCount = promptCharacterCount
        self.durationBucketMilliseconds = durationBucketMilliseconds
        self.appIntentReturnObserved = appIntentReturnObserved
        self.adapterStateReconciled = adapterStateReconciled
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        encodedSchemaPassCountPresent = schemaPassCount != nil
        encodedAdapterStateReconciledPresent = adapterStateReconciled != nil
    }

    init(from decoder: Decoder) throws {
        let fields = try qualificationContractFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue)),
            required: Set(CodingKeys.allCases.map(\.rawValue)).subtracting([
                CodingKeys.adapterSHA256.rawValue,
                CodingKeys.schemaPassCount.rawValue,
                CodingKeys.adapterStateReconciled.rawValue,
                CodingKeys.finishedAt.rawValue,
            ]),
            errorCode: "INVALID_PROVIDER_QUALIFICATION_ATTEMPT_FIELDS"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        attemptID = try container.decode(String.self, forKey: .attemptID)
        provider = try container.decode(AppProvider.self, forKey: .provider)
        epochSHA256 = try container.decode(String.self, forKey: .epochSHA256)
        adapterSHA256 = fields.contains(CodingKeys.adapterSHA256.rawValue)
            ? try container.decode(String.self, forKey: .adapterSHA256)
            : nil
        probe = try container.decode(ProviderQualificationProbe.self, forKey: .probe)
        outcome = try container.decode(ProviderQualificationOutcome.self, forKey: .outcome)
        encodedSchemaPassCountPresent = fields.contains(CodingKeys.schemaPassCount.rawValue)
        schemaPassCount = encodedSchemaPassCountPresent
            ? try container.decode(Int.self, forKey: .schemaPassCount)
            : nil
        assertionPassCount = try container.decode(Int.self, forKey: .assertionPassCount)
        assertionCount = try container.decode(Int.self, forKey: .assertionCount)
        promptCharacterCount = try container.decode(Int.self, forKey: .promptCharacterCount)
        durationBucketMilliseconds = try container.decode(Int.self, forKey: .durationBucketMilliseconds)
        appIntentReturnObserved = try container.decode(Bool.self, forKey: .appIntentReturnObserved)
        encodedAdapterStateReconciledPresent = fields.contains(CodingKeys.adapterStateReconciled.rawValue)
        adapterStateReconciled = encodedAdapterStateReconciledPresent
            ? try container.decode(Bool.self, forKey: .adapterStateReconciled)
            : nil
        startedAt = try container.decode(Date.self, forKey: .startedAt)
        finishedAt = fields.contains(CodingKeys.finishedAt.rawValue)
            ? try container.decode(Date.self, forKey: .finishedAt)
            : nil
    }

    func validated(schemaVersion: Int = ProviderQualificationLedgerPayload.currentSchemaVersion) throws -> Self {
        let digestPattern = "^[a-f0-9]{64}$"
        let startedSeconds = startedAt.timeIntervalSince1970
        let finishedSeconds = finishedAt?.timeIntervalSince1970
        let schemaMetricShapeIsValid = schemaVersion == 1
            ? !encodedSchemaPassCountPresent && schemaPassCount == nil
            : [2, ProviderQualificationLedgerPayload.currentSchemaVersion].contains(schemaVersion)
                && encodedSchemaPassCountPresent && schemaPassCount != nil
        let adapterReconciliationShapeIsValid = [1, 2].contains(schemaVersion)
            ? !encodedAdapterStateReconciledPresent && adapterStateReconciled == nil
            : schemaVersion == ProviderQualificationLedgerPayload.currentSchemaVersion
                && encodedAdapterStateReconciledPresent && adapterStateReconciled != nil
        let adapterReconciliationStateIsValid: Bool
        if schemaVersion < ProviderQualificationLedgerPayload.currentSchemaVersion {
            adapterReconciliationStateIsValid = true
        } else if provider == .apple {
            adapterReconciliationStateIsValid = adapterStateReconciled == true
        } else if outcome == .started {
            adapterReconciliationStateIsValid = adapterStateReconciled == false
        } else if outcome == .verified {
            adapterReconciliationStateIsValid = adapterStateReconciled != nil
        } else {
            adapterReconciliationStateIsValid = adapterStateReconciled == true
        }
        guard schemaMetricShapeIsValid,
              adapterReconciliationShapeIsValid,
              adapterReconciliationStateIsValid,
              attemptID.range(of: "^[A-Fa-f0-9-]{36}$", options: .regularExpression) != nil,
              epochSHA256.range(of: digestPattern, options: .regularExpression) != nil,
              adapterSHA256 == nil || adapterSHA256!.range(of: digestPattern, options: .regularExpression) != nil,
              schemaPassCount == nil || (0...1).contains(schemaPassCount!),
              assertionCount == 1, (0...assertionCount).contains(assertionPassCount),
              assertionPassCount <= (schemaPassCount ?? assertionCount),
              (outcome == .verified) == (assertionPassCount == 1),
              ![.started, .timedOut, .integrityFault].contains(outcome) || (schemaPassCount ?? 0) == 0,
              (1...12_000).contains(promptCharacterCount),
              (0...300_000).contains(durationBucketMilliseconds),
              (provider == .apple) == (adapterSHA256 == nil),
              startedSeconds.isFinite,
              finishedSeconds.map({ $0.isFinite }) ?? true,
              finishedAt.map({ $0 >= startedAt }) ?? true,
              ProviderQualificationStore.utcDayNumber(for: startedAt) != nil,
              (outcome == .started) == (finishedAt == nil) else {
            throw SandboxError.invalid("INVALID_PROVIDER_QUALIFICATION_ATTEMPT")
        }
        return self
    }

    mutating func upgradeSchemaPassCount(_ value: Int) {
        schemaPassCount = value
        encodedSchemaPassCountPresent = true
    }

    mutating func setAdapterStateReconciled(_ value: Bool) {
        adapterStateReconciled = value
        encodedAdapterStateReconciledPresent = true
    }
}

private func qualificationContractFields(
    _ decoder: Decoder,
    allowed: Set<String>,
    required: Set<String>,
    errorCode: String
) throws -> Set<String> {
    let dynamic = try decoder.container(keyedBy: QualificationDynamicCodingKey.self)
    let fields = Set(dynamic.allKeys.map(\.stringValue))
    guard fields.isSubset(of: allowed), required.isSubset(of: fields) else {
        throw SandboxError.invalid(errorCode)
    }
    return fields
}

private struct QualificationDynamicCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

struct OraclePinnedRecommendation: Codable {
    let provider: AppProvider
    let configurationSHA256: String
    let qualificationEpochSHA256: String
    let appliedAt: Date

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case provider, configurationSHA256, qualificationEpochSHA256, appliedAt
    }

    init(provider: AppProvider, configurationSHA256: String, qualificationEpochSHA256: String, appliedAt: Date) {
        self.provider = provider
        self.configurationSHA256 = configurationSHA256
        self.qualificationEpochSHA256 = qualificationEpochSHA256
        self.appliedAt = appliedAt
    }

    init(from decoder: Decoder) throws {
        _ = try qualificationContractFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue)),
            required: Set(CodingKeys.allCases.map(\.rawValue)),
            errorCode: "INVALID_ORACLE_RECOMMENDATION_FIELDS"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        provider = try container.decode(AppProvider.self, forKey: .provider)
        configurationSHA256 = try container.decode(String.self, forKey: .configurationSHA256)
        qualificationEpochSHA256 = try container.decode(String.self, forKey: .qualificationEpochSHA256)
        appliedAt = try container.decode(Date.self, forKey: .appliedAt)
        _ = try validated()
    }

    func validated() throws -> Self {
        let pattern = "^[a-f0-9]{64}$"
        guard configurationSHA256.range(of: pattern, options: .regularExpression) != nil,
              qualificationEpochSHA256.range(of: pattern, options: .regularExpression) != nil else {
            throw SandboxError.invalid("INVALID_ORACLE_RECOMMENDATION_RECORD")
        }
        return self
    }
}

struct ProviderQualificationLedgerPayload: Codable {
    static let currentSchemaVersion = 3

    let recordType: String
    let schemaVersion: Int
    let suiteVersion: Int
    var attempts: [ProviderQualificationAttempt]
    var recommendation: OraclePinnedRecommendation?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case recordType, schemaVersion, suiteVersion, attempts, recommendation
    }

    init(
        recordType: String,
        schemaVersion: Int,
        suiteVersion: Int,
        attempts: [ProviderQualificationAttempt],
        recommendation: OraclePinnedRecommendation?
    ) {
        self.recordType = recordType
        self.schemaVersion = schemaVersion
        self.suiteVersion = suiteVersion
        self.attempts = attempts
        self.recommendation = recommendation
    }

    init(from decoder: Decoder) throws {
        let fields = try qualificationContractFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue)),
            required: Set(CodingKeys.allCases.map(\.rawValue)).subtracting([CodingKeys.recommendation.rawValue]),
            errorCode: "INVALID_PROVIDER_QUALIFICATION_LEDGER_FIELDS"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        recordType = try container.decode(String.self, forKey: .recordType)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard [1, 2, Self.currentSchemaVersion].contains(schemaVersion) else {
            throw SandboxError.invalid("INVALID_PROVIDER_QUALIFICATION_LEDGER")
        }
        suiteVersion = try container.decode(Int.self, forKey: .suiteVersion)
        attempts = try container.decode([ProviderQualificationAttempt].self, forKey: .attempts)
        recommendation = fields.contains(CodingKeys.recommendation.rawValue)
            ? try container.decode(OraclePinnedRecommendation.self, forKey: .recommendation)
            : nil
        _ = try validated()
    }

    static var empty: Self {
        Self(recordType: "provider-qualification-ledger", schemaVersion: currentSchemaVersion, suiteVersion: ProviderQualificationStore.suiteVersion, attempts: [], recommendation: nil)
    }

    func validated() throws -> Self {
        guard recordType == "provider-qualification-ledger",
              [1, 2, Self.currentSchemaVersion].contains(schemaVersion),
              suiteVersion == ProviderQualificationStore.suiteVersion,
              attempts.count <= ProviderQualificationStore.maximumStoredAttempts,
              Set(attempts.map(\.attemptID)).count == attempts.count,
              ProviderQualificationStore.hasUniqueDailyAttempts(attempts) else {
            throw SandboxError.invalid("INVALID_PROVIDER_QUALIFICATION_LEDGER")
        }
        _ = try attempts.map { try $0.validated(schemaVersion: schemaVersion) }
        _ = try recommendation?.validated()
        return self
    }

    func upgradedToCurrentSchema() throws -> Self {
        guard schemaVersion < Self.currentSchemaVersion else { return self }
        var migratedAttempts = attempts
        for index in migratedAttempts.indices {
            if schemaVersion == 1 {
                migratedAttempts[index].upgradeSchemaPassCount(migratedAttempts[index].outcome == .verified ? 1 : 0)
            }
            let attempt = migratedAttempts[index]
            migratedAttempts[index].setAdapterStateReconciled(
                attempt.provider == .apple || attempt.outcome != .verified
            )
        }
        return try Self(
            recordType: recordType,
            schemaVersion: Self.currentSchemaVersion,
            suiteVersion: suiteVersion,
            attempts: migratedAttempts,
            recommendation: recommendation
        ).validated()
    }
}

struct SignedProviderQualificationLedger: Codable {
    let payload: ProviderQualificationLedgerPayload
    let hmacSHA256: String

    private enum CodingKeys: String, CodingKey, CaseIterable { case payload, hmacSHA256 }

    init(payload: ProviderQualificationLedgerPayload, hmacSHA256: String) {
        self.payload = payload
        self.hmacSHA256 = hmacSHA256
    }

    init(from decoder: Decoder) throws {
        _ = try qualificationContractFields(
            decoder,
            allowed: Set(CodingKeys.allCases.map(\.rawValue)),
            required: Set(CodingKeys.allCases.map(\.rawValue)),
            errorCode: "INVALID_SIGNED_PROVIDER_QUALIFICATION_LEDGER_FIELDS"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payload = try container.decode(ProviderQualificationLedgerPayload.self, forKey: .payload)
        hmacSHA256 = try container.decode(String.self, forKey: .hmacSHA256)
        guard hmacSHA256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else {
            throw SandboxError.invalid("INVALID_PROVIDER_QUALIFICATION_LEDGER_SIGNATURE")
        }
    }
}

@MainActor
struct ProviderQualificationResetOperations {
    let qualificationIsActive: () -> Bool
    let removeLedgerChecked: () throws -> Void
    let ledgerExists: () throws -> Bool
    let deleteSigningKeyChecked: () throws -> Void
    let signingKeyExists: () throws -> Bool
    let invalidateAdapterState: (AppProvider) throws -> Void
    let adapterStateExists: (AppProvider) -> Bool
}

@MainActor
struct ProviderQualificationSigningKeyOperations {
    let readChecked: () throws -> String?
    let generateRandomBytes: () throws -> Data
    let writeChecked: (String) throws -> Void
}

@MainActor
enum ProviderQualificationStore {
    nonisolated static let suiteVersion = 2
    nonisolated static let maximumStoredAttempts = 240
    nonisolated static let freshnessSeconds: TimeInterval = 7 * 24 * 60 * 60
    nonisolated static let pendingTimeoutSeconds: TimeInterval = 10 * 60
    nonisolated static let clockRollbackToleranceSeconds: TimeInterval = 5 * 60
    nonisolated private static let ledgerKeyName = "providerQualificationLedgerHMAC"
    nonisolated private static let fixedDurationBucket = 500
    nonisolated private static let appleTransportEpoch = "app-intent-suite-v1"
    private(set) static var appleSuiteRunning = false

    static var qualificationActive: Bool {
        if appleSuiteRunning { return true }
        return (try? load(now: Date()).attempts.contains { $0.outcome == .started }) == true
    }

    nonisolated static func utcDayNumber(for date: Date) -> Int64? {
        let day = floor(date.timeIntervalSince1970 / (24 * 60 * 60))
        guard day.isFinite, day > Double(Int64.min), day < Double(Int64.max) else { return nil }
        return Int64(day)
    }

    nonisolated fileprivate static func dailyAttemptKey(_ attempt: ProviderQualificationAttempt) -> String? {
        guard let day = utcDayNumber(for: attempt.startedAt) else { return nil }
        return "\(attempt.provider.rawValue)|\(attempt.probe.rawValue)|\(day)"
    }

    nonisolated static func hasUniqueDailyAttempts(_ attempts: [ProviderQualificationAttempt]) -> Bool {
        let dailyKeys = attempts.compactMap(dailyAttemptKey)
        return dailyKeys.count == attempts.count && Set(dailyKeys).count == attempts.count
    }

    nonisolated static func recordedProbes(
        provider: AppProvider,
        onUTCDate date: Date,
        attempts: [ProviderQualificationAttempt],
        completedOnly: Bool = false
    ) -> Set<ProviderQualificationProbe> {
        guard let day = utcDayNumber(for: date) else { return [] }
        return Set(attempts.compactMap { attempt in
            guard attempt.provider == provider,
                  utcDayNumber(for: attempt.startedAt) == day,
                  !completedOnly || attempt.outcome != .started else { return nil }
            return attempt.probe
        })
    }

    nonisolated static func hasMaterialClockRollback(
        now: Date,
        attempts: [ProviderQualificationAttempt]
    ) -> Bool {
        let latestStoredTimestamp = attempts.reduce(nil as Date?) { latest, attempt in
            let attemptLatest = max(attempt.startedAt, attempt.finishedAt ?? attempt.startedAt)
            return latest.map { max($0, attemptLatest) } ?? attemptLatest
        }
        guard let latestStoredTimestamp else { return false }
        return latestStoredTimestamp.timeIntervalSince(now) > clockRollbackToleranceSeconds
    }

    nonisolated static func scoredAttempts(
        provider: AppProvider,
        epochSHA256: String,
        now: Date,
        attempts: [ProviderQualificationAttempt]
    ) -> [ProviderQualificationAttempt] {
        Array(attempts
            .filter {
                $0.provider == provider &&
                $0.epochSHA256 == epochSHA256 &&
                $0.outcome != .started &&
                ($0.provider == .apple || $0.outcome != .verified || $0.adapterStateReconciled == true) &&
                now.timeIntervalSince($0.startedAt) <= freshnessSeconds
            }
            .sorted { $0.startedAt > $1.startedAt }
            .prefix(20))
    }

    nonisolated static func retainingCurrentAppleTransportEvidence(
        _ attempts: [ProviderQualificationAttempt],
        currentEpoch: String
    ) -> [ProviderQualificationAttempt] {
        attempts.filter { $0.provider != .apple || $0.epochSHA256 == currentEpoch }
    }

    static func prepare() throws {
        _ = try signingKey()
        if !FileManager.default.fileExists(atPath: try ledgerURL().path) {
            try save(.empty)
        } else {
            var ledger = try load(now: Date())
            try reconcilePersistedCompletions(&ledger)
        }
    }

    static func reset() throws {
        try reset(using: ProviderQualificationResetOperations(
            qualificationIsActive: { qualificationActive },
            removeLedgerChecked: { try removeLedgerChecked() },
            ledgerExists: { FileManager.default.fileExists(atPath: try ledgerURL().path) },
            deleteSigningKeyChecked: { try Keychain.deleteChecked(ledgerKeyName) },
            signingKeyExists: { try Keychain.getChecked(ledgerKeyName) != nil },
            invalidateAdapterState: { try AdapterSettings.invalidateMeasuredRoundTrip(for: $0) },
            adapterStateExists: { AdapterSettings.get($0).tested }
        ))
    }

    static func reset(using operations: ProviderQualificationResetOperations) throws {
        guard !operations.qualificationIsActive() else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_RESET_REQUIRES_IDLE_STATE")
        }
        try operations.removeLedgerChecked()
        try operations.deleteSigningKeyChecked()
        for provider in AppProvider.allCases where provider != .apple {
            try operations.invalidateAdapterState(provider)
        }
        guard try !operations.ledgerExists(),
              try !operations.signingKeyExists(),
              AppProvider.allCases.filter({ $0 != .apple }).allSatisfy({ !operations.adapterStateExists($0) }) else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_RESET_VERIFICATION_FAILED")
        }
    }

    static func deviceProfileSHA256() -> String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let os = ProviderRuntimeIdentity.operatingSystemDescriptor(
            version: version,
            buildDescription: ProcessInfo.processInfo.operatingSystemVersionString
        )
        return NativeDigest.sha256("hardware=\(machineIdentifier())|\(os)")
    }

    static func configurationSHA256(policy: ResourcePolicy) -> String {
        let policyJSON = (try? String(decoding: JSONEncoder.sorted.encode(policy), as: UTF8.self)) ?? "invalid-policy"
        return NativeDigest.sha256("suite=\(suiteVersion)|policy=\(policyJSON)|tools=\(ToolName.allNames.sorted().joined(separator: ","))")
    }

    static func epochSHA256(provider: AppProvider, adapter: ShortcutAdapter?) -> String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let os = ProviderRuntimeIdentity.operatingSystemDescriptor(
            version: version,
            buildDescription: ProcessInfo.processInfo.operatingSystemVersionString
        )
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
        let adapterDigest = adapter.map(adapterSHA256) ?? "foundation-models"
        let appleState: String
        let transportEpoch: String
        if provider == .apple {
            switch ProviderRuntimeCapabilities.appleModel {
            case .available: appleState = "available"
            case .unavailable: appleState = "unavailable"
            }
            transportEpoch = appleTransportEpoch
        } else {
            appleState = "not-applicable"
            transportEpoch = "external-app-intent-pair-v1"
        }
        return NativeDigest.sha256(
            "suite=\(suiteVersion)|device=\(deviceProfileSHA256())|\(os)|app=\(appVersion)|build=\(build)|provider=\(provider.rawValue)|adapter=\(adapterDigest)|apple=\(appleState)|transport=\(transportEpoch)"
        )
    }

    static func adapterSHA256(_ adapter: ShortcutAdapter) -> String {
        NativeDigest.sha256("name=\(adapter.name)|mode=\(adapter.mode)")
    }

    static func requireSavedAuthorization(for provider: AppProvider) throws -> ResourcePolicy {
        let policy = try SavedExecutionAuthorization.load()
        guard !provider.usesCloud || policy.cloudAllowed else {
            throw SandboxError.blocked("Authorize cloud app handoffs in Settings first.")
        }
        if provider != .apple { _ = try ProviderSharingConsent.require(provider) }
        return policy
    }

    static func externalChallenge(
        provider: AppProvider,
        pendingAttemptID: String? = nil,
        appIntentTransportObserved: Bool = false,
        loadPending: @MainActor (AppProvider) throws -> ProviderQualificationChallenge? = {
            try ProviderQualificationStore.pending(provider: $0)
        },
        createChallenge: @MainActor (AppProvider, Int, Bool) throws -> ProviderQualificationChallenge = {
            try ProviderQualificationStore.begin(
                provider: $0,
                contextCharacters: $1,
                appIntentTransportObserved: $2
            )
        }
    ) throws -> ProviderQualificationChallenge {
        guard provider != .apple else {
            throw SandboxError.blocked("Run Apple checks through the Apple qualification App Intent.")
        }
        let policy = try requireSavedAuthorization(for: provider)
        let contextCharacters = min(policy.contextChars, ProviderQualificationSnapshot.maximumSupportedContextCharacters)
        if let pendingAttemptID {
            guard let challenge = try loadPending(provider),
                  challenge.provider == provider,
                  challenge.attemptID == pendingAttemptID else {
                throw SandboxError.blocked("PROVIDER_CHECK_CHANGED: Refresh the pending check for the current Shortcut configuration.")
            }
            guard challenge.prompt.count <= contextCharacters else {
                throw SandboxError.blocked("PROVIDER_CHECK_EXCEEDS_SAVED_CONTEXT: Restore the saved prompt cap or wait for this check to expire before starting another.")
            }
            try ProviderSharingConsent.requireQualification(challenge)
            return challenge
        }
        return try createChallenge(provider, contextCharacters, appIntentTransportObserved)
    }

    static func begin(
        provider: AppProvider,
        contextCharacters: Int,
        appIntentTransportObserved: Bool = false,
        withinAppleSuite: Bool = false,
        now: Date = Date()
    ) throws -> ProviderQualificationChallenge {
        let authorizedContextCharacters: Int
        if provider == .apple {
            authorizedContextCharacters = contextCharacters
        } else {
            let policy = try requireSavedAuthorization(for: provider)
            authorizedContextCharacters = min(contextCharacters, policy.contextChars)
        }
        guard Keychain.get("appleUser") != nil, SandboxStore.shared.connected else {
            throw SandboxError.blocked("SIGN_IN_AND_PREPARE_PROTECTED_WORKSPACE_FIRST")
        }
        guard !AgentRunner.shared.running else { throw SandboxError.blocked("ANOTHER_RUN_IS_ACTIVE") }
        guard !qualificationActive || withinAppleSuite else {
            throw SandboxError.blocked("ANOTHER_PROVIDER_QUALIFICATION_IS_ACTIVE")
        }
        if let session = ShortcutCoordinator.shared.current(), ["awaiting_response", "applying"].contains(session.phase) {
            throw SandboxError.blocked("FINISH_PENDING_APP_HANDOFF_FIRST")
        }
        let boundedContext = min(max(authorizedContextCharacters, 2_000), ProviderQualificationSnapshot.maximumSupportedContextCharacters)
        let adapter: ShortcutAdapter?
        if provider == .apple {
            guard ProviderRuntimeCapabilities.appleModel == .available else {
                throw SandboxError.blocked("APPLE_INTELLIGENCE_UNAVAILABLE_FOR_QUALIFICATION")
            }
            adapter = nil
        } else {
            guard ProviderRuntimeCapabilities.shortcutsAvailable else { throw SandboxError.blocked("SHORTCUTS_UNAVAILABLE") }
            let configured = AdapterSettings.get(provider)
            guard !configured.name.isEmpty, ["action", "manual"].contains(configured.mode) else {
                throw SandboxError.blocked("CONFIGURE_PROVIDER_SHORTCUT_FIRST")
            }
            adapter = configured
        }

        var ledger = try load(now: now)
        let epoch = epochSHA256(provider: provider, adapter: adapter)
        guard !ledger.attempts.contains(where: { $0.provider == provider && $0.epochSHA256 == epoch && $0.outcome == .started }) else {
            throw SandboxError.blocked("COMPLETE_OR_WAIT_FOR_THE_PENDING_PROVIDER_CHECK")
        }
        let recordedToday = recordedProbes(provider: provider, onUTCDate: now, attempts: ledger.attempts)
        let availableProbes = ProviderQualificationProbe.allCases.filter { !recordedToday.contains($0) }
        guard !availableProbes.isEmpty else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_DAILY_SUITE_ALREADY_RECORDED")
        }
        let fresh = ledger.attempts.filter { $0.provider == provider && $0.epochSHA256 == epoch && now.timeIntervalSince($0.startedAt) <= freshnessSeconds }
        let counts = Dictionary(grouping: fresh, by: \.probe).mapValues(\.count)
        let probe = availableProbes.min { lhs, rhs in
            let left = counts[lhs, default: 0]
            let right = counts[rhs, default: 0]
            if left != right { return left < right }
            return ProviderQualificationProbe.allCases.firstIndex(of: lhs)! < ProviderQualificationProbe.allCases.firstIndex(of: rhs)!
        } ?? .strictJSON
        let attemptID = UUID().uuidString
        let token = try challengeToken(epoch: epoch, provider: provider, probe: probe, attemptID: attemptID)
        let prompt = ProviderQualificationVerifier.prompt(probe: probe, token: token, contextCharacters: boundedContext)
        ledger.attempts.append(try ProviderQualificationAttempt(
            attemptID: attemptID,
            provider: provider,
            epochSHA256: epoch,
            adapterSHA256: adapter.map(adapterSHA256),
            probe: probe,
            outcome: .started,
            schemaPassCount: 0,
            assertionPassCount: 0,
            assertionCount: 1,
            promptCharacterCount: prompt.count,
            durationBucketMilliseconds: 0,
            appIntentReturnObserved: appIntentTransportObserved && (provider == .apple || adapter?.mode != "manual"),
            adapterStateReconciled: provider == .apple,
            startedAt: now,
            finishedAt: nil
        ).validated())
        trim(&ledger)
        try save(ledger)
        let challenge = ProviderQualificationChallenge(attemptID: attemptID, provider: provider, probe: probe, adapterName: adapter?.name, prompt: prompt)
        if provider != .apple { try ProviderSharingConsent.bindQualification(challenge) }
        return challenge
    }

    @discardableResult
    static func complete(
        attemptID: String,
        provider: AppProvider,
        response: String,
        appIntentTransportObserved: Bool = false,
        withinAppleSuite: Bool = false,
        now: Date = Date()
    ) throws -> ProviderQualificationAttempt {
        guard Keychain.get("appleUser") != nil, SandboxStore.shared.connected else {
            throw SandboxError.blocked("SIGN_IN_AND_PREPARE_PROTECTED_WORKSPACE_FIRST")
        }
        if provider != .apple { _ = try requireSavedAuthorization(for: provider) }
        guard response.utf8.count <= 16_000 else { throw SandboxError.invalid("QUALIFICATION_RESPONSE_TOO_LARGE") }
        var ledger = try load(now: now)
        guard let index = ledger.attempts.firstIndex(where: { $0.attemptID == attemptID }),
              ledger.attempts[index].provider == provider else {
            throw SandboxError.blocked("PROVIDER_CHECK_NOT_FOUND")
        }
        if provider != .apple {
            // Reconstruct the exact retained attempt, including terminal retries whose
            // measured-adapter reconciliation failed. A started-only lookup loses them.
            let retained = ledger.attempts[index]
            let token = try challengeToken(epoch: retained.epochSHA256, provider: provider, probe: retained.probe, attemptID: retained.attemptID)
            let challenge = ProviderQualificationChallenge(attemptID: retained.attemptID, provider: provider, probe: retained.probe,
                adapterName: AdapterSettings.get(provider).name,
                prompt: ProviderQualificationVerifier.prompt(probe: retained.probe, token: token, contextCharacters: retained.promptCharacterCount))
            try ProviderSharingConsent.requireQualification(challenge)
        }
        guard !appleSuiteRunning || (withinAppleSuite && provider == .apple) else {
            throw SandboxError.blocked("APPLE_PROVIDER_QUALIFICATION_IS_ACTIVE")
        }
        let currentAdapter = provider == .apple ? nil : AdapterSettings.get(provider)
        let expectedEpoch = epochSHA256(provider: provider, adapter: currentAdapter)
        let expectedAdapter = currentAdapter.map(adapterSHA256)
        let completedAttempt: ProviderQualificationAttempt?
        if ledger.attempts[index].outcome == .started {
            var attempt = ledger.attempts[index]
            attempt.schemaPassCount = 0
            attempt.assertionPassCount = 0
            if attempt.epochSHA256 != expectedEpoch || attempt.adapterSHA256 != expectedAdapter {
                attempt.outcome = .integrityFault
            } else {
                let token = try challengeToken(epoch: attempt.epochSHA256, provider: provider, probe: attempt.probe, attemptID: attempt.attemptID)
                let schemaPassed = ProviderQualificationVerifier.validatesStrictSchema(response: response, probe: attempt.probe)
                let assertionPassed = ProviderQualificationVerifier.validate(response: response, probe: attempt.probe, token: token)
                attempt.schemaPassCount = schemaPassed ? 1 : 0
                attempt.assertionPassCount = assertionPassed ? 1 : 0
                attempt.outcome = assertionPassed ? .verified : .failed
            }
            attempt.durationBucketMilliseconds = durationBucket(milliseconds: max(0, now.timeIntervalSince(attempt.startedAt) * 1_000))
            attempt.appIntentReturnObserved = attempt.appIntentReturnObserved && appIntentTransportObserved
            attempt.finishedAt = now
            completedAttempt = attempt
        } else {
            completedAttempt = nil
        }
        return try persistAndReconcileCompletion(
            ledger: &ledger,
            index: index,
            completedAttempt: completedAttempt,
            expectedEpochSHA256: expectedEpoch,
            expectedAdapterSHA256: expectedAdapter,
            saveLedger: { try save($0) },
            markMeasuredRoundTrip: { try AdapterSettings.markMeasuredRoundTrip(for: $0) },
            readAdapter: { AdapterSettings.get($0) }
        )
    }

    static func persistAndReconcileCompletion(
        ledger: inout ProviderQualificationLedgerPayload,
        index: Int,
        completedAttempt: ProviderQualificationAttempt?,
        expectedEpochSHA256: String,
        expectedAdapterSHA256: String?,
        saveLedger: (ProviderQualificationLedgerPayload) throws -> Void,
        markMeasuredRoundTrip: (AppProvider) throws -> Void,
        readAdapter: (AppProvider) -> ShortcutAdapter
    ) throws -> ProviderQualificationAttempt {
        guard ledger.attempts.indices.contains(index) else {
            throw SandboxError.invalid("INVALID_PROVIDER_QUALIFICATION_ATTEMPT_INDEX")
        }
        let stored = ledger.attempts[index]
        if let completedAttempt {
            guard stored.outcome == .started,
                  completedAttempt.attemptID == stored.attemptID,
                  completedAttempt.provider == stored.provider,
                  completedAttempt.epochSHA256 == stored.epochSHA256,
                  completedAttempt.adapterSHA256 == stored.adapterSHA256,
                  completedAttempt.outcome != .started else {
                throw SandboxError.invalid("INVALID_PROVIDER_QUALIFICATION_COMPLETION")
            }
            var terminal = completedAttempt
            terminal.setAdapterStateReconciled(
                terminal.provider == .apple || terminal.outcome != .verified
            )
            ledger.attempts[index] = try terminal.validated()
            try saveLedger(ledger)
        } else {
            guard stored.outcome != .started else {
                throw SandboxError.blocked("PROVIDER_CHECK_RESPONSE_REQUIRED")
            }
        }

        var terminal = ledger.attempts[index]
        guard terminal.outcome == .verified,
              terminal.provider != .apple,
              terminal.adapterStateReconciled != true else {
            return terminal
        }
        guard terminal.epochSHA256 == expectedEpochSHA256,
              terminal.adapterSHA256 == expectedAdapterSHA256,
              expectedAdapterSHA256 != nil else {
            throw SandboxError.blocked("PROVIDER_CHECK_CONFIGURATION_CHANGED_BEFORE_RECONCILIATION")
        }

        var adapter = readAdapter(terminal.provider)
        guard adapterSHA256(adapter) == expectedAdapterSHA256 else {
            throw SandboxError.blocked("PROVIDER_CHECK_ADAPTER_READBACK_CHANGED")
        }
        if !adapter.tested {
            try markMeasuredRoundTrip(terminal.provider)
            adapter = readAdapter(terminal.provider)
        }
        guard adapter.tested, adapterSHA256(adapter) == expectedAdapterSHA256 else {
            throw SandboxError.conflict("PROVIDER_CHECK_ADAPTER_READBACK_FAILED")
        }

        terminal.setAdapterStateReconciled(true)
        ledger.attempts[index] = try terminal.validated()
        try saveLedger(ledger)
        return terminal
    }

    static func pending(provider: AppProvider, now: Date = Date()) throws -> ProviderQualificationChallenge? {
        let ledger = try load(now: now)
        let adapter = provider == .apple ? nil : AdapterSettings.get(provider)
        let epoch = epochSHA256(provider: provider, adapter: adapter)
        guard let attempt = ledger.attempts.last(where: { $0.provider == provider && $0.epochSHA256 == epoch && $0.outcome == .started }) else { return nil }
        let token = try challengeToken(epoch: epoch, provider: provider, probe: attempt.probe, attemptID: attempt.attemptID)
        return ProviderQualificationChallenge(
            attemptID: attempt.attemptID,
            provider: provider,
            probe: attempt.probe,
            adapterName: adapter?.name,
            prompt: ProviderQualificationVerifier.prompt(probe: attempt.probe, token: token, contextCharacters: attempt.promptCharacterCount)
        )
    }

    static func snapshots(now: Date = Date()) throws -> [AppProvider: ProviderQualificationSnapshot] {
        let ledger = try load(now: now)
        var values: [AppProvider: ProviderQualificationSnapshot] = [:]
        for provider in AppProvider.allCases {
            let adapter = provider == .apple ? nil : AdapterSettings.get(provider)
            let epoch = epochSHA256(provider: provider, adapter: adapter)
            let attempts = scoredAttempts(provider: provider, epochSHA256: epoch, now: now, attempts: ledger.attempts)
            guard !attempts.isEmpty else { continue }
            let completedDurations = attempts.filter { $0.outcome != .started && $0.appIntentReturnObserved }.map(\.durationBucketMilliseconds).sorted()
            let median = completedDurations.isEmpty ? 300_000 : completedDurations[(completedDurations.count - 1) / 2]
            let verified = attempts.filter { $0.outcome == .verified }
            let appIntentReturnProbes = Set(verified.filter(\.appIntentReturnObserved).map(\.probe))
            values[provider] = ProviderQualificationSnapshot(
                provider: provider,
                epochSHA256: epoch,
                adapterSHA256: adapter.map(adapterSHA256),
                sampleCount: attempts.count,
                distinctProbeCount: Set(attempts.map(\.probe)).count,
                verifiedCount: verified.count,
                schemaPassCount: attempts.reduce(0) { $0 + ($1.schemaPassCount ?? 0) },
                assertionPassCount: attempts.reduce(0) { $0 + $1.assertionPassCount },
                assertionCount: attempts.reduce(0) { $0 + $1.assertionCount },
                toolProbePassCount: Set(verified.filter { $0.probe.isToolProbe }.map(\.probe)).count,
                maximumContextCharacters: verified.map(\.promptCharacterCount).max() ?? 0,
                medianDurationBucketMilliseconds: median,
                integrityFaultCount: attempts.filter { $0.outcome == .integrityFault }.count,
                appIntentReturnObserved: appIntentReturnProbes.count >= ProviderQualificationSnapshot.requiredDistinctProbes,
                lastSuccessfulAt: verified.compactMap(\.finishedAt).max().map { ISO8601DateFormatter().string(from: $0) }
            )
        }
        return values
    }

    static func recordRecommendation(provider: AppProvider, policy: ResourcePolicy, now: Date = Date()) throws {
        let qualifications = try snapshots(now: now)
        guard let qualification = qualifications[provider], qualification.baseQualified else {
            throw SandboxError.blocked("ORACLE_RECOMMENDATION_QUALIFICATION_CHANGED")
        }
        var ledger = try load(now: now)
        ledger.recommendation = try OraclePinnedRecommendation(
            provider: provider,
            configurationSHA256: configurationSHA256(policy: policy),
            qualificationEpochSHA256: qualification.epochSHA256,
            appliedAt: now
        ).validated()
        try save(ledger)
    }

    static func hasCurrentRecommendation(provider: AppProvider, policy: ResourcePolicy, now: Date = Date()) -> Bool {
        guard let ledger = try? load(now: now),
              let record = ledger.recommendation,
              record.provider == provider,
              record.configurationSHA256 == configurationSHA256(policy: policy),
              now.timeIntervalSince(record.appliedAt) <= freshnessSeconds,
              let values = try? snapshots(now: now),
              let qualification = values[provider],
              qualification.epochSHA256 == record.qualificationEpochSHA256,
              qualification.baseQualified else { return false }
        return true
    }

    static func status(provider: AppProvider, contextCharacters: Int) -> String {
        do {
            guard let snapshot = try snapshots()[provider] else { return "0/5 measured checks · not qualified" }
            let requirement = OracleTaskRequirements.filesystem(policyContextCharacters: min(contextCharacters, ProviderQualificationSnapshot.maximumSupportedContextCharacters), localOnly: !provider.usesCloud, unattended: true)
            let state = snapshot.qualifies(for: requirement) ? "qualified" : "not qualified"
            let measuredPath = provider == .apple ? "in-process Apple model" : "external App Intent round trip"
            let timing = snapshot.appIntentReturnObserved ? "\(snapshot.medianDurationBucketMilliseconds) ms \(measuredPath) median" : "no complete observed App Intent return suite"
            return "\(snapshot.schemaPassCount)/\(snapshot.sampleCount) schema-valid · \(snapshot.assertionPassCount)/\(snapshot.assertionCount) exact assertions · \(snapshot.distinctProbeCount)/5 probe types · integrity faults \(snapshot.integrityFaultCount) · \(timing) · \(state)"
        } catch {
            return "Qualification ledger needs review"
        }
    }

    static func runAppleSuiteFromAppIntent(
        policy: ResourcePolicy,
        executionGeneration: ExecutionContinuationGate.Generation,
        onProgress: @escaping (String) -> Void = { _ in }
    ) async throws -> ProviderQualificationSnapshot {
        let continuationValidator = ExecutionContinuationGate.shared.validator(for: executionGeneration)
        try continuationValidator.requireCurrent()
        return try await continuationValidator.validatedAwait {
            try await runAppleSuite(
                policy: policy,
                continuationValidator: continuationValidator,
                onProgress: onProgress
            )
        }
    }

    static func performAppleQualificationProbe(
        continuationValidator: ExecutionContinuationValidator,
        providerResponse: @MainActor () async throws -> String,
        persistCompletion: @MainActor (_ response: String, _ appIntentTransportObserved: Bool) throws -> Void
    ) async throws {
        let response: String
        do {
            response = try await continuationValidator.validatedAwait {
                try await providerResponse()
            }
        } catch {
            // Retired generations must escape before a provider error can become durable
            // qualification evidence. Completion failures are not provider failures.
            try continuationValidator.requireCurrent()
            let cancelled = error is CancellationError || Task.isCancelled
            try continuationValidator.beforePersistence()
            try persistCompletion("{}", !cancelled)
            if cancelled { throw CancellationError() }
            return
        }

        do {
            try Task.checkCancellation()
        } catch {
            try continuationValidator.requireCurrent()
            try continuationValidator.beforePersistence()
            try persistCompletion("{}", false)
            throw CancellationError()
        }
        try continuationValidator.beforePersistence()
        try persistCompletion(response, true)
    }

    private static func runAppleSuite(
        policy: ResourcePolicy,
        continuationValidator: ExecutionContinuationValidator,
        onProgress: @escaping (String) -> Void
    ) async throws -> ProviderQualificationSnapshot {
        try continuationValidator.requireCurrent()
        guard ProviderRuntimeCapabilities.appleModel == .available else {
            throw SandboxError.blocked("APPLE_INTELLIGENCE_UNAVAILABLE_FOR_QUALIFICATION")
        }
        guard !qualificationActive else {
            throw SandboxError.blocked("ANOTHER_PROVIDER_QUALIFICATION_IS_ACTIVE")
        }
        guard !AgentRunner.shared.running else { throw SandboxError.blocked("ANOTHER_RUN_IS_ACTIVE") }
        if let session = ShortcutCoordinator.shared.current(), ["awaiting_response", "applying"].contains(session.phase) {
            throw SandboxError.blocked("FINISH_PENDING_APP_HANDOFF_FIRST")
        }
        appleSuiteRunning = true
        defer { appleSuiteRunning = false }
        let suiteDate = Date()
        var ledger = try load(now: suiteDate)
        let currentEpoch = epochSHA256(provider: .apple, adapter: nil)
        let retainedAttempts = retainingCurrentAppleTransportEvidence(ledger.attempts, currentEpoch: currentEpoch)
        if retainedAttempts.count != ledger.attempts.count {
            ledger.attempts = retainedAttempts
            if ledger.recommendation?.provider == .apple { ledger.recommendation = nil }
            try continuationValidator.beforePersistence()
            try save(ledger)
            onProgress("Removed obsolete Apple transport evidence; running a fresh App Intent suite.")
        }
        let currentAttempts = ledger.attempts.filter { $0.epochSHA256 == currentEpoch }
        let recordedToday = recordedProbes(provider: .apple, onUTCDate: suiteDate, attempts: ledger.attempts)
        let recordedForCurrentEpoch = recordedProbes(provider: .apple, onUTCDate: suiteDate, attempts: currentAttempts)
        guard recordedToday == recordedForCurrentEpoch else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_DAILY_SUITE_ALREADY_RECORDED")
        }
        let completedToday = recordedProbes(
            provider: .apple,
            onUTCDate: suiteDate,
            attempts: currentAttempts,
            completedOnly: true
        )
        if completedToday.count == ProviderQualificationSnapshot.requiredSamples {
            guard let snapshot = try snapshots(now: suiteDate)[.apple] else {
                throw SandboxError.blocked("APPLE_QUALIFICATION_DID_NOT_RECORD")
            }
            onProgress("Apple checks already recorded today.")
            try continuationValidator.requireCurrent()
            return snapshot
        }
        for index in completedToday.count..<ProviderQualificationSnapshot.requiredSamples {
            let attemptDate = Date()
            guard utcDayNumber(for: attemptDate) == utcDayNumber(for: suiteDate) else {
                throw SandboxError.blocked("APPLE_QUALIFICATION_UTC_DAY_CHANGED")
            }
            try Task.checkCancellation()
            try continuationValidator.beforePersistence()
            let challenge = try begin(provider: .apple, contextCharacters: min(policy.contextChars, ProviderQualificationSnapshot.appleMaximumContextCharacters), appIntentTransportObserved: true, withinAppleSuite: true, now: attemptDate)
            onProgress("Apple check \(index + 1) of \(ProviderQualificationSnapshot.requiredSamples): \(challenge.probe.rawValue)")
            try await performAppleQualificationProbe(
                continuationValidator: continuationValidator,
                providerResponse: {
                    try await AppleProvider().qualificationResponse(prompt: challenge.prompt)
                },
                persistCompletion: { response, appIntentTransportObserved in
                    _ = try complete(
                        attemptID: challenge.attemptID,
                        provider: .apple,
                        response: response,
                        appIntentTransportObserved: appIntentTransportObserved,
                        withinAppleSuite: true
                    )
                }
            )
        }
        guard let snapshot = try snapshots()[.apple] else {
            throw SandboxError.blocked("APPLE_QUALIFICATION_DID_NOT_RECORD")
        }
        try continuationValidator.requireCurrent()
        return snapshot
    }

    private static func challengeToken(epoch: String, provider: AppProvider, probe: ProviderQualificationProbe, attemptID: String) throws -> String {
        let message = "suite=\(suiteVersion)|epoch=\(epoch)|provider=\(provider.rawValue)|probe=\(probe.rawValue)|attempt=\(attemptID)"
        let code = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: try signingKey())
        return Data(code).map { String(format: "%02x", $0) }.joined().prefix(24).description
    }

    private static func reconcilePersistedCompletions(_ ledger: inout ProviderQualificationLedgerPayload) throws {
        for provider in AppProvider.allCases where provider != .apple {
            let adapter = AdapterSettings.get(provider)
            let expectedAdapter = adapterSHA256(adapter)
            let expectedEpoch = epochSHA256(provider: provider, adapter: adapter)
            let indices = ledger.attempts.indices.filter { index in
                let attempt = ledger.attempts[index]
                return attempt.provider == provider &&
                    attempt.outcome == .verified &&
                    attempt.adapterStateReconciled != true &&
                    attempt.epochSHA256 == expectedEpoch &&
                    attempt.adapterSHA256 == expectedAdapter
            }
            for index in indices {
                _ = try persistAndReconcileCompletion(
                    ledger: &ledger,
                    index: index,
                    completedAttempt: nil,
                    expectedEpochSHA256: expectedEpoch,
                    expectedAdapterSHA256: expectedAdapter,
                    saveLedger: { try save($0) },
                    markMeasuredRoundTrip: { try AdapterSettings.markMeasuredRoundTrip(for: $0) },
                    readAdapter: { AdapterSettings.get($0) }
                )
            }
        }
    }

    private static func load(now: Date) throws -> ProviderQualificationLedgerPayload {
        let url = try ledgerURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return .empty }
        let bytes = try Data(contentsOf: url, options: [.mappedIfSafe])
        var payload = try decodeAuthenticatedLedger(bytes, key: try signingKey(), now: now)
        let previousSchemaVersion = payload.schemaVersion
        payload = try payload.upgradedToCurrentSchema()
        var changed = payload.schemaVersion != previousSchemaVersion
        for index in payload.attempts.indices where payload.attempts[index].outcome == .started && now.timeIntervalSince(payload.attempts[index].startedAt) > pendingTimeoutSeconds {
            payload.attempts[index].outcome = .timedOut
            payload.attempts[index].setAdapterStateReconciled(true)
            payload.attempts[index].finishedAt = payload.attempts[index].startedAt.addingTimeInterval(pendingTimeoutSeconds)
            payload.attempts[index].durationBucketMilliseconds = durationBucket(milliseconds: pendingTimeoutSeconds * 1_000)
            changed = true
        }
        if changed { try save(payload) }
        return payload
    }

    static func decodeAuthenticatedLedger(
        _ bytes: Data,
        key: SymmetricKey,
        now: Date
    ) throws -> ProviderQualificationLedgerPayload {
        guard bytes.count <= 512_000 else { throw SandboxError.blocked("PROVIDER_QUALIFICATION_LEDGER_TOO_LARGE") }
        let signed = try StrictJSON.decode(SignedProviderQualificationLedger.self, from: bytes, limits: .qualificationLedger)
        let payload = try signed.payload.validated()
        let canonical = try JSONEncoder.sorted.encode(payload)
        let expected = hmac(canonical, key: key)
        guard constantTimeEqual(expected, signed.hmacSHA256) else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_LEDGER_INTEGRITY_FAILED")
        }
        guard !hasMaterialClockRollback(now: now, attempts: payload.attempts) else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_CLOCK_ROLLBACK_DETECTED")
        }
        return payload
    }

    private static func save(_ payload: ProviderQualificationLedgerPayload) throws {
        let valid = try payload.validated()
        let canonical = try JSONEncoder.sorted.encode(valid)
        let signed = SignedProviderQualificationLedger(payload: valid, hmacSHA256: hmac(canonical, key: try signingKey()))
        let bytes = try JSONEncoder.sorted.encode(signed)
        let url = try ledgerURL()
        try writeLedgerBytes(bytes, url)
    }

    static var writeLedgerBytes: @MainActor (Data, URL) throws -> Void = { bytes, url in
        try bytes.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        guard try Data(contentsOf: url) == bytes else { throw SandboxError.conflict("PROVIDER_QUALIFICATION_LEDGER_READBACK_FAILED") }
    }

    private static func removeLedgerChecked() throws {
        let url = try ledgerURL()
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        guard !FileManager.default.fileExists(atPath: url.path) else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_LEDGER_DELETE_FAILED")
        }
    }

    private static func trim(_ ledger: inout ProviderQualificationLedgerPayload) {
        if ledger.attempts.count > maximumStoredAttempts {
            ledger.attempts = Array(ledger.attempts.sorted { $0.startedAt < $1.startedAt }.suffix(maximumStoredAttempts))
        }
    }

    static var ledgerDirectory: @MainActor () throws -> URL = {
        try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("LocalSandboxPrivateRouting", isDirectory: true)
    }

    private static func ledgerURL() throws -> URL {
        let directory = try ledgerDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        return directory.appendingPathComponent("provider-qualification-ledger.json")
    }

    static func resolveSigningKey(using operations: ProviderQualificationSigningKeyOperations) throws -> SymmetricKey {
        if let encoded = try operations.readChecked() {
            guard let bytes = Data(base64Encoded: encoded), bytes.count == 32 else {
                throw SandboxError.blocked("PROVIDER_QUALIFICATION_SIGNING_KEY_INVALID")
            }
            return SymmetricKey(data: bytes)
        }
        let generated = try operations.generateRandomBytes()
        guard generated.count == 32 else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_KEY_GENERATION_FAILED")
        }
        try operations.writeChecked(generated.base64EncodedString())
        guard let encoded = try operations.readChecked(),
              let stored = Data(base64Encoded: encoded),
              stored.count == 32,
              stored == generated else {
            throw SandboxError.blocked("PROVIDER_QUALIFICATION_SIGNING_KEY_READBACK_FAILED")
        }
        return SymmetricKey(data: stored)
    }

    private static func signingKey() throws -> SymmetricKey {
        try resolveSigningKey(using: ProviderQualificationSigningKeyOperations(
            readChecked: { try Keychain.getChecked(ledgerKeyName) },
            generateRandomBytes: {
                var bytes = Data(count: 32)
                let status = bytes.withUnsafeMutableBytes { buffer in
                    SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
                }
                guard status == errSecSuccess else {
                    throw SandboxError.blocked("PROVIDER_QUALIFICATION_KEY_GENERATION_FAILED")
                }
                return bytes
            },
            writeChecked: { try Keychain.set($0, for: ledgerKeyName) }
        ))
    }

    private static func hmac(_ data: Data, key: SymmetricKey) -> String {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: key)).map { String(format: "%02x", $0) }.joined()
    }

    private static func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8), right = Array(rhs.utf8)
        guard left.count == right.count else { return false }
        return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    private static func durationBucket(milliseconds: Double) -> Int {
        min(300_000, max(fixedDurationBucket, Int((milliseconds + Double(fixedDurationBucket - 1)) / Double(fixedDurationBucket)) * fixedDurationBucket))
    }

    private static func machineIdentifier() -> String {
        var system = utsname()
        uname(&system)
        let capacity = MemoryLayout.size(ofValue: system.machine)
        return withUnsafePointer(to: &system.machine) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: capacity) { String(cString: $0) }
        }
    }
}
