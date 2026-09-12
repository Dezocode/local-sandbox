import CryptoKit
import Foundation

enum SandboxFolder: String, CaseIterable {
    case workspace, config, state, logs, output
}

enum NativeToolOperation {
    case read(SandboxPath)
    case list(SandboxFolder)
    case create(path: SandboxPath, content: String)
    case append(path: SandboxPath, content: String, expectedSHA256: String)
    case patch(path: SandboxPath, old: String, replacement: String, expectedSHA256: String)
    case clipboardGet
    case clipboardSet(String)
    case notify(String)

    var tool: ToolName {
        switch self {
        case .read: return .read
        case .list: return .list
        case .create: return .create
        case .append: return .append
        case .patch: return .patch
        case .clipboardGet: return .clipboardGet
        case .clipboardSet: return .clipboardSet
        case .notify: return .notify
        }
    }

    static func parse(_ raw: ToolCall, authorizedRead: ToolEvidence?) throws -> (ToolCall, NativeToolOperation) {
        let call = try raw.validated()
        let args = call.arguments
        let operation: NativeToolOperation
        switch call.tool {
        case .read:
            operation = .read(try SandboxPath(args["path"] ?? ""))
        case .list:
            guard let folder = SandboxFolder(rawValue: args["path"] ?? "") else {
                throw SandboxError.invalid("INVALID_FOLDER")
            }
            operation = .list(folder)
        case .create:
            operation = .create(
                path: try writablePath(args["path"] ?? ""),
                content: args["content"] ?? ""
            )
        case .append:
            let path = try writablePath(args["path"] ?? "")
            let expected = args["expectedSHA256"] ?? ""
            try requireAuthorizedRead(path: path, expectedSHA256: expected, evidence: authorizedRead)
            operation = .append(path: path, content: args["content"] ?? "", expectedSHA256: expected)
        case .patch:
            let path = try writablePath(args["path"] ?? "")
            let expected = args["expectedSHA256"] ?? ""
            try requireAuthorizedRead(path: path, expectedSHA256: expected, evidence: authorizedRead)
            operation = .patch(
                path: path,
                old: args["old"] ?? "",
                replacement: args["replacement"] ?? "",
                expectedSHA256: expected
            )
        case .clipboardGet:
            operation = .clipboardGet
        case .clipboardSet:
            operation = .clipboardSet(args["content"] ?? "")
        case .notify:
            operation = .notify(args["content"] ?? "")
        }
        return (call, operation)
    }

    private static func writablePath(_ raw: String) throws -> SandboxPath {
        let path = try SandboxPath(raw)
        guard path.value.hasPrefix("workspace/") || path.value.hasPrefix("output/") else {
            throw SandboxError.blocked("MODEL_WRITES_REQUIRE_WORKSPACE_OR_OUTPUT")
        }
        return path
    }

    private static func requireAuthorizedRead(path: SandboxPath, expectedSHA256: String, evidence: ToolEvidence?) throws {
        guard evidence?.path == path.value,
              evidence?.sha256 == expectedSHA256,
              evidence?.contentComplete == true else {
            throw SandboxError.blocked("EDIT_REQUIRES_COMPLETE_FRESH_READ")
        }
    }
}

@MainActor
protocol ToolFileStorage: AnyObject {
    func read(_ path: SandboxPath) throws -> String
    func list(_ folder: String) throws -> [String]
    func exists(_ path: SandboxPath) throws -> Bool
    func write(_ path: SandboxPath, content: String, createOnly: Bool, expectedSHA256: String?) throws
}

struct PreparedToolCall {
    let operation: NativeToolOperation
    fileprivate let fingerprint: String
    fileprivate let journalPath: SandboxPath
}

enum PreparedToolExecution {
    case cached(ToolResult)
    case ready(PreparedToolCall)
}

@MainActor
struct NativeToolExecutor<Storage: ToolFileStorage> {
    private enum JournalPhase: String, Codable { case pending, done }

    private struct Journal: Codable {
        let fingerprint: String
        let phase: JournalPhase
        let result: ToolResult?

        private enum CodingKeys: String, CodingKey {
            case recordType, schemaVersion, fingerprint, phase, result
        }

        init(fingerprint: String, phase: JournalPhase, result: ToolResult?) {
            self.fingerprint = fingerprint
            self.phase = phase
            self.result = result
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0
            guard version <= 1 else { throw SandboxError.invalid("UNSUPPORTED_CALL_JOURNAL_VERSION") }
            if let recordType = try container.decodeIfPresent(String.self, forKey: .recordType), recordType != "call-journal" {
                throw SandboxError.invalid("WRONG_CALL_JOURNAL_RECORD_TYPE")
            }
            fingerprint = try container.decode(String.self, forKey: .fingerprint)
            phase = try container.decode(JournalPhase.self, forKey: .phase)
            result = try container.decodeIfPresent(ToolResult.self, forKey: .result)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode("call-journal", forKey: .recordType)
            try container.encode(1, forKey: .schemaVersion)
            try container.encode(fingerprint, forKey: .fingerprint)
            try container.encode(phase, forKey: .phase)
            try container.encodeIfPresent(result, forKey: .result)
        }
    }

    private let storage: Storage

    init(storage: Storage) {
        self.storage = storage
    }

    func prepare(_ raw: ToolCall, callID: String, authorizedRead: ToolEvidence? = nil) throws -> PreparedToolExecution {
        let (call, operation) = try NativeToolOperation.parse(raw, authorizedRead: authorizedRead)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let fingerprint = NativeDigest.sha256(String(decoding: try encoder.encode(call), as: UTF8.self))
        let journalPath = try SandboxPath("logs/call-\(NativeDigest.sha256(callID)).json")

        if try storage.exists(journalPath) {
            let existing: Journal
            do {
                existing = try decodeJournal(at: journalPath)
            } catch {
                throw SandboxError.blocked("CORRUPT_CALL_JOURNAL_REQUIRES_READBACK")
            }
            guard existing.fingerprint == fingerprint else {
                throw SandboxError.conflict("CALL_ID_REUSED_WITH_DIFFERENT_ARGUMENTS")
            }
            if existing.phase == .done, let result = existing.result {
                return .cached(result)
            }
            throw SandboxError.blocked("UNCERTAIN_PRIOR_CALL_REQUIRES_READBACK")
        }

        try writeJournal(
            Journal(fingerprint: fingerprint, phase: .pending, result: nil),
            at: journalPath,
            createOnly: true
        )
        return .ready(PreparedToolCall(operation: operation, fingerprint: fingerprint, journalPath: journalPath))
    }

    func performFile(_ prepared: PreparedToolCall, callID: String) throws -> ToolResult {
        let result: String
        let digest: String?
        let evidence: ToolEvidence?

        switch prepared.operation {
        case .read(let path):
            let content = try storage.read(path)
            guard content.count <= 8_000 else {
                throw SandboxError.invalid("READ_TOO_LARGE: Use a smaller source file before editing.")
            }
            result = content
            digest = NativeDigest.sha256(content)
            evidence = ToolEvidence(
                path: path.value,
                sha256: digest,
                byteCount: content.utf8.count,
                readbackKind: "source-read",
                contentComplete: true
            )
        case .list(let folder):
            result = try storage.list(folder.rawValue).joined(separator: "\n")
            digest = nil
            evidence = ToolEvidence(
                path: folder.rawValue,
                sha256: NativeDigest.sha256(result),
                byteCount: result.utf8.count,
                readbackKind: "directory-list",
                contentComplete: true
            )
        case .create(let path, let content):
            try storage.write(path, content: content, createOnly: true, expectedSHA256: nil)
            result = "Readback verified: \(path.value). \(content.utf8.count) bytes."
            digest = NativeDigest.sha256(content)
            evidence = ToolEvidence(path: path.value, sha256: digest, byteCount: content.utf8.count, readbackKind: "write-readback", contentComplete: true)
        case .append(let path, let appended, let expectedSHA256):
            let before = try storage.read(path)
            guard NativeDigest.sha256(before) == expectedSHA256 else {
                throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED")
            }
            try storage.write(
                try SandboxPath("output/backup-\(NativeDigest.sha256(callID)).txt"),
                content: before,
                createOnly: true,
                expectedSHA256: nil
            )
            let content = before + appended
            try storage.write(path, content: content, createOnly: false, expectedSHA256: expectedSHA256)
            result = "Readback verified: \(path.value). \(content.utf8.count) bytes."
            digest = NativeDigest.sha256(content)
            evidence = ToolEvidence(path: path.value, sha256: digest, byteCount: content.utf8.count, readbackKind: "write-readback", contentComplete: true)
        case .patch(let path, let old, let replacement, let expectedSHA256):
            let before = try storage.read(path)
            guard NativeDigest.sha256(before) == expectedSHA256 else {
                throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED")
            }
            try storage.write(
                try SandboxPath("output/backup-\(NativeDigest.sha256(callID)).txt"),
                content: before,
                createOnly: true,
                expectedSHA256: nil
            )
            let content = try exactPatch(before, old: old, replacement: replacement)
            try storage.write(path, content: content, createOnly: false, expectedSHA256: expectedSHA256)
            result = "Readback verified: \(path.value). \(content.utf8.count) bytes."
            digest = NativeDigest.sha256(content)
            evidence = ToolEvidence(path: path.value, sha256: digest, byteCount: content.utf8.count, readbackKind: "write-readback", contentComplete: true)
        case .clipboardGet, .clipboardSet, .notify:
            throw SandboxError.invalid("NOT_A_FILE_TOOL")
        }

        return ToolResult(
            ok: true,
            tool: prepared.operation.tool.rawValue,
            result: result,
            sha256: digest,
            error_code: nil,
            evidence: evidence
        )
    }

    func complete(_ prepared: PreparedToolCall, result: ToolResult) throws {
        let existing: Journal
        do {
            existing = try decodeJournal(at: prepared.journalPath)
        } catch {
            throw SandboxError.blocked("CORRUPT_CALL_JOURNAL_REQUIRES_READBACK")
        }
        guard existing.fingerprint == prepared.fingerprint, existing.phase == .pending, existing.result == nil else {
            throw SandboxError.blocked("CALL_JOURNAL_CHANGED_REQUIRES_READBACK")
        }
        try writeJournal(
            Journal(fingerprint: prepared.fingerprint, phase: .done, result: result),
            at: prepared.journalPath,
            createOnly: false
        )
    }

    func executeFile(_ raw: ToolCall, callID: String, authorizedRead: ToolEvidence? = nil) throws -> ToolResult {
        switch try prepare(raw, callID: callID, authorizedRead: authorizedRead) {
        case .cached(let result):
            return result
        case .ready(let prepared):
            let result = try performFile(prepared, callID: callID)
            try complete(prepared, result: result)
            return result
        }
    }

    private func decodeJournal(at path: SandboxPath) throws -> Journal {
        try JSONDecoder().decode(Journal.self, from: Data(storage.read(path).utf8))
    }

    private func writeJournal(_ journal: Journal, at path: SandboxPath, createOnly: Bool) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try storage.write(
            path,
            content: String(decoding: try encoder.encode(journal), as: UTF8.self),
            createOnly: createOnly,
            expectedSHA256: nil
        )
    }
}

struct ShortcutSession: Codable {
    var id: String
    var goal: String
    var policy: ResourcePolicy
    var started: Date
    var initialBattery: Int?
    var step = 0
    var failures = 0
    var repeated = 0
    var lastFailure = ""
    var latest = "No actions executed."
    var phase = "awaiting_response"
    var trace: [TraceEntry] = []
    var lastResponseHash = ""
    var contract: GoalContract?
    var latestResult: ToolResult?
    var lastReadEvidence: ToolEvidence?
    var authorizationPolicy: ResourcePolicy
    var providerSelection: ProviderSelection
    var taskOrigin: ProviderTaskOrigin
    var shortcutAdapterName: String
    var routingEvidence: ProviderRoutingEvidence

    init(
        id: String,
        goal: String,
        policy: ResourcePolicy,
        authorizationPolicy: ResourcePolicy,
        started: Date,
        initialBattery: Int?,
        contract: GoalContract? = nil,
        providerSelection: ProviderSelection = .saved,
        taskOrigin: ProviderTaskOrigin = .app,
        shortcutAdapterName: String,
        routingEvidence: ProviderRoutingEvidence
    ) {
        self.id = id
        self.goal = goal
        self.policy = policy
        self.authorizationPolicy = authorizationPolicy
        self.started = started
        self.initialBattery = initialBattery
        self.contract = contract
        self.providerSelection = providerSelection
        self.taskOrigin = taskOrigin
        self.shortcutAdapterName = shortcutAdapterName
        self.routingEvidence = routingEvidence
    }

    mutating func beginDistinctResponse(_ response: String) throws -> Int? {
        try AgentAction.requireBoundedResponse(response)
        let responseHash = NativeDigest.sha256(response)
        guard lastResponseHash != responseHash else { return nil }
        let actionIndex = step
        step += 1
        lastResponseHash = responseHash
        return actionIndex
    }

    mutating func recordSuccessfulResponse() {
        lastFailure = ""
        repeated = 0
    }

    mutating func recordFailedResponse(_ message: String) {
        failures += 1
        repeated = message == lastFailure ? repeated + 1 : 1
        lastFailure = message
        lastReadEvidence = nil
        latest = "Action failed: \(message). Read current state before proposing a repair."
        trace.append(.receiptError(tool: "app.response", message: message))
    }

    func authorizationMatches(_ current: ResourcePolicy) -> Bool {
        current == authorizationPolicy
    }

    var requiresLegacyRestart: Bool {
        shortcutAdapterName.isEmpty ||
            routingEvidence.deviceProfileSHA256 == String(repeating: "0", count: 64) ||
            routingEvidence.configurationSHA256 == String(repeating: "0", count: 64)
    }

    private func validate(allowLegacyAdapter: Bool = false, allowLegacyRouteEvidence: Bool = false) throws {
        let validatedPolicy = try policy.validated()
        let validatedAuthorization = try authorizationPolicy.validated()
        var expectedResolvedPolicy = validatedAuthorization
        expectedResolvedPolicy.provider = validatedPolicy.provider
        let validPhase = phase == "awaiting_response" || phase == "applying" || RunStatus(rawValue: phase) != nil
        let validResponseHash = lastResponseHash.isEmpty || lastResponseHash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
        guard (1...100).contains(id.count),
              !goal.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              goal.count <= 2_000,
              started.timeIntervalSinceReferenceDate.isFinite,
              initialBattery == nil || (0...100).contains(initialBattery!),
              (0...validatedPolicy.maxSteps).contains(step),
              (0...validatedPolicy.maxFailures).contains(failures),
              failures <= step,
              (0...min(2, failures)).contains(repeated),
              (repeated == 0) == lastFailure.isEmpty,
              lastFailure.count <= 1_000,
              latest.count <= 16_000,
              validPhase,
              trace.count <= 100,
              validResponseHash else {
            throw SandboxError.invalid("INVALID_SHORTCUT_SESSION_STATE")
        }
        guard validatedPolicy == expectedResolvedPolicy,
              routingEvidence.provider.rawValue == validatedPolicy.provider,
              routingEvidence.selection == providerSelection,
              routingEvidence.provider != .apple,
              taskOrigin != .appIntent || routingEvidence.appIntentReturnObserved,
              providerSelection != .saved || validatedPolicy.provider == validatedAuthorization.provider,
              !routingEvidence.provider.usesCloud || validatedAuthorization.cloudAllowed else {
            throw SandboxError.invalid("SHORTCUT_SESSION_ROUTING_EVIDENCE_MISMATCH")
        }
        guard allowLegacyAdapter || (!shortcutAdapterName.isEmpty && shortcutAdapterName.count <= 80 && !shortcutAdapterName.contains("\n") && !shortcutAdapterName.contains("\r")) else {
            throw SandboxError.invalid("INVALID_SHORTCUT_SESSION_ADAPTER")
        }
        guard allowLegacyRouteEvidence || !requiresLegacyRestart else {
            throw SandboxError.invalid("SHORTCUT_SESSION_ROUTING_EVIDENCE_MISMATCH")
        }
        if let lastReadEvidence {
            guard latestResult?.tool == ToolName.read.rawValue,
                  latestResult?.evidence == lastReadEvidence,
                  lastReadEvidence.contentComplete else {
                throw SandboxError.invalid("INVALID_SHORTCUT_SESSION_READ_EVIDENCE")
            }
        }
    }

    private enum CodingKeys: String, CodingKey {
        case recordType, schemaVersion, id, goal, policy, started, initialBattery, step, failures, repeated
        case lastFailure, latest, phase, trace, lastResponseHash, contract, latestResult, lastReadEvidence
        case authorizationPolicy, providerSelection, taskOrigin, shortcutAdapterName, routingEvidence
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0
        guard version <= 4 else { throw SandboxError.invalid("UNSUPPORTED_SHORTCUT_SESSION_VERSION") }
        if let recordType = try container.decodeIfPresent(String.self, forKey: .recordType), recordType != "shortcut-session" {
            throw SandboxError.invalid("WRONG_SHORTCUT_SESSION_RECORD_TYPE")
        }
        id = try container.decode(String.self, forKey: .id)
        goal = try container.decode(String.self, forKey: .goal)
        policy = try container.decode(ResourcePolicy.self, forKey: .policy)
        started = try container.decode(Date.self, forKey: .started)
        initialBattery = try container.decodeIfPresent(Int.self, forKey: .initialBattery)
        step = try container.decodeIfPresent(Int.self, forKey: .step) ?? 0
        failures = try container.decodeIfPresent(Int.self, forKey: .failures) ?? 0
        repeated = try container.decodeIfPresent(Int.self, forKey: .repeated) ?? 0
        lastFailure = try container.decodeIfPresent(String.self, forKey: .lastFailure) ?? ""
        latest = try container.decodeIfPresent(String.self, forKey: .latest) ?? "No actions executed."
        phase = try container.decodeIfPresent(String.self, forKey: .phase) ?? "awaiting_response"
        trace = try container.decodeIfPresent([TraceEntry].self, forKey: .trace) ?? []
        lastResponseHash = try container.decodeIfPresent(String.self, forKey: .lastResponseHash) ?? ""
        contract = try container.decodeIfPresent(GoalContract.self, forKey: .contract)
        latestResult = try container.decodeIfPresent(ToolResult.self, forKey: .latestResult)
        lastReadEvidence = try container.decodeIfPresent(ToolEvidence.self, forKey: .lastReadEvidence)
        authorizationPolicy = try container.decodeIfPresent(ResourcePolicy.self, forKey: .authorizationPolicy) ?? policy
        providerSelection = try container.decodeIfPresent(ProviderSelection.self, forKey: .providerSelection) ?? .saved
        taskOrigin = try container.decodeIfPresent(ProviderTaskOrigin.self, forKey: .taskOrigin) ?? .app
        if version >= 3 {
            let decodedAdapterName = try container.decode(String.self, forKey: .shortcutAdapterName)
            guard !decodedAdapterName.isEmpty,
                  decodedAdapterName.count <= 80,
                  !decodedAdapterName.contains("\n") && !decodedAdapterName.contains("\r") else {
                throw SandboxError.invalid("INVALID_SHORTCUT_SESSION_ADAPTER")
            }
            shortcutAdapterName = decodedAdapterName
        } else {
            shortcutAdapterName = ""
        }
        if version >= 4 {
            routingEvidence = try container.decode(ProviderRoutingEvidence.self, forKey: .routingEvidence)
        } else {
            routingEvidence = ProviderRoutingEvidence(
                selection: providerSelection,
                provider: AppProvider(rawValue: policy.provider) ?? .local,
                authorizedProvider: AppProvider(rawValue: authorizationPolicy.provider) ?? .local,
                strategy: providerSelection == .saved ? .savedPinned : providerSelection == .bestLocal ? .bestLocalColdStart : .explicitPinned,
                activity: .workspaceIdle,
                accessEvidence: .configuredUnmeasured,
                deviceProfileSHA256: String(repeating: "0", count: 64),
                configurationSHA256: String(repeating: "0", count: 64),
                qualification: nil
            )
        }
        try validate(allowLegacyAdapter: version < 3, allowLegacyRouteEvidence: version < 4)
    }

    func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("shortcut-session", forKey: .recordType)
        try container.encode(4, forKey: .schemaVersion)
        try container.encode(id, forKey: .id)
        try container.encode(goal, forKey: .goal)
        try container.encode(policy, forKey: .policy)
        try container.encode(started, forKey: .started)
        try container.encodeIfPresent(initialBattery, forKey: .initialBattery)
        try container.encode(step, forKey: .step)
        try container.encode(failures, forKey: .failures)
        try container.encode(repeated, forKey: .repeated)
        try container.encode(lastFailure, forKey: .lastFailure)
        try container.encode(latest, forKey: .latest)
        try container.encode(phase, forKey: .phase)
        try container.encode(trace, forKey: .trace)
        try container.encode(lastResponseHash, forKey: .lastResponseHash)
        try container.encodeIfPresent(contract, forKey: .contract)
        try container.encodeIfPresent(latestResult, forKey: .latestResult)
        try container.encodeIfPresent(lastReadEvidence, forKey: .lastReadEvidence)
        try container.encode(authorizationPolicy, forKey: .authorizationPolicy)
        try container.encode(providerSelection, forKey: .providerSelection)
        try container.encode(taskOrigin, forKey: .taskOrigin)
        try container.encode(shortcutAdapterName, forKey: .shortcutAdapterName)
        try container.encode(routingEvidence, forKey: .routingEvidence)
    }
}
