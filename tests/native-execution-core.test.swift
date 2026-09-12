import Foundation

@MainActor
private final class MemoryToolStorage: ToolFileStorage {
    private(set) var files: [String: String]
    private(set) var workspaceWrites = 0

    init(_ files: [String: String] = [:]) {
        self.files = files
    }

    func read(_ path: SandboxPath) throws -> String {
        guard let content = files[path.value] else {
            throw SandboxError.invalid("FILE_NOT_FOUND")
        }
        return content
    }

    func list(_ folder: String) throws -> [String] {
        guard SandboxFolder(rawValue: folder) != nil else {
            throw SandboxError.invalid("INVALID_FOLDER")
        }
        return files.keys.filter { $0.hasPrefix(folder + "/") }.sorted()
    }

    func exists(_ path: SandboxPath) throws -> Bool {
        files[path.value] != nil
    }

    func write(_ path: SandboxPath, content: String, createOnly: Bool, expectedSHA256: String?) throws {
        if createOnly && files[path.value] != nil {
            throw SandboxError.conflict("FILE_EXISTS")
        }
        if let expectedSHA256 {
            guard let current = files[path.value], NativeDigest.sha256(current) == expectedSHA256 else {
                throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED")
            }
        }
        files[path.value] = content
        if path.value.hasPrefix("workspace/") || path.value.hasPrefix("output/result-") {
            workspaceWrites += 1
        }
        guard files[path.value] == content else {
            throw SandboxError.conflict("READBACK_FAILED")
        }
    }

    func replaceOutOfBand(path: String, content: String) {
        files[path] = content
    }
}

@MainActor
private final class MutableContinuationState {
    var authorizationCurrent = true
    var routeCurrent = true
}

private actor HeldProviderResponse {
    private var responseContinuation: CheckedContinuation<String, Never>?
    private var heldWaiters: [CheckedContinuation<Void, Never>] = []

    func response() async -> String {
        await withCheckedContinuation { continuation in
            responseContinuation = continuation
            let waiters = heldWaiters
            heldWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
    }

    func waitUntilHeld() async {
        guard responseContinuation == nil else { return }
        await withCheckedContinuation { continuation in
            heldWaiters.append(continuation)
        }
    }

    func release(_ response: String) {
        guard let continuation = responseContinuation else {
            fatalError("provider response was not held")
        }
        responseContinuation = nil
        continuation.resume(returning: response)
    }
}

@MainActor
private final class DispatcherSideEffectRecorder {
    private(set) var count = 0

    func record() {
        count += 1
    }
}

@MainActor
private final class ShortcutContinuationEffectRecorder {
    private(set) var submittedExternalOperations = 0
    private(set) var dispatcherCompletions = 0
    private(set) var successfulResponses = 0
    private(set) var sessionWrites = 0
    private(set) var providerFailures = 0

    func recordExternalSubmission() { submittedExternalOperations += 1 }
    func recordDispatcherCompletion() { dispatcherCompletions += 1 }
    func recordSuccessfulResponse() { successfulResponses += 1 }
    func recordSessionWrite() { sessionWrites += 1 }
    func recordProviderFailure() { providerFailures += 1 }
}

@MainActor
private final class IntentBoundaryEffectRecorder {
    private(set) var protectedReads = 0
    private(set) var successfulCompletions = 0
    private(set) var failureAccounting = 0
    private(set) var terminalReturns = 0

    func recordProtectedRead() { protectedReads += 1 }
    func recordSuccessfulCompletion() { successfulCompletions += 1 }
    func recordFailureAccounting() { failureAccounting += 1 }
    func recordTerminalReturn() { terminalReturns += 1 }
}

@MainActor
@main
enum NativeExecutionCoreContractTests {
    static func main() async throws {
        try providerRouting()
        try measuredRouting()
        try continuationValidationAndRuntimeIdentity()
        try await validatedAwaitRejectsStaleEntryAndPreservesCurrentErrors()
        try await heldIntentAuthenticationCannotCrossLockFence()
        try await heldProviderResponseCannotCrossLockFence()
        try await heldShortcutContinuationCannotCrossLockFence()
        try await heldQualificationFailureCannotCrossLockFence()
        try strictJSONContracts()
        try providerQualificationVerifier()
        try providerHandoffTelemetry()
        try appIntentOutputEnvelope()
        try createReadPatchReadback()
        try traversalAndOverwriteRejection()
        try staleAndAmbiguousPatchRejection()
        try journalRecoveryRules()
        try explicitProviderSessionAuthorizationAndTimeline()
        try distinctResponseAccounting()
        print("Native execution core contracts passed: deterministic measured routing, five provider probes, Siri payload loop, hash-only handoff telemetry, file readback, confinement, mutation guards, journal recovery, and distinct-response accounting.")
    }

    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func expectError(_ expected: String, _ operation: () throws -> Void) throws {
        do {
            try operation()
            fatalError("Expected \(expected)")
        } catch let error as SandboxError {
            require(error.localizedDescription == expected, "Expected \(expected), got \(error.localizedDescription)")
        }
    }

    static func call(_ tool: ToolName, _ arguments: [String: String]) -> ToolCall {
        ToolCall(tool: tool, arguments: arguments)
    }

    static func qualifiedExternalEvidence(selection: ProviderSelection, provider: AppProvider) -> ProviderRoutingEvidence {
        ProviderRoutingEvidence(
            selection: selection,
            provider: provider,
            authorizedProvider: selection == .saved ? provider : .apple,
            strategy: selection == .saved ? .savedPinned : selection == .bestLocal ? .bestLocalMeasured : .explicitPinned,
            activity: .workspaceIdle,
            accessEvidence: .recentLocallyValidatedResponse,
            deviceProfileSHA256: String(repeating: "d", count: 64),
            configurationSHA256: String(repeating: "e", count: 64),
            qualification: qualification(provider, verified: 5, assertions: 5, latency: 500)
        )
    }

    static func qualification(
        _ provider: AppProvider,
        verified: Int,
        assertions: Int,
        latency: Int,
        schemaPasses: Int? = nil,
        context: Int = 6_000,
        appIntentReturnObserved: Bool = true,
        faultCount: Int = 0
    ) -> ProviderQualificationSnapshot {
        ProviderQualificationSnapshot(
            provider: provider,
            epochSHA256: String(repeating: provider == .apple ? "a" : "b", count: 64),
            adapterSHA256: provider == .apple ? nil : String(repeating: "c", count: 64),
            sampleCount: 5,
            distinctProbeCount: 5,
            verifiedCount: verified,
            schemaPassCount: schemaPasses ?? verified,
            assertionPassCount: assertions,
            assertionCount: 5,
            toolProbePassCount: 3,
            maximumContextCharacters: context,
            medianDurationBucketMilliseconds: latency,
            integrityFaultCount: faultCount,
            appIntentReturnObserved: appIntentReturnObserved,
            lastSuccessfulAt: "2026-09-11T00:00:00Z"
        )
    }

    static func appIntentOutputEnvelope() throws {
        let decoder = JSONDecoder()
        let prompt = AppIntentTaskOutput.providerHandoffPrompt(
            provider: .chatgpt,
            selection: .chatgpt,
            adapterName: "My ChatGPT action",
            payload: "provider prompt"
        )
        let promptJSON = try prompt.json
        let decodedPrompt = try decoder.decode(AppIntentTaskOutput.self, from: Data(promptJSON.utf8))
        require(decodedPrompt == prompt, "provider handoff output did not round-trip")
        require(decodedPrompt.kind == .providerHandoffPrompt && decodedPrompt.decision == .appShortcut && decodedPrompt.phase == "awaiting_response", "provider handoff output lost its route decision or loop phase")
        require(decodedPrompt.provider == .chatgpt && decodedPrompt.selection == .chatgpt, "provider handoff output lost its resolved route")
        require(decodedPrompt.adapterName == "My ChatGPT action", "provider handoff output lost the configured adapter")
        let beginDictionary = try JSONSerialization.jsonObject(with: Data(promptJSON.utf8)) as! [String: Any]
        require(beginDictionary["payload"] as? String == "provider prompt", "personal Shortcut could not extract the provider input from payload")
        require(beginDictionary["prompt"] == nil && beginDictionary["receipt"] == nil, "schema v1 invented prompt or receipt keys outside payload")

        let rawProviderAction = "{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}"
        let applyContinuation = AppIntentTaskOutput.providerHandoffPrompt(
            provider: .chatgpt,
            selection: .chatgpt,
            adapterName: "My ChatGPT action",
            payload: "next provider prompt"
        )
        let applyDictionary = try JSONSerialization.jsonObject(with: Data(try applyContinuation.json.utf8)) as! [String: Any]
        require(rawProviderAction.hasPrefix("{\"kind\":"), "provider action response was not raw action JSON for Apply Validated Action")
        require(applyDictionary["phase"] as? String == "awaiting_response", "Apply envelope did not preserve the loop decision")
        require(applyDictionary["payload"] as? String == "next provider prompt", "personal Shortcut could not extract the next provider input from Apply payload")

        let apple = AppIntentTaskOutput.terminalAppleReceipt(selection: .bestLocal, phase: .verified, payload: "{\"status\":\"verified\"}")
        let appleJSON = try apple.json
        let decodedApple = try decoder.decode(AppIntentTaskOutput.self, from: Data(appleJSON.utf8))
        require(decodedApple == apple, "terminal Apple output did not round-trip")
        require(decodedApple.kind == .terminalAppleReceipt && decodedApple.decision == .onDeviceApple && decodedApple.provider == .apple && decodedApple.adapterName == nil, "terminal Apple output lost its strict on-device decision")
        require(!appleJSON.contains("adapterName"), "terminal Apple output invented a Shortcut adapter")

        let terminalProvider = AppIntentTaskOutput.terminalProviderReceipt(
            provider: .local,
            selection: .bestLocal,
            adapterName: "Agent Step - Local",
            phase: .completed,
            payload: "{\"status\":\"completed\"}"
        )
        let terminalProviderJSON = try terminalProvider.json
        let decodedTerminalProvider = try decoder.decode(AppIntentTaskOutput.self, from: Data(terminalProviderJSON.utf8))
        require(decodedTerminalProvider == terminalProvider, "terminal provider output did not round-trip")
        require(decodedTerminalProvider.kind == .terminalProviderReceipt && decodedTerminalProvider.decision == .appShortcut && decodedTerminalProvider.provider == .local && decodedTerminalProvider.adapterName == "Agent Step - Local", "terminal provider output lost its strict Shortcut decision")
        let terminalDictionary = try JSONSerialization.jsonObject(with: Data(terminalProviderJSON.utf8)) as! [String: Any]
        require(terminalDictionary["phase"] as? String == "completed", "terminal provider envelope did not stop the Shortcut loop")
        require(terminalDictionary["payload"] as? String == "{\"status\":\"completed\"}", "terminal provider receipt was not retained in payload")

        var leaked = try JSONSerialization.jsonObject(with: Data(promptJSON.utf8)) as! [String: Any]
        leaked["credential"] = "must-not-cross"
        do {
            _ = try decoder.decode(AppIntentTaskOutput.self, from: JSONSerialization.data(withJSONObject: leaked))
            fatalError("App Intent output accepted a credential field")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_HANDOFF_OUTPUT", "credential field did not fail the strict output schema")
        }

        leaked.removeValue(forKey: "credential")
        leaked["decision"] = "on-device-apple"
        do {
            _ = try decoder.decode(AppIntentTaskOutput.self, from: JSONSerialization.data(withJSONObject: leaked))
            fatalError("provider handoff accepted an Apple decision")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_HANDOFF_OUTPUT", "mismatched decision returned the wrong error")
        }

        leaked["decision"] = "app-shortcut"
        leaked["schemaVersion"] = 2
        do {
            _ = try decoder.decode(AppIntentTaskOutput.self, from: JSONSerialization.data(withJSONObject: leaked))
            fatalError("App Intent output accepted a future schema")
        } catch let error as SandboxError {
            require(error.localizedDescription == "UNSUPPORTED_APP_INTENT_OUTPUT", "future output did not fail closed")
        }

        let mismatched = AppIntentTaskOutput.providerHandoffPrompt(
            provider: .claude,
            selection: .chatgpt,
            adapterName: "Wrong route",
            payload: "prompt"
        )
        do {
            _ = try mismatched.json
            fatalError("explicit provider selection accepted substitution")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_APP_INTENT_OUTPUT", "route substitution returned the wrong error")
        }
    }

    static func strictJSONContracts() throws {
        func rejects(_ text: String, limits: StrictJSONLimits = .providerResponse) -> Bool {
            do {
                try StrictJSON.validate(Data(text.utf8), limits: limits)
                return false
            } catch {
                return true
            }
        }

        let final = "{\"kind\":\"final\",\"summary\":\"done\"}"
        guard case .final(let summary) = try AgentAction.parse(final) else {
            fatalError("exact final action did not parse")
        }
        require(summary == "done", "exact final action changed its summary")

        for invalid in [
            "{\"kind\":\"final\",\"summary\":\"done\",\"verified\":false}",
            "{\"kind\":\"tool\",\"kind\":\"final\",\"summary\":\"done\"}",
            "{\"kind\":\"final\",\"\\u006bind\":\"tool\",\"summary\":\"done\"}",
            "{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/a.txt\",\"\\u0070ath\":\"workspace/b.txt\"}}",
        ] {
            do {
                _ = try AgentAction.parse(invalid)
                fatalError("agent action accepted duplicate or arbitrary final members")
            } catch {}
        }

        require(rejects("{\"outer\":[{\"provider\":\"local\",\"\\u0070rovider\":\"chatgpt\"}]}"), "nested escaped-equivalent member names were collapsed")
        require(rejects("{\"😀\":1,\"\\uD83D\\uDE00\":2}"), "surrogate-pair-equivalent member names were collapsed")
        require(rejects("{\"a\":1,}"), "malformed trailing-comma JSON passed")
        require(rejects("{\"a\":\"\\uD800\"}"), "unpaired JSON surrogate passed")
        require(rejects("true false"), "multiple JSON roots passed")
        do {
            try StrictJSON.validate(Data([0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x31, 0x7D]), limits: .providerResponse)
            fatalError("invalid UTF-8 passed strict JSON validation")
        } catch {}

        let maximumDepth = String(repeating: "[", count: 16) + "0" + String(repeating: "]", count: 16)
        require(!rejects(maximumDepth), "maximum valid JSON depth was rejected")
        let excessiveDepth = "[" + maximumDepth + "]"
        require(rejects(excessiveDepth), "JSON depth limit was not enforced")

        let maximumMembers = "{" + (0..<128).map { "\"k\($0)\":0" }.joined(separator: ",") + "}"
        require(!rejects(maximumMembers), "maximum valid JSON member count was rejected")
        let excessiveMembers = "{" + (0..<129).map { "\"k\($0)\":0" }.joined(separator: ",") + "}"
        require(rejects(excessiveMembers), "JSON member limit was not enforced")

        let unicodeSummary = String(repeating: "🧪", count: 2_000)
        let unicodeAction = "{\"kind\":\"final\",\"summary\":\"\(unicodeSummary)\"}"
        let padding = String(repeating: " ", count: AgentAction.maximumResponseBytes - unicodeAction.utf8.count)
        let exactBoundary = unicodeAction + padding
        require(exactBoundary.utf8.count == AgentAction.maximumResponseBytes, "UTF-8 action fixture missed the byte boundary")
        guard case .final(let decodedUnicode) = try AgentAction.parse(exactBoundary) else {
            fatalError("maximum-byte Unicode final action did not parse")
        }
        require(decodedUnicode == unicodeSummary, "Unicode final summary changed during strict parsing")
        do {
            _ = try AgentAction.parse(exactBoundary + " ")
            fatalError("oversized valid JSON action passed")
        } catch let error as SandboxError {
            require(error.localizedDescription == "PROVIDER_RESPONSE_TOO_LARGE", "oversized action returned the wrong boundary error")
        }
    }

    static func completeReadEvidence(path: String, content: String) -> ToolEvidence {
        ToolEvidence(
            path: path,
            sha256: NativeDigest.sha256(content),
            byteCount: content.utf8.count,
            readbackKind: "source-read",
            contentComplete: true
        )
    }

    static func providerRouting() throws {
        require(ProviderSelection.allCases.map(\.rawValue) == ["saved", "best-local", "apple", "local", "chatgpt", "grok", "grokbot", "claude"], "Siri provider choices drifted")
        let adapters: [AppProvider: ShortcutAdapter] = [
            .local: ShortcutAdapter(name: "Agent Step - Local", tested: true),
            .chatgpt: ShortcutAdapter(name: "Agent Step - ChatGPT", tested: true),
            .grok: ShortcutAdapter(name: "Agent Step - Grok", tested: true),
            .grokbot: ShortcutAdapter(name: "Agent Step - Grokbot", tested: true),
            .claude: ShortcutAdapter(name: "Agent Step - Claude", tested: true),
            .apple: ShortcutAdapter(name: "unused")
        ]
        let adapterFor: (AppProvider) -> ShortcutAdapter = { provider in
            adapters[provider] ?? ShortcutAdapter(name: "")
        }

        let bestApple = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .chatgpt,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false
        )
        require(bestApple.provider == .apple && bestApple.evidence == nil, "best-local cold start did not retain the available on-device Apple target")
        guard case .blocked(let unqualifiedAppleReason) = bestApple.decision else { fatalError("unqualified Apple cold start became runnable") }
        require(unqualifiedAppleReason.contains("PROVIDER_QUALIFICATION_REQUIRED"), "unqualified Apple cold start returned the wrong block")

        let qualifiedApple = ProviderRoutingPolicy.resolve(
            selection: .apple,
            savedProvider: .local,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [.apple: qualification(.apple, verified: 5, assertions: 5, latency: 500)],
            requirements: OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: true, unattended: true),
            deviceProfileSHA256: String(repeating: "d", count: 64),
            configurationSHA256: String(repeating: "e", count: 64)
        )
        require(qualifiedApple.provider == .apple && qualifiedApple.decision == .onDeviceApple && qualifiedApple.evidence != nil, "qualified explicit Apple route did not commit measured evidence")

        let bestShortcut = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .chatgpt,
            appleAvailability: .unavailable("notEligible"),
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: true,
            qualifications: [.local: qualification(.local, verified: 5, assertions: 5, latency: 500)]
        )
        require(bestShortcut.provider == .local && bestShortcut.decision == .shortcut(name: "Agent Step - Local"), "best-local selected a cloud provider instead of Locally")

        let explicitShortcuts: [(ProviderSelection, AppProvider)] = [
            (.local, .local),
            (.chatgpt, .chatgpt),
            (.grok, .grok),
            (.grokbot, .grokbot),
            (.claude, .claude)
        ]
        for (selection, expectedProvider) in explicitShortcuts {
            let route = ProviderRoutingPolicy.resolve(
                selection: selection,
                savedProvider: .apple,
                appleAvailability: .available,
                shortcutsAvailable: true,
                adapterFor: adapterFor,
                cloudAllowed: true,
                qualifications: [expectedProvider: qualification(expectedProvider, verified: 5, assertions: 5, latency: 500)]
            )
            require(route.provider == expectedProvider, "explicit \(selection.rawValue) selection changed providers")
            require(route.decision == .shortcut(name: adapters[expectedProvider]?.name ?? ""), "explicit \(selection.rawValue) selection did not use its tested Shortcut")
        }

        let unavailableBestLocal = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .claude,
            appleAvailability: .unavailable("notEligible"),
            shortcutsAvailable: true,
            adapterFor: { provider in provider == .local ? ShortcutAdapter(name: "Agent Step - Local", tested: false) : adapterFor(provider) },
            cloudAllowed: true
        )
        guard case .blocked = unavailableBestLocal.decision else {
            fatalError("best-local bypassed the tested Locally requirement")
        }
        require(unavailableBestLocal.provider == .local, "blocked best-local route selected a cloud provider")

        let savedCloud = ProviderRoutingPolicy.resolve(
            selection: .saved,
            savedProvider: .chatgpt,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false
        )
        guard case .blocked(let savedCloudReason) = savedCloud.decision else {
            fatalError("saved cloud provider bypassed consent")
        }
        require(savedCloud.provider == .chatgpt && savedCloudReason == "Authorize cloud app handoffs in Settings first.", "saved choice silently changed providers")

        let explicitApple = ProviderRoutingPolicy.resolve(
            selection: .apple,
            savedProvider: .local,
            appleAvailability: .unavailable("deviceNotEligible"),
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: true
        )
        guard case .blocked = explicitApple.decision else {
            fatalError("explicit Apple request silently substituted another provider")
        }
        require(explicitApple.provider == .apple, "explicit Apple request changed its resolved provider")

        let apple = ShortcutAdapter(name: "unused")
        require(
            ProviderRoutingPolicy.resolve(
                provider: .apple,
                appleAvailability: .available,
                shortcutsAvailable: false,
                adapter: apple,
                cloudAllowed: false
            ) == .onDeviceApple,
            "iPhone 18-class Apple Intelligence availability did not select the on-device model"
        )

        let unavailable = ProviderRoutingPolicy.resolve(
            provider: .apple,
            appleAvailability: .unavailable("deviceNotEligible"),
            shortcutsAvailable: true,
            adapter: ShortcutAdapter(name: "Agent Step - Apple", tested: true),
            cloudAllowed: true
        )
        guard case .blocked(let unavailableReason) = unavailable else {
            fatalError("Apple unavailability silently substituted a Shortcut provider")
        }
        require(unavailableReason.contains("configured and currently qualified"), "Apple unavailability must not promise an unqualified fallback")

        require(
            ProviderRoutingPolicy.resolve(
                provider: .local,
                appleAvailability: .unavailable("notEligible"),
                shortcutsAvailable: true,
                adapter: ShortcutAdapter(name: "Agent Step - Local", tested: true),
                cloudAllowed: false
            ) == .shortcut(name: "Agent Step - Local"),
            "lower-device native Shortcut routing depended on Apple Intelligence"
        )

        guard case .blocked(let cloudReason) = ProviderRoutingPolicy.resolve(
            provider: .chatgpt,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapter: ShortcutAdapter(name: "Agent Step - ChatGPT", tested: true),
            cloudAllowed: false
        ) else {
            fatalError("cloud Shortcut bypassed explicit consent")
        }
        require(cloudReason == "Authorize cloud app handoffs in Settings first.", "cloud consent refusal changed")
        require(
            ProviderRoutingPolicy.resolve(
                provider: .chatgpt,
                appleAvailability: .available,
                shortcutsAvailable: true,
                adapter: ShortcutAdapter(name: "Agent Step - ChatGPT", tested: true),
                cloudAllowed: true
            ) == .shortcut(name: "Agent Step - ChatGPT"),
            "authorized cloud Shortcut did not retain its explicit provider"
        )
    }

    static func measuredRouting() throws {
        let adapters: [AppProvider: ShortcutAdapter] = [
            .local: ShortcutAdapter(name: "Agent Step - Local", tested: true),
            .chatgpt: ShortcutAdapter(name: "Agent Step - ChatGPT", tested: true),
            .grok: ShortcutAdapter(name: "Agent Step - Grok", tested: true),
            .grokbot: ShortcutAdapter(name: "Agent Step - Grokbot", tested: true),
            .claude: ShortcutAdapter(name: "Agent Step - Claude", tested: true),
            .apple: ShortcutAdapter(name: "unused")
        ]
        let adapterFor: (AppProvider) -> ShortcutAdapter = { adapters[$0] ?? ShortcutAdapter(name: "") }
        let requirements = OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: true, unattended: true)
        let localWins = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .apple,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [
                .apple: qualification(.apple, verified: 4, assertions: 4, latency: 1_000),
                .local: qualification(.local, verified: 5, assertions: 5, latency: 2_000)
            ],
            requirements: requirements,
            deviceProfileSHA256: String(repeating: "d", count: 64),
            configurationSHA256: String(repeating: "e", count: 64)
        )
        guard let localWinsEvidence = localWins.evidence else { fatalError("measured local winner omitted committed evidence") }
        require(localWins.provider == .local && localWins.decision == .shortcut(name: "Agent Step - Local"), "measured Best Local ignored higher reliability and quality")
        require(localWinsEvidence.strategy == .bestLocalMeasured && localWinsEvidence.reliabilityBasisPoints == 10_000, "measured routing evidence omitted its deterministic score")
        require(localWinsEvidence.accessEvidence == .recentLocallyValidatedResponse, "routing evidence overstated caller-supplied response provenance")

        let independentMetrics = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .local,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [
                .apple: qualification(.apple, verified: 4, assertions: 4, latency: 2_000, schemaPasses: 5),
                .local: qualification(.local, verified: 5, assertions: 5, latency: 500, schemaPasses: 4)
            ],
            requirements: requirements
        )
        guard let independentEvidence = independentMetrics.evidence else { fatalError("ranked route omitted committed evidence") }
        require(independentMetrics.provider == .apple, "schema reliability was not ranked independently ahead of assertion quality")
        require(independentEvidence.reliabilityBasisPoints == 10_000 && independentEvidence.qualityBasisPoints == 8_000, "routing evidence collapsed reliability and quality")
        require(!qualification(.local, verified: 5, assertions: 5, latency: 500, schemaPasses: 3).baseQualified, "sub-80-percent schema reliability qualified")
        require(!qualification(.local, verified: 3, assertions: 3, latency: 500, schemaPasses: 5).baseQualified, "sub-80-percent assertion quality qualified")

        let singleMeasuredLocal = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .apple,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [.local: qualification(.local, verified: 5, assertions: 5, latency: 500)],
            requirements: requirements
        )
        require(singleMeasuredLocal.provider == .local && singleMeasuredLocal.evidence?.strategy == .bestLocalMeasured && singleMeasuredLocal.decision == .shortcut(name: "Agent Step - Local"), "one qualified local route was ignored because its peer had no evidence")

        let appleTieBreak = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .local,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [
                .apple: qualification(.apple, verified: 5, assertions: 5, latency: 1_000),
                .local: qualification(.local, verified: 5, assertions: 5, latency: 1_000)
            ],
            requirements: requirements
        )
        require(appleTieBreak.provider == .apple, "fixed Apple/Locally tie-break drifted")

        let incomparableTimingTie = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .local,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [
                .apple: qualification(.apple, verified: 5, assertions: 5, latency: 300_000),
                .local: qualification(.local, verified: 5, assertions: 5, latency: 0)
            ],
            requirements: requirements
        )
        require(incomparableTimingTie.provider == .apple, "in-process Apple timing was compared with an external Shortcut round trip")

        let fasterExternal = ProviderRoutingPolicy.recommend(
            providers: [.chatgpt, .claude],
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: true,
            qualifications: [
                .chatgpt: qualification(.chatgpt, verified: 5, assertions: 5, latency: 2_000),
                .claude: qualification(.claude, verified: 5, assertions: 5, latency: 500)
            ],
            requirements: OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: false, unattended: true)
        )
        require(fasterExternal == .claude, "comparable external round-trip timing stopped breaking an equal-quality tie")

        let manualLocal = qualification(.local, verified: 5, assertions: 5, latency: 500, appIntentReturnObserved: false)
        let automatedRequirement = OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: true, unattended: true)
        require(!manualLocal.qualifies(for: automatedRequirement), "manual-return route qualified for unattended Siri execution")
        let twelveThousandRequirement = OracleTaskRequirements.filesystem(policyContextCharacters: 12_000, localOnly: true, unattended: true)
        require(!qualification(.local, verified: 5, assertions: 5, latency: 500, context: 6_000).qualifies(for: twelveThousandRequirement), "6,000-character evidence qualified a 12,000-character handoff")
        require(qualification(.local, verified: 5, assertions: 5, latency: 500, context: 12_000).qualifies(for: twelveThousandRequirement), "12,000-character evidence did not qualify the matching handoff cap")

        let bothFailed = ProviderRoutingPolicy.resolve(
            selection: .bestLocal,
            savedProvider: .local,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: false,
            qualifications: [
                .apple: qualification(.apple, verified: 3, assertions: 3, latency: 500),
                .local: qualification(.local, verified: 3, assertions: 3, latency: 500)
            ],
            requirements: requirements
        )
        guard case .blocked(let reason) = bothFailed.decision else { fatalError("unqualified measured routes did not block") }
        require(reason.contains("REQUALIFICATION_REQUIRED") && bothFailed.provider == .apple, "failed measured route silently substituted or used cloud")

        let savedPinned = ProviderRoutingPolicy.resolve(
            selection: .saved,
            savedProvider: .chatgpt,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: true,
            qualifications: [.chatgpt: qualification(.chatgpt, verified: 5, assertions: 5, latency: 500)],
            requirements: OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: false, unattended: false)
        )
        require(savedPinned.provider == .chatgpt && savedPinned.evidence?.strategy == .savedPinned, "measured evidence changed a pinned saved route")

        let manualAdapters: (AppProvider) -> ShortcutAdapter = { provider in
            provider == .chatgpt
                ? ShortcutAdapter(name: "Agent Step - ChatGPT", mode: "manual", tested: true)
                : adapterFor(provider)
        }
        let unattendedCloud = OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: false, unattended: true)
        let explicitManual = ProviderRoutingPolicy.resolve(
            selection: .chatgpt,
            savedProvider: .apple,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: manualAdapters,
            cloudAllowed: true,
            requirements: unattendedCloud
        )
        let savedManual = ProviderRoutingPolicy.resolve(
            selection: .saved,
            savedProvider: .chatgpt,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: manualAdapters,
            cloudAllowed: true,
            requirements: unattendedCloud
        )
        require(explicitManual.provider == .chatgpt && explicitManual.decision == .blocked("MANUAL_PROVIDER_RETURN_REQUIRES_USER"), "unattended explicit routing switched or allowed a manual provider")
        require(savedManual.provider == .chatgpt && savedManual.decision == .blocked("MANUAL_PROVIDER_RETURN_REQUIRES_USER"), "unattended saved routing switched or allowed a manual provider")

        let recommendedPinned = ProviderRoutingPolicy.resolve(
            selection: .saved,
            savedProvider: .chatgpt,
            appleAvailability: .available,
            shortcutsAvailable: true,
            adapterFor: adapterFor,
            cloudAllowed: true,
            qualifications: [.chatgpt: qualification(.chatgpt, verified: 5, assertions: 5, latency: 500)],
            requirements: OracleTaskRequirements.filesystem(policyContextCharacters: 6_000, localOnly: false, unattended: true),
            savedStrategy: .oracleRecommendation
        )
        require(recommendedPinned.provider == .chatgpt && recommendedPinned.evidence?.strategy == .oracleRecommendation, "Oracle recommendation did not remain a pinned Saved route")

        let encoded = try JSONEncoder().encode(localWinsEvidence)
        let restored = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: encoded)
        require(restored == localWinsEvidence && !String(decoding: encoded, as: UTF8.self).contains("Agent Step"), "routing evidence was not strict or leaked an adapter name")
        let encodedEvidence = String(decoding: encoded, as: UTF8.self)
        require(encodedEvidence.contains("\"automatedReturnQualified\":true") && !encodedEvidence.contains("appIntentReturnObserved"), "routing evidence broke the schema 2 compatibility key")
        var legacyEvidence = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        legacyEvidence["accessEvidence"] = "recent-successful-round-trip"
        let migratedEvidence = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: legacyEvidence))
        require(migratedEvidence.accessEvidence == .recentLocallyValidatedResponse, "legacy routing evidence did not migrate to the honest local-validation label")
        let reencodedEvidence = try JSONEncoder().encode(migratedEvidence)
        require(String(decoding: reencodedEvidence, as: UTF8.self).contains("recent-locally-validated-response"), "migrated routing evidence re-emitted the legacy provenance claim")
        var extra = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        extra["providerOutput"] = "secret"
        do {
            _ = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: extra))
            fatalError("routing evidence accepted an extra provider-output field")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_EVIDENCE_FIELDS", "extra routing evidence returned the wrong error")
        }
        var nullOptionalMetric = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        nullOptionalMetric["qualityBasisPoints"] = NSNull()
        do {
            _ = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: nullOptionalMetric))
            fatalError("routing evidence accepted null for a non-null optional metric")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NULL_PROVIDER_ROUTING_OPTIONAL_FIELD", "null optional metric returned the wrong error")
        }
        var mismatchedExplicit = try JSONSerialization.jsonObject(with: JSONEncoder().encode(qualifiedExternalEvidence(selection: .chatgpt, provider: .chatgpt))) as! [String: Any]
        mismatchedExplicit["provider"] = "claude"
        do {
            _ = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: mismatchedExplicit))
            fatalError("routing evidence accepted an explicit selection/provider mismatch")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_SELECTION", "explicit mismatch returned the wrong routing evidence error")
        }
        var impossibleMetrics = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        impossibleMetrics["sampleCount"] = 0
        impossibleMetrics["distinctProbeCount"] = 0
        impossibleMetrics["verifiedCount"] = 0
        impossibleMetrics["automatedReturnQualified"] = false
        do {
            _ = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: impossibleMetrics))
            fatalError("routing evidence accepted qualification metrics with zero samples")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_METRICS", "zero-sample metrics returned the wrong routing evidence error")
        }
        var forgedQuality = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        forgedQuality["verifiedCount"] = 4
        forgedQuality["qualityBasisPoints"] = 10_000
        do {
            _ = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: forgedQuality))
            fatalError("routing evidence accepted a forged assertion-quality rate")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_METRICS", "forged assertion quality returned the wrong routing evidence error")
        }
        var forgedReliability = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        forgedReliability["reliabilityBasisPoints"] = 9_000
        do {
            _ = try JSONDecoder().decode(ProviderRoutingEvidence.self, from: JSONSerialization.data(withJSONObject: forgedReliability))
            fatalError("routing evidence accepted a reliability rate that no whole-sample count can produce")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_METRICS", "forged reliability returned the wrong routing evidence error")
        }
    }

    static func continuationValidationAndRuntimeIdentity() throws {
        let state = MutableContinuationState()
        let validator = ExecutionContinuationValidator {
            guard state.authorizationCurrent else { throw SandboxError.blocked("AUTHORIZATION_CHANGED") }
            guard state.routeCurrent else { throw SandboxError.blocked("ROUTE_CHANGED") }
        }
        try validator.beforePlanningContinuation()
        state.authorizationCurrent = false
        try expectError("AUTHORIZATION_CHANGED") {
            try validator.afterAwait()
        }
        state.authorizationCurrent = true
        state.routeCurrent = false
        try expectError("ROUTE_CHANGED") {
            try validator.beforeDispatcherSideEffect()
        }

        let version = OperatingSystemVersion(majorVersion: 26, minorVersion: 4, patchVersion: 1)
        let patchedVersion = OperatingSystemVersion(majorVersion: 26, minorVersion: 4, patchVersion: 2)
        let baseline = ProviderRuntimeIdentity.operatingSystemDescriptor(version: version, buildDescription: "Build 23A100")
        let patchChanged = ProviderRuntimeIdentity.operatingSystemDescriptor(version: patchedVersion, buildDescription: "Build 23A100")
        let buildChanged = ProviderRuntimeIdentity.operatingSystemDescriptor(version: version, buildDescription: "Build 23A101")
        require(baseline.contains("os=26.4.1") && baseline.contains("Build 23A100"), "OS descriptor omitted the patch or build")
        require(baseline != patchChanged && baseline != buildChanged, "OS patch or build changes did not invalidate runtime identity")
    }

    static func validatedAwaitRejectsStaleEntryAndPreservesCurrentErrors() async throws {
        let gate = ExecutionContinuationGate()
        let validator = gate.validator(for: gate.capture())
        var staleClosureEntries = 0
        gate.invalidate()
        do {
            let _: String = try await validator.validatedAwait {
                staleClosureEntries += 1
                return "stale-work-started"
            }
            fatalError("stale validatedAwait entered its closure")
        } catch let error as SandboxError {
            require(error.localizedDescription == "LOCAL_SANDBOX_LOCKED", "stale validatedAwait returned the wrong error")
        }
        require(staleClosureEntries == 0, "stale validatedAwait started protected work")

        let currentValidator = ExecutionContinuationValidator {}
        do {
            let _: String = try await currentValidator.validatedAwait {
                throw SandboxError.invalid("CURRENT_PROVIDER_ERROR")
            }
            fatalError("current-generation provider error was swallowed")
        } catch let error as SandboxError {
            require(error.localizedDescription == "CURRENT_PROVIDER_ERROR", "current-generation provider error changed")
        }
    }

    static func heldProviderResponseCannotCrossLockFence() async throws {
        let gate = ExecutionContinuationGate()
        let executionGeneration = gate.capture()
        let validator = gate.validator(for: executionGeneration)
        let provider = HeldProviderResponse()
        let sideEffects = DispatcherSideEffectRecorder()
        let run = Task { @MainActor in
            let response = try await validator.validatedAwait {
                await provider.response()
            }
            require(response == #"{"kind":"tool"}"#, "held provider response changed")
            try validator.beforeDispatcherSideEffect()
            sideEffects.record()
        }

        await provider.waitUntilHeld()
        gate.invalidate()
        await provider.release(#"{"kind":"tool"}"#)
        do {
            try await run.value
            fatalError("provider response crossed the lock generation fence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "LOCAL_SANDBOX_LOCKED", "lock fence returned the wrong error")
        }
        require(sideEffects.count == 0, "a dispatcher side effect ran after lock")
    }

    static func heldShortcutContinuationCannotCrossLockFence() async throws {
        let gate = ExecutionContinuationGate()
        let executionGeneration = gate.capture()
        let validator = gate.validator(for: executionGeneration)
        let heldSystemOperation = HeldProviderResponse()
        let effects = ShortcutContinuationEffectRecorder()
        let continuation = Task { @MainActor in
            do {
                try validator.beforeDispatcherSideEffect()
                effects.recordExternalSubmission()
                _ = try await validator.validatedAwait {
                    await heldSystemOperation.response()
                }
                try validator.beforeDispatcherSideEffect()
                effects.recordDispatcherCompletion()
                try validator.beforePersistence()
                effects.recordSuccessfulResponse()
                try validator.beforePersistence()
                effects.recordSessionWrite()
            } catch {
                // ShortcutCoordinator must rethrow a retired generation before converting an
                // execution error into a provider failure or persisting continuation state.
                try validator.requireCurrent()
                effects.recordProviderFailure()
            }
        }

        await heldSystemOperation.waitUntilHeld()
        gate.invalidate()
        await heldSystemOperation.release("notification-system-return")
        do {
            try await continuation.value
            fatalError("shortcut continuation crossed the lock generation fence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "LOCAL_SANDBOX_LOCKED", "shortcut lock fence returned the wrong error")
        }
        require(effects.submittedExternalOperations == 1, "held system operation did not reach its pre-lock submission boundary")
        require(effects.dispatcherCompletions == 0, "dispatcher completion ran after shortcut lock")
        require(effects.successfulResponses == 0, "shortcut success was recorded after lock")
        require(effects.sessionWrites == 0, "shortcut session state was persisted after lock")
        require(effects.providerFailures == 0, "lock retirement was converted into a provider failure")
    }

    static func heldIntentAuthenticationCannotCrossLockFence() async throws {
        let gate = ExecutionContinuationGate()
        let executionGeneration = gate.capture()
        let validator = gate.validator(for: executionGeneration)
        let heldAuthentication = HeldProviderResponse()
        let effects = IntentBoundaryEffectRecorder()
        let intent = Task { @MainActor in
            _ = try await validator.validatedAwait {
                await heldAuthentication.response()
            }
            effects.recordProtectedRead()
            try validator.beforePersistence()
            effects.recordSuccessfulCompletion()
            try validator.requireCurrent()
            effects.recordTerminalReturn()
        }

        await heldAuthentication.waitUntilHeld()
        gate.invalidate()
        await heldAuthentication.release("authenticated")
        do {
            try await intent.value
            fatalError("intent authentication crossed the lock generation fence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "LOCAL_SANDBOX_LOCKED", "intent authentication lock fence returned the wrong error")
        }
        require(effects.protectedReads == 0, "protected state was read after authentication crossed a lock")
        require(effects.successfulCompletions == 0, "intent state was persisted after authentication crossed a lock")
        require(effects.terminalReturns == 0, "intent returned after authentication crossed a lock")
    }

    static func heldQualificationFailureCannotCrossLockFence() async throws {
        let gate = ExecutionContinuationGate()
        let executionGeneration = gate.capture()
        let validator = gate.validator(for: executionGeneration)
        let heldModel = HeldProviderResponse()
        let effects = IntentBoundaryEffectRecorder()
        let qualification = Task { @MainActor in
            do {
                let _: String = try await validator.validatedAwait {
                    _ = await heldModel.response()
                    throw SandboxError.invalid("PROVIDER_FAILED_AFTER_WAIT")
                }
                try validator.beforePersistence()
                effects.recordSuccessfulCompletion()
            } catch {
                // ProviderQualificationStore must retire the generation before failure
                // accounting, including when the held model operation itself throws.
                try validator.requireCurrent()
                try validator.beforePersistence()
                effects.recordFailureAccounting()
            }
            try validator.requireCurrent()
            effects.recordTerminalReturn()
        }

        await heldModel.waitUntilHeld()
        gate.invalidate()
        await heldModel.release("release-with-provider-error")
        do {
            try await qualification.value
            fatalError("qualification failure crossed the lock generation fence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "LOCAL_SANDBOX_LOCKED", "qualification lock fence returned the wrong error")
        }
        require(effects.successfulCompletions == 0, "qualification success was persisted after lock")
        require(effects.failureAccounting == 0, "lock retirement was converted into qualification failure accounting")
        require(effects.terminalReturns == 0, "qualification returned after lock")
    }

    static func providerQualificationVerifier() throws {
        let token = "0123456789abcdef01234567"
        let exact: [ProviderQualificationProbe: String] = [
            .strictJSON: "{\"kind\":\"final\",\"summary\":\"\(token)\"}",
            .readTool: "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}}",
            .listTool: "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.list\",\"arguments\":{\"path\":\"workspace\"}}}",
            .patchTool: "{\"kind\":\"tool\",\"tool\":\"file.patch\",\"arguments\":{\"path\":\"workspace/test.txt\",\"old\":\"Status: pending\",\"replacement\":\"Status: \(token)\",\"expectedSHA256\":\"\(NativeDigest.sha256("Status: pending"))\"}}",
            .boundedContext: "{\"kind\":\"final\",\"summary\":\"\(token)\"}"
        ]
        for probe in ProviderQualificationProbe.allCases {
            let prompt = ProviderQualificationVerifier.prompt(probe: probe, token: token, contextCharacters: 6_000)
            require(!prompt.contains("credential") && !prompt.contains("token="), "qualification prompt requested secret material")
            require(ProviderQualificationVerifier.validatesStrictSchema(response: exact[probe]!, probe: probe), "\(probe.rawValue) rejected its strict action schema")
            require(ProviderQualificationVerifier.validate(response: exact[probe]!, probe: probe, token: token), "\(probe.rawValue) rejected its exact held-out response")
            require(!ProviderQualificationVerifier.validatesStrictSchema(response: "```json\n\(exact[probe]!)\n```", probe: probe), "\(probe.rawValue) counted markdown as a strict schema pass")
            require(!ProviderQualificationVerifier.validate(response: "```json\n\(exact[probe]!)\n```", probe: probe, token: token), "\(probe.rawValue) accepted markdown wrapping")
        }
        let contextPrompt = ProviderQualificationVerifier.prompt(probe: .boundedContext, token: token, contextCharacters: 12_000)
        require(contextPrompt.count == 12_000 && contextPrompt.components(separatedBy: token).count - 1 == 1, "bounded-context probe did not exercise the full policy cap with one start-only challenge")
        let wrongChallenge = "{\"kind\":\"final\",\"summary\":\"wrong\"}"
        require(ProviderQualificationVerifier.validatesStrictSchema(response: wrongChallenge, probe: .boundedContext), "schema reliability incorrectly depended on held-out content")
        require(!ProviderQualificationVerifier.validate(response: wrongChallenge, probe: .boundedContext, token: token), "context probe accepted the wrong device challenge")
        let extraRuntimeField = "{\"kind\":\"final\",\"summary\":\"\(token)\",\"verified\":true}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: extraRuntimeField, probe: .strictJSON), "final action accepted the removed verified member")
        require(!ProviderQualificationVerifier.validate(response: extraRuntimeField, probe: .strictJSON, token: token), "exact final assertion accepted the removed verified member")
        let otherToken = "fedcba987654321001234567"
        for probe in [ProviderQualificationProbe.readTool, .listTool] {
            require(ProviderQualificationVerifier.validatesStrictSchema(response: exact[probe]!, probe: probe), "\(probe.rawValue) replay fixture was not schema-valid")
            require(!ProviderQualificationVerifier.validate(response: exact[probe]!, probe: probe, token: otherToken), "\(probe.rawValue) accepted a response from another attempt")
            require(ProviderQualificationVerifier.prompt(probe: probe, token: token, contextCharacters: 6_000).components(separatedBy: token).count - 1 == 1, "\(probe.rawValue) prompt did not bind the full attempt challenge exactly once")
        }
        let wrongReadPath = "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/other.txt\"}}}"
        require(ProviderQualificationVerifier.validatesStrictSchema(response: wrongReadPath, probe: .readTool), "schema reliability incorrectly depended on the expected read path")
        require(!ProviderQualificationVerifier.validate(response: wrongReadPath, probe: .readTool, token: token), "tool probe accepted the wrong path")
        let malformedChallenge = "{\"challenge\":\"short\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: malformedChallenge, probe: .readTool), "read-tool accepted a malformed challenge envelope")
        let extraEnvelopeField = "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.list\",\"arguments\":{\"path\":\"workspace\"}},\"extra\":true}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: extraEnvelopeField, probe: .listTool), "list-tool accepted an extra envelope field")
        require(!ProviderQualificationVerifier.validate(response: extraEnvelopeField, probe: .listTool, token: token), "list-tool assertion accepted an extra envelope field")
        let extraActionField = "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"},\"extra\":true}}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: extraActionField, probe: .readTool), "read-tool accepted an extra nested action field")
        require(!ProviderQualificationVerifier.validate(response: extraActionField, probe: .readTool, token: token), "read-tool assertion accepted an extra nested action field")
        let duplicateChallenge = "{\"challenge\":\"\(token)\",\"challenge\":\"\(otherToken)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: duplicateChallenge, probe: .readTool), "read-tool collapsed duplicate top-level challenge members")
        require(!ProviderQualificationVerifier.validate(response: duplicateChallenge, probe: .readTool, token: token), "read-tool assertion collapsed duplicate top-level challenge members")
        let duplicateNestedTool = "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"\\u0074ool\":\"file.list\",\"arguments\":{\"path\":\"workspace/test.txt\"}}}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: duplicateNestedTool, probe: .readTool), "read-tool collapsed an escaped duplicate nested tool member")
        require(!ProviderQualificationVerifier.validate(response: duplicateNestedTool, probe: .readTool, token: token), "read-tool assertion collapsed an escaped duplicate nested tool member")
        let duplicateNestedPath = "{\"challenge\":\"\(token)\",\"action\":{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\",\"\\u0070ath\":\"workspace/other.txt\"}}}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: duplicateNestedPath, probe: .readTool), "read-tool collapsed an escaped duplicate nested path member")
        require(!ProviderQualificationVerifier.validate(response: duplicateNestedPath, probe: .readTool, token: token), "read-tool assertion collapsed an escaped duplicate nested path member")
        let executableLegacyRead = "{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}"
        require(!ProviderQualificationVerifier.validatesStrictSchema(response: executableLegacyRead, probe: .readTool), "read-tool accepted a replayable executable action without its qualification envelope")
    }

    static func providerHandoffTelemetry() throws {
        let prompt = "private workspace prompt"
        let response = "{\"kind\":\"final\",\"summary\":\"private response\"}"
        let adapterName = "Private Custom Adapter"
        let header = ProviderHandoffPromptHeader(provider: .local, selection: .bestLocal, origin: .appIntent).jsonLine
        let headerJSON = try JSONSerialization.jsonObject(with: Data(header.utf8)) as! [String: Any]
        require(headerJSON["recordType"] as? String == "provider-handoff-prompt", "handoff prompt is not self-describing")
        require(headerJSON["kind"] as? String == "handoff-prompt" && headerJSON["provider"] as? String == "local", "handoff prompt omitted its route")
        require(headerJSON["selection"] as? String == "best-local" && headerJSON["origin"] as? String == "app-intent", "handoff prompt omitted its selection or origin")
        let outbound = try ProviderHandoffTrace.outbound(
            provider: .local,
            selection: .bestLocal,
            origin: .appIntent,
            adapterName: adapterName,
            actionIndex: 0,
            prompt: prompt
        )
        let inbound = try ProviderHandoffTrace.inbound(
            provider: .local,
            selection: .bestLocal,
            origin: .appIntent,
            adapterName: adapterName,
            actionIndex: 0,
            response: response
        )
        require(outbound.tool == "provider.handoff.outbound" && inbound.tool == "provider.handoff.inbound", "handoff trace tools are not machine-detectable")
        require(!outbound.detail.contains(prompt) && !inbound.detail.contains(response) && !outbound.detail.contains(adapterName) && !inbound.detail.contains(adapterName), "handoff trace leaked provider content or adapter name")

        let outboundJSON = try JSONSerialization.jsonObject(with: Data(outbound.detail.utf8)) as! [String: Any]
        let inboundJSON = try JSONSerialization.jsonObject(with: Data(inbound.detail.utf8)) as! [String: Any]
        require(outboundJSON["recordType"] as? String == "provider-handoff", "outbound trace omitted its record type")
        require(outboundJSON["provider"] as? String == "local" && outboundJSON["selection"] as? String == "best-local", "outbound trace omitted provider routing")
        require(outboundJSON["origin"] as? String == "app-intent" && outboundJSON["transport"] as? String == "app-shortcut", "outbound trace omitted origin or transport")
        require(outboundJSON["schemaVersion"] as? Int == 2 && outboundJSON["adapterSHA256"] as? String == NativeDigest.sha256(adapterName), "outbound trace omitted its versioned adapter fingerprint")
        require(inboundJSON["adapterSHA256"] as? String == NativeDigest.sha256(adapterName), "inbound trace did not bind the same adapter fingerprint")
        require(outboundJSON["promptSHA256"] as? String == NativeDigest.sha256(prompt), "outbound trace stored the wrong prompt hash")
        require(outboundJSON["responseSHA256"] == nil, "outbound trace admitted an inbound response field")
        require(inboundJSON["responseSHA256"] as? String == NativeDigest.sha256(response), "inbound trace stored the wrong response hash")
        require(inboundJSON["promptSHA256"] == nil, "inbound trace admitted an outbound prompt field")
        require(inboundJSON["content"] == nil && inboundJSON["credential"] == nil && inboundJSON["token"] == nil, "inbound trace admitted secret-bearing fields")
        require(outbound.receiptSafe().detail == outbound.detail && inbound.receiptSafe().detail == inbound.detail, "receipt privacy rejected valid version 2 adapter telemetry")

        var leakedAdapterEvent = outboundJSON
        leakedAdapterEvent["adapterName"] = adapterName
        let leakedAdapterDetail = String(decoding: try JSONSerialization.data(withJSONObject: leakedAdapterEvent, options: [.sortedKeys]), as: UTF8.self)
        let sanitized = TraceEntry(tool: outbound.tool, status: "ok", detail: leakedAdapterDetail).receiptSafe()
        require(!sanitized.detail.contains(adapterName) && sanitized.detail.contains("legacy-redacted"), "receipt privacy retained a raw adapter name")

        let duplicateProviderDetail = String(outbound.detail.dropLast()) + ",\"provider\":\"chatgpt\"}"
        let duplicateProvider = TraceEntry(tool: outbound.tool, status: "ok", detail: duplicateProviderDetail).receiptSafe()
        require(duplicateProvider.detail.contains("legacy-redacted"), "receipt privacy collapsed duplicate provider handoff members")
        require(!duplicateProvider.detail.contains("chatgpt"), "duplicate provider handoff text survived receipt sanitization")

        let escapedProviderDetail = String(outbound.detail.dropLast()) + ",\"\\u0070rovider\":\"chatgpt\"}"
        let escapedProvider = TraceEntry(tool: outbound.tool, status: "ok", detail: escapedProviderDetail).receiptSafe()
        require(escapedProvider.detail.contains("legacy-redacted"), "receipt privacy collapsed escaped-equivalent provider handoff members")
        require(!escapedProvider.detail.contains("chatgpt"), "escaped duplicate provider handoff text survived receipt sanitization")
    }

    static func createReadPatchReadback() throws {
        let storage = MemoryToolStorage()
        let executor = NativeToolExecutor(storage: storage)
        let path = "workspace/status.txt"
        let initial = "Status: pending"
        let final = "Status: verified"

        let created = try executor.executeFile(call(.create, ["path": path, "content": initial]), callID: "create")
        require(created.sha256 == NativeDigest.sha256(initial), "create returned the wrong digest")
        require(storage.files[path] == initial, "create readback did not match exact bytes")

        let read = try executor.executeFile(call(.read, ["path": path]), callID: "read-before-patch")
        require(read.result == initial && read.evidence?.contentComplete == true, "source read was incomplete")
        let expected = read.sha256 ?? ""

        let patched = try executor.executeFile(
            call(.patch, ["path": path, "old": initial, "replacement": final, "expectedSHA256": expected]),
            callID: "patch",
            authorizedRead: read.evidence
        )
        require(patched.sha256 == NativeDigest.sha256(final), "patch returned the wrong digest")

        let independent = try executor.executeFile(call(.read, ["path": path]), callID: "independent-readback")
        require(independent.result == final, "independent exact readback did not observe the final bytes")
        require(independent.sha256 == patched.sha256, "write and independent readback digests differ")
    }

    static func traversalAndOverwriteRejection() throws {
        let storage = MemoryToolStorage(["workspace/existing.txt": "protected"])
        let executor = NativeToolExecutor(storage: storage)

        try expectError("PATH_OUTSIDE_SANDBOX") {
            _ = try executor.executeFile(call(.read, ["path": "workspace/../secret.txt"]), callID: "traversal")
        }
        try expectError("FILE_EXISTS") {
            _ = try executor.executeFile(
                call(.create, ["path": "workspace/existing.txt", "content": "replacement"]),
                callID: "duplicate-create"
            )
        }
        require(storage.files["workspace/existing.txt"] == "protected", "duplicate create replaced protected bytes")
    }

    static func staleAndAmbiguousPatchRejection() throws {
        let staleStorage = MemoryToolStorage(["workspace/stale.txt": "old"])
        let staleExecutor = NativeToolExecutor(storage: staleStorage)
        let evidence = completeReadEvidence(path: "workspace/stale.txt", content: "old")
        staleStorage.replaceOutOfBand(path: "workspace/stale.txt", content: "new")
        try expectError("FILE_CHANGED_REREAD_REQUIRED") {
            _ = try staleExecutor.executeFile(
                call(.patch, ["path": "workspace/stale.txt", "old": "old", "replacement": "changed", "expectedSHA256": evidence.sha256 ?? ""]),
                callID: "stale-patch",
                authorizedRead: evidence
            )
        }
        require(staleStorage.files["workspace/stale.txt"] == "new", "stale patch changed current bytes")

        let ambiguous = "Status: pending\nStatus: pending"
        let ambiguousStorage = MemoryToolStorage(["workspace/ambiguous.txt": ambiguous])
        let ambiguousExecutor = NativeToolExecutor(storage: ambiguousStorage)
        let ambiguousEvidence = completeReadEvidence(path: "workspace/ambiguous.txt", content: ambiguous)
        try expectError("PATCH_CONTEXT_AMBIGUOUS") {
            _ = try ambiguousExecutor.executeFile(
                call(.patch, [
                    "path": "workspace/ambiguous.txt",
                    "old": "Status: pending",
                    "replacement": "Status: verified",
                    "expectedSHA256": ambiguousEvidence.sha256 ?? ""
                ]),
                callID: "ambiguous-patch",
                authorizedRead: ambiguousEvidence
            )
        }
        require(ambiguousStorage.files["workspace/ambiguous.txt"] == ambiguous, "ambiguous patch changed source bytes")
    }

    static func journalRecoveryRules() throws {
        let storage = MemoryToolStorage()
        let executor = NativeToolExecutor(storage: storage)
        let create = call(.create, ["path": "workspace/replay.txt", "content": "once"])
        let first = try executor.executeFile(create, callID: "completed-call")
        let writesAfterFirst = storage.workspaceWrites
        let replay = try executor.executeFile(create, callID: "completed-call")
        require(replay.sha256 == first.sha256 && replay.result == first.result, "completed call did not return cached evidence")
        require(storage.workspaceWrites == writesAfterFirst, "completed call replayed a side effect")

        try expectError("CALL_ID_REUSED_WITH_DIFFERENT_ARGUMENTS") {
            _ = try executor.executeFile(
                call(.create, ["path": "workspace/replay.txt", "content": "different"]),
                callID: "completed-call"
            )
        }

        let pending = call(.create, ["path": "workspace/pending.txt", "content": "never blind replay"])
        guard case .ready = try executor.prepare(pending, callID: "pending-call") else {
            fatalError("new call did not persist a pending journal")
        }
        try expectError("UNCERTAIN_PRIOR_CALL_REQUIRES_READBACK") {
            _ = try executor.prepare(pending, callID: "pending-call")
        }
        require(storage.files["workspace/pending.txt"] == nil, "pending call executed during recovery inspection")
    }

    static func explicitProviderSessionAuthorizationAndTimeline() throws {
        var savedPolicy = ResourcePolicy()
        savedPolicy.provider = "local"
        savedPolicy.cloudAllowed = true
        var routedPolicy = savedPolicy
        routedPolicy.provider = "chatgpt"
        var session = ShortcutSession(
            id: "siri-chatgpt",
            goal: "Use the explicitly selected provider",
            policy: routedPolicy,
            authorizationPolicy: savedPolicy,
            started: Date(timeIntervalSince1970: 0),
            initialBattery: 90,
            providerSelection: .chatgpt,
            taskOrigin: .appIntent,
            shortcutAdapterName: "Agent Step - ChatGPT",
            routingEvidence: qualifiedExternalEvidence(selection: .chatgpt, provider: .chatgpt)
        )
        require(session.policy.provider == "chatgpt" && session.authorizationMatches(savedPolicy), "explicit Siri route was mistaken for an authorization change")
        var corruptSession = try JSONSerialization.jsonObject(with: JSONEncoder().encode(session)) as! [String: Any]
        corruptSession["shortcutAdapterName"] = ""
        do {
            _ = try JSONDecoder().decode(ShortcutSession.self, from: JSONSerialization.data(withJSONObject: corruptSession))
            fatalError("current Shortcut session accepted missing adapter identity")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_SHORTCUT_SESSION_ADAPTER", "invalid session adapter returned the wrong error")
        }
        var negativeStep = try JSONSerialization.jsonObject(with: JSONEncoder().encode(session)) as! [String: Any]
        negativeStep["step"] = -100
        do {
            _ = try JSONDecoder().decode(ShortcutSession.self, from: JSONSerialization.data(withJSONObject: negativeStep))
            fatalError("current Shortcut session accepted a negative step counter")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_SHORTCUT_SESSION_STATE", "negative session step returned the wrong error")
        }

        var substitutedSaved = try JSONSerialization.jsonObject(with: JSONEncoder().encode(session)) as! [String: Any]
        substitutedSaved["providerSelection"] = "saved"
        var substitutedEvidence = substitutedSaved["routingEvidence"] as! [String: Any]
        substitutedEvidence["selection"] = "saved"
        substitutedEvidence["strategy"] = "saved-pinned"
        substitutedSaved["routingEvidence"] = substitutedEvidence
        do {
            _ = try JSONDecoder().decode(ShortcutSession.self, from: JSONSerialization.data(withJSONObject: substitutedSaved))
            fatalError("Saved Shortcut session substituted a provider outside the saved authorization")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_STRATEGY", "Saved provider substitution returned the wrong error")
        }

        let prompt = ProviderHandoffPromptHeader(provider: .chatgpt, selection: .chatgpt, origin: .appIntent).jsonLine + "\nTask"
        session.trace.append(try ProviderHandoffTrace.outbound(provider: .chatgpt, selection: .chatgpt, origin: .appIntent, adapterName: session.shortcutAdapterName, actionIndex: 0, prompt: prompt))
        let response = "{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}"
        guard let actionIndex = try session.beginDistinctResponse(response) else { fatalError("explicit provider response was rejected") }
        session.trace.append(try ProviderHandoffTrace.inbound(provider: .chatgpt, selection: .chatgpt, origin: .appIntent, adapterName: session.shortcutAdapterName, actionIndex: actionIndex, response: response))
        require(session.step == 1 && session.failures == 0, "handoff telemetry changed response accounting")
        require(session.trace.map(\.tool) == ["provider.handoff.outbound", "provider.handoff.inbound"], "explicit provider round trip was not recorded in order")

        var changedResources = savedPolicy
        changedResources.maxSteps += 1
        require(!session.authorizationMatches(changedResources), "resource authorization changed without blocking the session")
        var revokedCloud = savedPolicy
        revokedCloud.cloudAllowed = false
        require(!session.authorizationMatches(revokedCloud), "cloud authorization revocation changed without blocking the session")
    }

    static func distinctResponseAccounting() throws {
        var policy = ResourcePolicy()
        policy.provider = "local"
        var session = ShortcutSession(
            id: "response-run",
            goal: "Count distinct responses",
            policy: policy,
            authorizationPolicy: policy,
            started: Date(timeIntervalSince1970: 0),
            initialBattery: 90,
            providerSelection: .bestLocal,
            taskOrigin: .appIntent,
            shortcutAdapterName: "Agent Step - Local",
            routingEvidence: qualifiedExternalEvidence(selection: .bestLocal, provider: .local)
        )

        try AgentAction.requireBoundedResponse(String(repeating: "x", count: AgentAction.maximumResponseBytes))
        let oversized = String(repeating: "x", count: AgentAction.maximumResponseBytes + 1)
        let initialStep = session.step
        let initialHash = session.lastResponseHash
        let initialTrace = session.trace
        try expectError("PROVIDER_RESPONSE_TOO_LARGE") { _ = try session.beginDistinctResponse(oversized) }
        require(session.step == initialStep && session.lastResponseHash == initialHash && session.trace.count == initialTrace.count, "oversized response mutated session state before rejection")

        let firstIndex = try session.beginDistinctResponse("malformed-a")
        require(firstIndex == 0, "first response used the wrong step")
        session.recordFailedResponse("INVALID_ACTION_JSON")
        require(session.step == 1 && session.failures == 1 && session.repeated == 1, "first malformed response was counted incorrectly")

        let duplicateIndex = try session.beginDistinctResponse("malformed-a")
        require(duplicateIndex == nil, "duplicate response was admitted twice")
        require(session.step == 1 && session.failures == 1, "duplicate response changed counters")

        let secondIndex = try session.beginDistinctResponse("malformed-b")
        require(secondIndex == 1, "second distinct response used the wrong step")
        session.recordFailedResponse("INVALID_ACTION_JSON")
        require(session.step == 2 && session.failures == 2 && session.repeated == 2, "distinct malformed response was not counted")

        let finalResponse = "{\"kind\":\"final\",\"summary\":\"done\"}"
        let finalIndex = try session.beginDistinctResponse(finalResponse)
        require(finalIndex == 2 && session.step == 3, "terminal response was omitted from the step count")
        session.recordSuccessfulResponse()
        require(session.lastFailure.isEmpty && session.repeated == 0, "successful response did not clear the repeated-failure state")

        let encoded = try JSONEncoder().encode(session)
        let restored = try JSONDecoder().decode(ShortcutSession.self, from: encoded)
        require(restored.step == 3 && restored.failures == 2 && restored.lastResponseHash == session.lastResponseHash, "response accounting did not survive checkpoint encoding")
        require(restored.providerSelection == .bestLocal && restored.taskOrigin == .appIntent, "provider route did not survive checkpoint encoding")
        require(restored.shortcutAdapterName == "Agent Step - Local", "provider adapter did not survive checkpoint encoding")

        var mismatchedRoute = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        var mismatchedPolicy = mismatchedRoute["policy"] as! [String: Any]
        mismatchedPolicy["provider"] = "claude"
        mismatchedRoute["policy"] = mismatchedPolicy
        var mismatchedEvidence = mismatchedRoute["routingEvidence"] as! [String: Any]
        mismatchedEvidence["provider"] = "claude"
        mismatchedEvidence["selection"] = "chatgpt"
        mismatchedEvidence["strategy"] = "explicit-pinned"
        mismatchedRoute["routingEvidence"] = mismatchedEvidence
        mismatchedRoute["providerSelection"] = "chatgpt"
        do {
            _ = try JSONDecoder().decode(ShortcutSession.self, from: JSONSerialization.data(withJSONObject: mismatchedRoute))
            fatalError("Shortcut session accepted a mutually consistent outer policy with malformed explicit route evidence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "INVALID_PROVIDER_ROUTING_SELECTION", "malformed explicit session route returned the wrong error")
        }

        var legacy = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        for key in ["recordType", "schemaVersion", "contract", "latestResult", "lastReadEvidence", "lastResponseHash", "authorizationPolicy", "providerSelection", "taskOrigin", "shortcutAdapterName"] {
            legacy.removeValue(forKey: key)
        }
        let migrated = try JSONDecoder().decode(
            ShortcutSession.self,
            from: JSONSerialization.data(withJSONObject: legacy)
        )
        require(migrated.step == 3 && migrated.lastResponseHash.isEmpty, "legacy Shortcut session did not migrate with safe response defaults")
        require(migrated.providerSelection == .saved && migrated.taskOrigin == .app, "legacy Shortcut session did not migrate with safe route defaults")
        require(migrated.requiresLegacyRestart, "legacy Shortcut session was resumable without current adapter and route evidence")
        require(!restored.requiresLegacyRestart, "current Shortcut session was incorrectly marked legacy")
        require(migrated.shortcutAdapterName.isEmpty, "legacy Shortcut session invented an adapter name")
        require(migrated.authorizationPolicy == migrated.policy, "legacy Shortcut session did not preserve its original authorization policy")
    }
}
