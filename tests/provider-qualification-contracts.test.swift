import CryptoKit
import Foundation

@main
enum ProviderQualificationLedgerContracts {
    enum InjectedFailure: Error { case read, write, adapter, reset }

    static func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() {
            throw NSError(
                domain: "ProviderQualificationLedgerContracts",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: message]
            )
        }
    }

    static func signedData(_ payload: ProviderQualificationLedgerPayload, key: SymmetricKey) throws -> Data {
        let canonical = try JSONEncoder.sorted.encode(payload)
        let signature = Data(HMAC<SHA256>.authenticationCode(for: canonical, using: key))
            .map { String(format: "%02x", $0) }
            .joined()
        return try JSONEncoder.sorted.encode(
            SignedProviderQualificationLedger(payload: payload, hmacSHA256: signature)
        )
    }

    static func mutate(
        _ data: Data,
        _ mutation: (inout [String: Any]) throws -> Void
    ) throws -> Data {
        var object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        try mutation(&object)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    static func localAttempt(
        index: Int,
        probe: ProviderQualificationProbe,
        outcome: ProviderQualificationOutcome,
        reconciled: Bool,
        epoch: String,
        adapterSHA256: String,
        now: Date
    ) -> ProviderQualificationAttempt {
        ProviderQualificationAttempt(
            attemptID: String(format: "10000000-0000-4000-8000-%012d", index),
            provider: .local,
            epochSHA256: epoch,
            adapterSHA256: adapterSHA256,
            probe: probe,
            outcome: outcome,
            schemaPassCount: outcome == .verified ? 1 : 0,
            assertionPassCount: outcome == .verified ? 1 : 0,
            assertionCount: 1,
            promptCharacterCount: 2_000,
            durationBucketMilliseconds: outcome == .started ? 0 : 500,
            appIntentReturnObserved: true,
            adapterStateReconciled: reconciled,
            startedAt: now.addingTimeInterval(TimeInterval(index)),
            finishedAt: outcome == .started ? nil : now.addingTimeInterval(TimeInterval(index + 1))
        )
    }

    static func snapshot(
        attempts: [ProviderQualificationAttempt],
        epoch: String,
        adapterSHA256: String
    ) -> ProviderQualificationSnapshot {
        let verified = attempts.filter { $0.outcome == .verified }
        return ProviderQualificationSnapshot(
            provider: .local,
            epochSHA256: epoch,
            adapterSHA256: adapterSHA256,
            sampleCount: attempts.count,
            distinctProbeCount: Set(attempts.map(\.probe)).count,
            verifiedCount: verified.count,
            schemaPassCount: attempts.reduce(0) { $0 + ($1.schemaPassCount ?? 0) },
            assertionPassCount: attempts.reduce(0) { $0 + $1.assertionPassCount },
            assertionCount: attempts.reduce(0) { $0 + $1.assertionCount },
            toolProbePassCount: Set(verified.filter { $0.probe.isToolProbe }.map(\.probe)).count,
            maximumContextCharacters: verified.map(\.promptCharacterCount).max() ?? 0,
            medianDurationBucketMilliseconds: 500,
            integrityFaultCount: attempts.filter { $0.outcome == .integrityFault }.count,
            appIntentReturnObserved: Set(verified.filter(\.appIntentReturnObserved).map(\.probe)).count == ProviderQualificationSnapshot.requiredDistinctProbes,
            lastSuccessfulAt: "2026-09-11T00:00:00Z"
        )
    }

    @MainActor
    static func testSigningKeyTransactions() throws {
        var readFailureGenerationCount = 0
        var readFailureWriteCount = 0
        do {
            _ = try ProviderQualificationStore.resolveSigningKey(using: ProviderQualificationSigningKeyOperations(
                readChecked: { throw InjectedFailure.read },
                generateRandomBytes: {
                    readFailureGenerationCount += 1
                    return Data(repeating: 0x11, count: 32)
                },
                writeChecked: { _ in readFailureWriteCount += 1 }
            ))
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 26, userInfo: [NSLocalizedDescriptionKey: "retained-key read failure generated a replacement key"])
        } catch InjectedFailure.read {}
        try check(readFailureGenerationCount == 0 && readFailureWriteCount == 0, "retained-key read failure generated or wrote a replacement key")

        var malformedGenerationCount = 0
        var malformedWriteCount = 0
        do {
            _ = try ProviderQualificationStore.resolveSigningKey(using: ProviderQualificationSigningKeyOperations(
                readChecked: { "malformed-retained-key" },
                generateRandomBytes: {
                    malformedGenerationCount += 1
                    return Data(repeating: 0x22, count: 32)
                },
                writeChecked: { _ in malformedWriteCount += 1 }
            ))
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 27, userInfo: [NSLocalizedDescriptionKey: "malformed retained key generated a replacement key"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}
        try check(malformedGenerationCount == 0 && malformedWriteCount == 0, "malformed retained key generated or wrote a replacement key")

        let generated = Data((0..<32).map(UInt8.init))
        var stored: String?
        var readCount = 0
        var generationCount = 0
        var writeCount = 0
        let created = try ProviderQualificationStore.resolveSigningKey(using: ProviderQualificationSigningKeyOperations(
            readChecked: {
                readCount += 1
                return stored
            },
            generateRandomBytes: {
                generationCount += 1
                return generated
            },
            writeChecked: { encoded in
                writeCount += 1
                stored = encoded
            }
        ))
        let createdBytes = created.withUnsafeBytes { Data($0) }
        try check(readCount == 2, "new signing key was not checked-read exactly once after its initial missing read")
        try check(generationCount == 1 && writeCount == 1, "true missing state did not generate and write exactly one key")
        try check(stored == generated.base64EncodedString() && createdBytes == generated, "new signing key did not pass exact persisted-byte readback")

        var mismatchReadCount = 0
        var mismatchWriteCount = 0
        do {
            _ = try ProviderQualificationStore.resolveSigningKey(using: ProviderQualificationSigningKeyOperations(
                readChecked: {
                    mismatchReadCount += 1
                    return mismatchReadCount == 1 ? nil : Data(repeating: 0x44, count: 32).base64EncodedString()
                },
                generateRandomBytes: { Data(repeating: 0x33, count: 32) },
                writeChecked: { _ in mismatchWriteCount += 1 }
            ))
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 28, userInfo: [NSLocalizedDescriptionKey: "mismatched signing-key readback was accepted"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}
        try check(mismatchReadCount == 2 && mismatchWriteCount == 1, "new signing key did not require one exact checked readback")
    }

    @MainActor
    static func testCompletionTransactions(now: Date) throws {
        let epoch = String(repeating: "c", count: 64)
        var adapter = ShortcutAdapter(name: AppProvider.local.shortcut, tested: false)
        let adapterDigest = ProviderQualificationStore.adapterSHA256(adapter)
        let firstStarted = localAttempt(
            index: 1,
            probe: .strictJSON,
            outcome: .started,
            reconciled: false,
            epoch: epoch,
            adapterSHA256: adapterDigest,
            now: now
        )
        let firstCompleted = localAttempt(
            index: 1,
            probe: .strictJSON,
            outcome: .verified,
            reconciled: false,
            epoch: epoch,
            adapterSHA256: adapterDigest,
            now: now
        )
        var persisted = ProviderQualificationLedgerPayload(
            recordType: "provider-qualification-ledger",
            schemaVersion: ProviderQualificationLedgerPayload.currentSchemaVersion,
            suiteVersion: ProviderQualificationStore.suiteVersion,
            attempts: [firstStarted],
            recommendation: nil
        )
        var markShouldFail = true
        do {
            var working = persisted
            _ = try ProviderQualificationStore.persistAndReconcileCompletion(
                ledger: &working,
                index: 0,
                completedAttempt: firstCompleted,
                expectedEpochSHA256: epoch,
                expectedAdapterSHA256: adapterDigest,
                saveLedger: { persisted = $0 },
                markMeasuredRoundTrip: { _ in
                    if markShouldFail { markShouldFail = false; throw InjectedFailure.adapter }
                    adapter.tested = true
                },
                readAdapter: { _ in adapter }
            )
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 20, userInfo: [NSLocalizedDescriptionKey: "adapter failure was ignored"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}
        try check(persisted.attempts[0].outcome == .verified, "terminal ledger state was not durable before adapter reconciliation")
        try check(persisted.attempts[0].adapterStateReconciled == false, "failed adapter persistence was recorded as reconciled")

        var retry = persisted
        let retried = try ProviderQualificationStore.persistAndReconcileCompletion(
            ledger: &retry,
            index: 0,
            completedAttempt: nil,
            expectedEpochSHA256: epoch,
            expectedAdapterSHA256: adapterDigest,
            saveLedger: { persisted = $0 },
            markMeasuredRoundTrip: { _ in adapter.tested = true },
            readAdapter: { _ in adapter }
        )
        try check(retried.adapterStateReconciled == true && persisted.attempts[0].adapterStateReconciled == true, "terminal retry did not converge adapter and signed ledger state")

        let probes = ProviderQualificationProbe.allCases
        let completedFour = probes.prefix(4).enumerated().map { offset, probe in
            localAttempt(
                index: offset + 10,
                probe: probe,
                outcome: .verified,
                reconciled: true,
                epoch: epoch,
                adapterSHA256: adapterDigest,
                now: now
            )
        }
        let fifthStarted = localAttempt(
            index: 14,
            probe: probes[4],
            outcome: .started,
            reconciled: false,
            epoch: epoch,
            adapterSHA256: adapterDigest,
            now: now
        )
        let fifthCompleted = localAttempt(
            index: 14,
            probe: probes[4],
            outcome: .verified,
            reconciled: false,
            epoch: epoch,
            adapterSHA256: adapterDigest,
            now: now
        )
        adapter.tested = true
        persisted = ProviderQualificationLedgerPayload(
            recordType: "provider-qualification-ledger",
            schemaVersion: ProviderQualificationLedgerPayload.currentSchemaVersion,
            suiteVersion: ProviderQualificationStore.suiteVersion,
            attempts: completedFour + [fifthStarted],
            recommendation: nil
        )
        var saveCount = 0
        do {
            var working = persisted
            _ = try ProviderQualificationStore.persistAndReconcileCompletion(
                ledger: &working,
                index: 4,
                completedAttempt: fifthCompleted,
                expectedEpochSHA256: epoch,
                expectedAdapterSHA256: adapterDigest,
                saveLedger: { candidate in
                    saveCount += 1
                    if saveCount == 2 { throw InjectedFailure.write }
                    persisted = candidate
                },
                markMeasuredRoundTrip: { _ in throw InjectedFailure.adapter },
                readAdapter: { _ in adapter }
            )
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 21, userInfo: [NSLocalizedDescriptionKey: "second signed-ledger failure was ignored"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}
        let preRetryScored = ProviderQualificationStore.scoredAttempts(provider: .local, epochSHA256: epoch, now: now.addingTimeInterval(30), attempts: persisted.attempts)
        try check(preRetryScored.count == 4, "unreconciled fifth probe became scoring-eligible")
        let blockedRoute = ProviderRoutingPolicy.resolve(
            selection: .local,
            savedProvider: .local,
            appleAvailability: .unavailable("test"),
            shortcutsAvailable: true,
            adapterFor: { _ in adapter },
            cloudAllowed: false,
            qualifications: [.local: snapshot(attempts: preRetryScored, epoch: epoch, adapterSHA256: adapterDigest)],
            requirements: .filesystem(policyContextCharacters: 2_000, localOnly: true, unattended: false)
        )
        try check(!blockedRoute.decision.isRunnable, "fifth-probe partial commit exposed a runnable route")

        retry = persisted
        _ = try ProviderQualificationStore.persistAndReconcileCompletion(
            ledger: &retry,
            index: 4,
            completedAttempt: nil,
            expectedEpochSHA256: epoch,
            expectedAdapterSHA256: adapterDigest,
            saveLedger: { persisted = $0 },
            markMeasuredRoundTrip: { _ in throw InjectedFailure.adapter },
            readAdapter: { _ in adapter }
        )
        let postRetryScored = ProviderQualificationStore.scoredAttempts(provider: .local, epochSHA256: epoch, now: now.addingTimeInterval(30), attempts: persisted.attempts)
        try check(postRetryScored.count == 5, "fifth-probe retry did not restore the complete suite")
        let runnableRoute = ProviderRoutingPolicy.resolve(
            selection: .local,
            savedProvider: .local,
            appleAvailability: .unavailable("test"),
            shortcutsAvailable: true,
            adapterFor: { _ in adapter },
            cloudAllowed: false,
            qualifications: [.local: snapshot(attempts: postRetryScored, epoch: epoch, adapterSHA256: adapterDigest)],
            requirements: .filesystem(policyContextCharacters: 2_000, localOnly: true, unattended: false)
        )
        try check(runnableRoute.decision.isRunnable, "fully reconciled fifth-probe retry remained blocked")
    }

    @MainActor
    static func testAppleProbePersistenceFailuresPropagate() async throws {
        let validator = ExecutionContinuationValidator {}
        var successfulResponseCompletionCalls = 0
        do {
            try await ProviderQualificationStore.performAppleQualificationProbe(
                continuationValidator: validator,
                providerResponse: { "valid-provider-response" },
                persistCompletion: { _, _ in
                    successfulResponseCompletionCalls += 1
                    throw InjectedFailure.write
                }
            )
            throw NSError(
                domain: "ProviderQualificationLedgerContracts",
                code: 24,
                userInfo: [NSLocalizedDescriptionKey: "successful-response persistence failure was ignored"]
            )
        } catch InjectedFailure.write {}
        try check(successfulResponseCompletionCalls == 1, "completion persistence was retried as a provider failure")

        var providerFailureCompletionCalls = 0
        do {
            try await ProviderQualificationStore.performAppleQualificationProbe(
                continuationValidator: validator,
                providerResponse: { throw InjectedFailure.adapter },
                persistCompletion: { response, appIntentTransportObserved in
                    providerFailureCompletionCalls += 1
                    try check(response == "{}" && appIntentTransportObserved, "provider failure completion lost its observed-return evidence")
                    throw InjectedFailure.write
                }
            )
            throw NSError(
                domain: "ProviderQualificationLedgerContracts",
                code: 25,
                userInfo: [NSLocalizedDescriptionKey: "provider-failure persistence failure was ignored"]
            )
        } catch InjectedFailure.write {}
        try check(providerFailureCompletionCalls == 1, "provider-failure completion persistence did not fail exactly once")

        var recordedProviderFailure: (response: String, appIntentTransportObserved: Bool)?
        try await ProviderQualificationStore.performAppleQualificationProbe(
            continuationValidator: validator,
            providerResponse: { throw InjectedFailure.adapter },
            persistCompletion: { response, appIntentTransportObserved in
                recordedProviderFailure = (response, appIntentTransportObserved)
            }
        )
        try check(
            recordedProviderFailure?.response == "{}" && recordedProviderFailure?.appIntentTransportObserved == true,
            "current-generation provider failure no longer records one durable failed attempt"
        )
    }

    @MainActor
    static func testResetTransactions() throws {
        var ledgerExists = true
        var signingKeyExists = true
        var adapters = Set(AppProvider.allCases.filter { $0 != .apple })
        var ledgerFailurePending = true
        var adapterFailurePending = true
        let operations = ProviderQualificationResetOperations(
            qualificationIsActive: { false },
            removeLedgerChecked: {
                if ledgerFailurePending { ledgerFailurePending = false; throw InjectedFailure.reset }
                ledgerExists = false
            },
            ledgerExists: { ledgerExists },
            deleteSigningKeyChecked: { signingKeyExists = false },
            signingKeyExists: { signingKeyExists },
            invalidateAdapterState: { provider in
                if provider == .grok && adapterFailurePending {
                    adapterFailurePending = false
                    throw InjectedFailure.reset
                }
                adapters.remove(provider)
            },
            adapterStateExists: { adapters.contains($0) }
        )
        do { try ProviderQualificationStore.reset(using: operations) }
        catch {}
        try check(ledgerExists && signingKeyExists, "reset continued after checked ledger deletion failed")
        do { try ProviderQualificationStore.reset(using: operations) }
        catch {}
        try check(!ledgerExists && !signingKeyExists && adapters.contains(.grok), "partial reset did not stop at the injected adapter failure")
        try ProviderQualificationStore.reset(using: operations)
        try check(!ledgerExists && !signingKeyExists && adapters.isEmpty, "reset retry did not converge all persisted state to absent")

        let unverifiable = ProviderQualificationResetOperations(
            qualificationIsActive: { false },
            removeLedgerChecked: {},
            ledgerExists: { true },
            deleteSigningKeyChecked: {},
            signingKeyExists: { false },
            invalidateAdapterState: { _ in },
            adapterStateExists: { _ in false }
        )
        do {
            try ProviderQualificationStore.reset(using: unverifiable)
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 22, userInfo: [NSLocalizedDescriptionKey: "reset reported success without absent-state readback"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}

        let unreadableHMAC = ProviderQualificationResetOperations(
            qualificationIsActive: { false },
            removeLedgerChecked: {},
            ledgerExists: { false },
            deleteSigningKeyChecked: {},
            signingKeyExists: { throw InjectedFailure.reset },
            invalidateAdapterState: { _ in },
            adapterStateExists: { _ in false }
        )
        do {
            try ProviderQualificationStore.reset(using: unreadableHMAC)
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 23, userInfo: [NSLocalizedDescriptionKey: "reset reported success with unreadable HMAC state"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}
    }

    @MainActor
    static func testExternalQualificationAuthorization() throws {
        let defaults = UserDefaults.standard
        let previousPolicy = defaults.object(forKey: "policy")
        defer {
            if let previousPolicy { defaults.set(previousPolicy, forKey: "policy") }
            else { defaults.removeObject(forKey: "policy") }
        }
        let ledgerURL = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: false
        ).appendingPathComponent("LocalSandboxPrivateRouting/provider-qualification-ledger.json")
        let ledgerExisted = FileManager.default.fileExists(atPath: ledgerURL.path)
        let ledgerBefore = ledgerExisted ? try Data(contentsOf: ledgerURL) : nil
        let cloudProviders: [AppProvider] = [.chatgpt, .grok, .grokbot, .claude]
        let pendingID = "00000000-0000-4000-8000-000000000099"
        var pendingReads = 0
        var creations = 0
        var handedOff = 0
        var saved = ResourcePolicy()
        saved.contextChars = 2_000
        var unsavedDraft = saved
        unsavedDraft.cloudAllowed = true
        unsavedDraft.contextChars = 12_000
        try check(unsavedDraft.cloudAllowed, "unsaved draft fixture does not enable cloud")

        func authorize(_ provider: AppProvider, pending: String? = nil) throws -> ProviderQualificationChallenge {
            let challenge = try ProviderQualificationStore.externalChallenge(
                provider: provider,
                pendingAttemptID: pending,
                appIntentTransportObserved: true,
                loadPending: { requested in
                    pendingReads += 1
                    return ProviderQualificationChallenge(
                        attemptID: pendingID,
                        provider: requested,
                        probe: .strictJSON,
                        adapterName: requested.shortcut,
                        prompt: "current protected-store challenge"
                    )
                },
                createChallenge: { requested, context, observed in
                    creations += 1
                    try check(context == saved.contextChars, "qualification used the unsaved draft context cap")
                    try check(observed, "App Intent transport marker was lost")
                    return ProviderQualificationChallenge(
                        attemptID: pendingID,
                        provider: requested,
                        probe: .strictJSON,
                        adapterName: requested.shortcut,
                        prompt: "new authorized challenge"
                    )
                }
            )
            handedOff += 1
            return challenge
        }

        for policyData: Data? in [nil, Data("malformed policy".utf8), try JSONEncoder().encode(saved)] {
            if let policyData { defaults.set(policyData, forKey: "policy") }
            else { defaults.removeObject(forKey: "policy") }
            for provider in cloudProviders {
                for pending: String? in [nil, pendingID] {
                    do {
                        _ = try authorize(provider, pending: pending)
                        throw InjectedFailure.write
                    } catch is SandboxError {}
                }
                do {
                    _ = try ProviderQualificationStore.begin(provider: provider, contextCharacters: unsavedDraft.contextChars)
                    throw InjectedFailure.write
                } catch is SandboxError {}
            }
        }
        try check(pendingReads == 0 && creations == 0 && handedOff == 0,
                  "denied, missing, or malformed saved authorization reached the ledger or handoff")
        try check(FileManager.default.fileExists(atPath: ledgerURL.path) == ledgerExisted,
                  "denied qualification created or removed the protected ledger")
        if let ledgerBefore {
            let ledgerAfter = try Data(contentsOf: ledgerURL)
            try check(ledgerAfter == ledgerBefore,
                      "denied qualification changed protected ledger bytes")
        }

        defaults.set(try JSONEncoder().encode(saved), forKey: "policy")
        let local = try authorize(.local)
        try check(local.provider == .local && creations == 1 && handedOff == 1,
                  "saved local-only authorization no longer admits Locally")
        saved.cloudAllowed = true
        defaults.set(try JSONEncoder().encode(saved), forKey: "policy")
        for provider in cloudProviders {
            let cloud = try authorize(provider)
            try check(cloud.provider == provider, "allowed cloud provider was changed")
        }
        let pending = try authorize(.chatgpt, pending: pendingID)
        try check(pending.prompt == "current protected-store challenge" && pendingReads == 1,
                  "pending handoff did not reread its protected-store challenge")

        let readsBeforeRevocation = pendingReads
        let creationsBeforeRevocation = creations
        let handoffsBeforeRevocation = handedOff
        saved.cloudAllowed = false
        defaults.set(try JSONEncoder().encode(saved), forKey: "policy")
        do {
            _ = try authorize(.chatgpt, pending: pendingID)
            throw InjectedFailure.write
        } catch is SandboxError {}
        try check(pendingReads == readsBeforeRevocation && creations == creationsBeforeRevocation && handedOff == handoffsBeforeRevocation,
                  "revoked pending cloud qualification read, rewrote, or handed off its challenge")

        saved.cloudAllowed = true
        defaults.set(try JSONEncoder().encode(saved), forKey: "policy")
        for retainedChallenge: ProviderQualificationChallenge? in [
            nil,
            ProviderQualificationChallenge(attemptID: "changed-attempt", provider: .chatgpt, probe: .strictJSON, adapterName: AppProvider.chatgpt.shortcut, prompt: "current"),
            ProviderQualificationChallenge(attemptID: pendingID, provider: .claude, probe: .strictJSON, adapterName: AppProvider.claude.shortcut, prompt: "current"),
            ProviderQualificationChallenge(attemptID: pendingID, provider: .chatgpt, probe: .boundedContext, adapterName: AppProvider.chatgpt.shortcut, prompt: String(repeating: "x", count: saved.contextChars + 1)),
        ] {
            do {
                _ = try ProviderQualificationStore.externalChallenge(
                    provider: .chatgpt,
                    pendingAttemptID: pendingID,
                    loadPending: { _ in retainedChallenge },
                    createChallenge: { _, _, _ in
                        creations += 1
                        throw InjectedFailure.write
                    }
                )
                throw InjectedFailure.write
            } catch is SandboxError {}
        }
        try check(creations == creationsBeforeRevocation,
                  "stale, mismatched, or oversized pending challenge created a replacement")
    }

    @MainActor
    static func main() async throws {
        let key = SymmetricKey(data: Data(repeating: 0xA5, count: 32))
        let now = Date(timeIntervalSince1970: 1_788_921_600)
        let hash = String(repeating: "a", count: 64)
        let attempt = ProviderQualificationAttempt(
            attemptID: "00000000-0000-4000-8000-000000000001",
            provider: .apple,
            epochSHA256: hash,
            adapterSHA256: nil,
            probe: .strictJSON,
            outcome: .verified,
            schemaPassCount: 1,
            assertionPassCount: 1,
            assertionCount: 1,
            promptCharacterCount: 2_000,
            durationBucketMilliseconds: 500,
            appIntentReturnObserved: true,
            startedAt: now,
            finishedAt: now.addingTimeInterval(1)
        )
        let recommendation = OraclePinnedRecommendation(
            provider: .apple,
            configurationSHA256: String(repeating: "b", count: 64),
            qualificationEpochSHA256: hash,
            appliedAt: now
        )
        let payload = ProviderQualificationLedgerPayload(
            recordType: "provider-qualification-ledger",
            schemaVersion: ProviderQualificationLedgerPayload.currentSchemaVersion,
            suiteVersion: ProviderQualificationStore.suiteVersion,
            attempts: [attempt],
            recommendation: recommendation
        )
        let baseline = try signedData(payload, key: key)
        let decoded = try ProviderQualificationStore.decodeAuthenticatedLedger(baseline, key: key, now: now)
        try check(decoded.attempts.count == 1, "valid signed provider qualification ledger was rejected")

        let originalSignature = (try JSONSerialization.jsonObject(with: baseline) as! [String: Any])["hmacSHA256"] as! String
        let unknownMutations: [(String, ([String: Any]) throws -> Data)] = [
            ("wrapper", { _ in
                try mutate(baseline) { $0["unexpected"] = true }
            }),
            ("payload", { _ in
                try mutate(baseline) { root in
                    var value = root["payload"] as! [String: Any]
                    value["unexpected"] = true
                    root["payload"] = value
                }
            }),
            ("attempt", { _ in
                try mutate(baseline) { root in
                    var value = root["payload"] as! [String: Any]
                    var attempts = value["attempts"] as! [[String: Any]]
                    attempts[0]["unexpected"] = true
                    value["attempts"] = attempts
                    root["payload"] = value
                }
            }),
            ("recommendation", { _ in
                try mutate(baseline) { root in
                    var value = root["payload"] as! [String: Any]
                    var recommendation = value["recommendation"] as! [String: Any]
                    recommendation["unexpected"] = true
                    value["recommendation"] = recommendation
                    root["payload"] = value
                }
            }),
        ]
        for (level, makeMutation) in unknownMutations {
            let mutated = try makeMutation([:])
            let retainedSignature = (try JSONSerialization.jsonObject(with: mutated) as! [String: Any])["hmacSHA256"] as! String
            try check(retainedSignature == originalSignature, "\(level) mutation did not retain its otherwise-valid HMAC")
            do {
                _ = try ProviderQualificationStore.decodeAuthenticatedLedger(mutated, key: key, now: now)
                throw NSError(
                    domain: "ProviderQualificationLedgerContracts",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "signed ledger accepted unknown \(level) member"]
                )
            } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
                throw error
            } catch {}
        }

        let legacyAttempt = ProviderQualificationAttempt(
            attemptID: "00000000-0000-4000-8000-000000000002",
            provider: .apple,
            epochSHA256: hash,
            adapterSHA256: nil,
            probe: .readTool,
            outcome: .verified,
            schemaPassCount: nil,
            assertionPassCount: 1,
            assertionCount: 1,
            promptCharacterCount: 2_000,
            durationBucketMilliseconds: 500,
            appIntentReturnObserved: true,
            adapterStateReconciled: nil,
            startedAt: now.addingTimeInterval(-86_400),
            finishedAt: now.addingTimeInterval(-86_399)
        )
        let legacyPayload = ProviderQualificationLedgerPayload(
            recordType: "provider-qualification-ledger",
            schemaVersion: 1,
            suiteVersion: ProviderQualificationStore.suiteVersion,
            attempts: [legacyAttempt],
            recommendation: nil
        )
        let legacyData = try signedData(legacyPayload, key: key)
        let decodedLegacy = try ProviderQualificationStore.decodeAuthenticatedLedger(legacyData, key: key, now: now)
        try check(decodedLegacy.schemaVersion == 1 && decodedLegacy.attempts[0].schemaPassCount == nil, "valid schema v1 ledger did not retain its legacy metric shape")

        let illegalLegacyAttempt = ProviderQualificationAttempt(
            attemptID: legacyAttempt.attemptID,
            provider: legacyAttempt.provider,
            epochSHA256: legacyAttempt.epochSHA256,
            adapterSHA256: legacyAttempt.adapterSHA256,
            probe: legacyAttempt.probe,
            outcome: legacyAttempt.outcome,
            schemaPassCount: 1,
            assertionPassCount: legacyAttempt.assertionPassCount,
            assertionCount: legacyAttempt.assertionCount,
            promptCharacterCount: legacyAttempt.promptCharacterCount,
            durationBucketMilliseconds: legacyAttempt.durationBucketMilliseconds,
            appIntentReturnObserved: legacyAttempt.appIntentReturnObserved,
            startedAt: legacyAttempt.startedAt,
            finishedAt: legacyAttempt.finishedAt
        )
        let illegalLegacyPayload = ProviderQualificationLedgerPayload(
            recordType: legacyPayload.recordType,
            schemaVersion: 1,
            suiteVersion: legacyPayload.suiteVersion,
            attempts: [illegalLegacyAttempt],
            recommendation: nil
        )
        do {
            _ = try ProviderQualificationStore.decodeAuthenticatedLedger(try signedData(illegalLegacyPayload, key: key), key: key, now: now)
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 3, userInfo: [NSLocalizedDescriptionKey: "schema v1 accepted the schema v2 metric field"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}

        let missingV2Metric = try mutate(baseline) { root in
            var value = root["payload"] as! [String: Any]
            var attempts = value["attempts"] as! [[String: Any]]
            attempts[0].removeValue(forKey: "schemaPassCount")
            value["attempts"] = attempts
            root["payload"] = value
        }
        do {
            _ = try ProviderQualificationStore.decodeAuthenticatedLedger(missingV2Metric, key: key, now: now)
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 4, userInfo: [NSLocalizedDescriptionKey: "schema v2 accepted a missing schema metric"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}

        let missingReconciliationMetric = try mutate(baseline) { root in
            var value = root["payload"] as! [String: Any]
            var attempts = value["attempts"] as! [[String: Any]]
            attempts[0].removeValue(forKey: "adapterStateReconciled")
            value["attempts"] = attempts
            root["payload"] = value
        }
        do {
            _ = try ProviderQualificationStore.decodeAuthenticatedLedger(missingReconciliationMetric, key: key, now: now)
            throw NSError(domain: "ProviderQualificationLedgerContracts", code: 5, userInfo: [NSLocalizedDescriptionKey: "schema v3 accepted a missing adapter reconciliation metric"])
        } catch let error as NSError where error.domain == "ProviderQualificationLedgerContracts" {
            throw error
        } catch {}

        let legacyAdapter = ShortcutAdapter(name: AppProvider.local.shortcut)
        let legacyAdapterDigest = ProviderQualificationStore.adapterSHA256(legacyAdapter)
        let legacyExternalAttempt = ProviderQualificationAttempt(
            attemptID: "00000000-0000-4000-8000-000000000003",
            provider: .local,
            epochSHA256: hash,
            adapterSHA256: legacyAdapterDigest,
            probe: .strictJSON,
            outcome: .verified,
            schemaPassCount: 1,
            assertionPassCount: 1,
            assertionCount: 1,
            promptCharacterCount: 2_000,
            durationBucketMilliseconds: 500,
            appIntentReturnObserved: true,
            adapterStateReconciled: nil,
            startedAt: now.addingTimeInterval(-172_800),
            finishedAt: now.addingTimeInterval(-172_799)
        )
        let v2Payload = ProviderQualificationLedgerPayload(
            recordType: "provider-qualification-ledger",
            schemaVersion: 2,
            suiteVersion: ProviderQualificationStore.suiteVersion,
            attempts: [legacyExternalAttempt],
            recommendation: nil
        )
        let decodedV2 = try ProviderQualificationStore.decodeAuthenticatedLedger(try signedData(v2Payload, key: key), key: key, now: now)
        let upgradedV2 = try decodedV2.upgradedToCurrentSchema()
        try check(upgradedV2.attempts[0].adapterStateReconciled == false, "legacy external evidence did not migrate fail-closed")
        try check(
            ProviderQualificationStore.scoredAttempts(provider: .local, epochSHA256: hash, now: now, attempts: upgradedV2.attempts).isEmpty,
            "legacy external evidence became runnable before adapter reconciliation"
        )

        try testSigningKeyTransactions()
        try testExternalQualificationAuthorization()
        try testCompletionTransactions(now: now)
        try await testAppleProbePersistenceFailuresPropagate()
        try testResetTransactions()

        print("Provider qualification contracts passed: exact signed schemas, fail-closed migration, checked signing-key creation, saved qualification authorization and pending handoff admission, durable probe failures, retryable two-phase completion, fifth-probe admission, and checked reset.")
    }
}
