import Foundation
import Security

@main
enum NativeCoreContracts {
    static func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw NSError(domain: "NativeCoreContracts", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }

    static func rejectsReceipt(_ object: [String: Any]) -> Bool {
        do {
            _ = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
            return false
        } catch {
            return true
        }
    }

    static func main() throws {
        let decoder = JSONDecoder()
        let encoder = JSONEncoder()

        let legacyPolicy = Data("""
        {"batteryBudget":15,"batteryReserve":20,"memoryTarget":35,"maxSteps":6,"maxFailures":3,"contextChars":6000,"cloudAllowed":false,"notifications":true,"provider":"openai","localShortcut":"Agent Step - Local"}
        """.utf8)
        let migratedPolicy = try decoder.decode(ResourcePolicy.self, from: legacyPolicy)
        try check(migratedPolicy.provider == "chatgpt", "legacy provider did not migrate")
        let policyJSON = String(decoding: try encoder.encode(migratedPolicy), as: UTF8.self)
        try check(policyJSON.contains("\"schemaVersion\":2"), "policy write is not versioned")
        try check(!migratedPolicy.clipboardReadAllowed && !migratedPolicy.clipboardWriteAllowed, "legacy policy unexpectedly authorized clipboard access")
        let futurePolicy = Data("{\"recordType\":\"resource-policy\",\"schemaVersion\":3}".utf8)
        do { _ = try decoder.decode(ResourcePolicy.self, from: futurePolicy); throw NSError(domain: "NativeCoreContracts", code: 2) }
        catch let error as SandboxError { try check(error.localizedDescription == "UNSUPPORTED_POLICY_VERSION", "future policy did not fail closed") }

        let sha = String(repeating: "a", count: 64)
        let result = ToolResult(ok: true, tool: "file.read", result: String(repeating: "body", count: 2000), sha256: sha, error_code: nil,
                                evidence: ToolEvidence(path: "workspace/a.txt", sha256: sha, byteCount: 8000, readbackKind: "source-read", contentComplete: true))
        let compact = result.promptJSON(maxCharacters: 700)
        try check(compact.count <= 700, "tool prompt exceeded its budget")
        try check(compact.contains(sha), "tool prompt truncated its SHA evidence")
        try check(compact.contains("\"bodyTruncated\":true"), "tool prompt omitted truncation evidence")
        try check(!result.isCompleteInPrompt(maxCharacters: 700), "truncated read authorized an edit")

        let bounded = boundedPrompt(goal: String(repeating: "g", count: 3000), capsule: String(repeating: "s", count: 3000), latest: "LATEST-EVIDENCE", limit: 2000)
        try check(bounded.count <= 2000 && bounded.contains("LATEST-EVIDENCE"), "bounded prompt lost latest evidence")

        let contract = try filesystemGoalContract(mode: "exactText", path: "workspace/result.txt", expected: "done")
        let decodedContract = try decoder.decode(GoalContract.self, from: encoder.encode(contract))
        try check(decodedContract == contract, "goal contract did not round-trip")
        let unversionedContract = Data("""
        {"assertions":[{"kind":"pathExists","path":"workspace/result.txt"}]}
        """.utf8)
        var rejectedUnversionedContract = false
        do { _ = try decoder.decode(GoalContract.self, from: unversionedContract) }
        catch { rejectedUnversionedContract = true }
        try check(rejectedUnversionedContract, "receipt goal contract retained a legacy shape the web schema rejects")

        let evidence = AssertionEvidence(kind: "exactText", path: "workspace/result.txt", passed: true, expected: "done", observed: "exact match", observedSHA256: sha, byteCount: 4, checkedAt: "2026-09-10T00:00:00Z", errorCode: nil)
        let receiptEnvironment = ReceiptEnvironment(appVersion: "0.3.0", build: "1", os: "iOS", device: "iPhone")
        let appleQualification = ProviderQualificationSnapshot(provider: .apple, epochSHA256: String(repeating: "e", count: 64), adapterSHA256: nil, sampleCount: 5, distinctProbeCount: 5, verifiedCount: 5, schemaPassCount: 5, assertionPassCount: 5, assertionCount: 5, toolProbePassCount: 3, maximumContextCharacters: 6_000, medianDurationBucketMilliseconds: 500, integrityFaultCount: 0, appIntentReturnObserved: true, lastSuccessfulAt: "2026-09-10T00:00:00Z")
        let appleRouting = ProviderRoutingEvidence(selection: .apple, provider: .apple, authorizedProvider: .apple, strategy: .explicitPinned, activity: .workspaceIdle, accessEvidence: .onDeviceRuntime, deviceProfileSHA256: String(repeating: "c", count: 64), configurationSHA256: String(repeating: "d", count: 64), qualification: appleQualification)
        let verifiedReceipt = try RunReceipt(id: "verified", goal: "write result", status: .verified, origin: "native", summary: "verified", steps: 1, failures: 0, durationMs: 2, createdAt: "2026-09-10T00:00:00Z", trace: [], contract: contract, assertions: [evidence], provider: "apple", policyDigest: sha, workspaceID: "workspace-123", environment: receiptEnvironment, taskOrigin: .appIntent, routingEvidence: appleRouting, legacyTraceOnly: false)
        let verifiedData = try encoder.encode(verifiedReceipt)
        let decodedVerifiedReceipt = try decoder.decode(RunReceipt.self, from: verifiedData)
        try check(decodedVerifiedReceipt.status == .verified, "matching verified receipt did not round-trip")
        try check(decodedVerifiedReceipt.taskOrigin == .appIntent, "native receipt lost its App Intent origin")
        let strictDecodedReceipt = try RunReceipt.decodeStrict(from: verifiedData)
        try check(strictDecodedReceipt.status == .verified, "strict receipt boundary rejected a valid current receipt")

        let cloudReceipt = try RunReceipt(
            id: "cloud-receipt", goal: "cloud task", status: .completed, origin: "cloud-sandbox", summary: "done",
            steps: 0, failures: 0, durationMs: 1, createdAt: "2026-09-10T00:00:00Z", trace: []
        )
        let cloudData = try encoder.encode(cloudReceipt)
        let cloudObject = try JSONSerialization.jsonObject(with: cloudData) as! [String: Any]
        for requiredNullable in ["contract", "provider", "policyDigest", "workspaceID", "environment"] {
            try check(cloudObject[requiredNullable] is NSNull, "current receipt omitted required nullable field \(requiredNullable)")
        }
        try check(cloudObject["taskOrigin"] == nil && cloudObject["routingEvidence"] == nil, "current receipt emitted absent optional route fields")
        _ = try RunReceipt.decodeStrict(from: cloudData)
        var explicitNullRoute = cloudObject
        explicitNullRoute["taskOrigin"] = NSNull()
        explicitNullRoute["routingEvidence"] = NSNull()
        let decodedNullRoute = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: explicitNullRoute))
        try check(decodedNullRoute.taskOrigin == nil && decodedNullRoute.routingEvidence == nil, "receipt rejected nullable optional route fields")
        var missingRequiredNullable = cloudObject
        missingRequiredNullable.removeValue(forKey: "environment")
        try check(rejectsReceipt(missingRequiredNullable), "current receipt accepted a missing required nullable field")

        var unicodeReceipt = try JSONSerialization.jsonObject(with: verifiedData) as! [String: Any]
        var unicodeEnvironment = unicodeReceipt["environment"] as! [String: Any]
        let unicodeDevice = String(repeating: "📱", count: 100)
        unicodeEnvironment["device"] = unicodeDevice
        unicodeReceipt["environment"] = unicodeEnvironment
        let decodedUnicodeReceipt = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: unicodeReceipt))
        try check(decodedUnicodeReceipt.environment?.device == unicodeDevice, "valid 100-character multibyte environment value was rejected")

        try check(ReceiptWireContract.scalarCount("📱") == 1, "single-scalar emoji did not count as one wire character")
        try check(ReceiptWireContract.scalarCount("e\u{301}") == 2, "combining-mark grapheme did not use the deterministic scalar metric")
        try check(ReceiptWireContract.scalarCount("👨‍👩‍👧‍👦") == 7, "ZWJ grapheme did not expose its bounded scalar cost")
        var maximumEmojiSummary = cloudObject
        maximumEmojiSummary["summary"] = String(repeating: "🙂", count: 3_000)
        _ = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: maximumEmojiSummary))
        maximumEmojiSummary["summary"] = String(repeating: "🙂", count: 3_001)
        try check(rejectsReceipt(maximumEmojiSummary), "receipt accepted one Unicode scalar beyond the summary limit")
        var maximumCombiningSummary = cloudObject
        maximumCombiningSummary["summary"] = String(repeating: "e\u{301}", count: 1_500)
        _ = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: maximumCombiningSummary))
        maximumCombiningSummary["summary"] = String(repeating: "e\u{301}", count: 1_501)
        try check(rejectsReceipt(maximumCombiningSummary), "receipt counted combining graphemes instead of bounded Unicode scalars")

        for dateTime in [
            "0000-02-29T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2024-02-29T23:59:59Z",
            "2026-09-11T12:34:56.123456789Z",
            "2026-09-11T12:34:56+00:00",
            "2026-09-11T12:34:56-23:59",
            "2026-09-11T12:34:56z",
        ] {
            var datedReceipt = cloudObject
            datedReceipt["createdAt"] = dateTime
            _ = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: datedReceipt))
        }
        for dateTime in [
            "1900-02-29T12:34:56Z",
            "2023-02-29T12:34:56Z",
            "2026-00-11T12:34:56Z",
            "2026-13-11T12:34:56Z",
            "2026-04-31T12:34:56Z",
            "2026-09-00T12:34:56Z",
            "2026-09-11T24:34:56Z",
            "2026-09-11T12:60:56Z",
            "2026-09-11T12:34:60Z",
            "2026-09-11T12:34Z",
            "2026-09-11T12:34:56.1234567890Z",
            "2026-09-11T12:34:56+24:00",
            "2026-09-11T12:34:56+00:60",
            "2026-09-11t12:34:56Z",
        ] {
            var datedReceipt = cloudObject
            datedReceipt["createdAt"] = dateTime
            try check(rejectsReceipt(datedReceipt), "receipt accepted invalid wire datetime \(dateTime)")
        }

        let safeTraceDetail = "{\"byteCount\":0,\"errorCode\":null,\"readbackKind\":null,\"recordType\":\"trace-metadata\",\"resultKind\":\"legacy-redacted\",\"schemaVersion\":1,\"sha256\":null}"
        let maximumTrace = (0..<100).map { _ in
            TraceEntry(tool: String(repeating: "🛠", count: 100), status: "ok", detail: safeTraceDetail)
        }
        let maximumShapeReceipt = try RunReceipt(
            id: String(repeating: "i", count: 80),
            goal: String(repeating: "🙂", count: 2_000),
            status: .completed,
            origin: "cloud-sandbox",
            summary: String(repeating: "🙂", count: 3_000),
            steps: 100,
            failures: 100,
            durationMs: 86_400_000,
            createdAt: "2026-09-11T12:34:56.123456789+00:00",
            trace: maximumTrace,
            workspaceID: String(repeating: "w", count: 80),
            environment: ReceiptEnvironment(
                appVersion: String(repeating: "📱", count: 40),
                build: String(repeating: "📱", count: 40),
                os: String(repeating: "📱", count: 100),
                device: String(repeating: "📱", count: 100)
            )
        )
        let maximumShapeData = try maximumShapeReceipt.encodedWireData()
        try check(maximumShapeData.count > 64_000, "maximum valid Unicode receipt did not prove the old 64 KB regression")
        try check(maximumShapeData.count <= 128_000, "sanitized terminal receipt exceeded the explicit App Intent payload boundary")
        _ = try RunReceipt.decodeStrict(from: maximumShapeData)
        _ = try AppIntentTaskOutput.terminalAppleReceipt(
            selection: .apple,
            phase: maximumShapeReceipt.status,
            payload: String(decoding: maximumShapeData, as: UTF8.self)
        ).json

        try ReceiptWireContract.validateSerializedByteCount(ReceiptWireContract.maximumSerializedUTF8Bytes)
        var rejectedCanonicalOneOver = false
        do { try ReceiptWireContract.validateSerializedByteCount(ReceiptWireContract.maximumSerializedUTF8Bytes + 1) }
        catch { rejectedCanonicalOneOver = true }
        try check(rejectedCanonicalOneOver, "canonical receipt byte cap accepted one byte over")
        let exactRawPadding = ReceiptWireContract.maximumSerializedUTF8Bytes - cloudData.count
        let exactRawReceipt = cloudData + Data(repeating: 0x20, count: exactRawPadding)
        try check(exactRawReceipt.count == ReceiptWireContract.maximumSerializedUTF8Bytes, "near-cap receipt fixture has the wrong byte count")
        _ = try RunReceipt.decodeStrict(from: exactRawReceipt)
        var rejectedRawOneOver = false
        do { _ = try RunReceipt.decodeStrict(from: exactRawReceipt + Data([0x20])) }
        catch { rejectedRawOneOver = true }
        try check(rejectedRawOneOver, "raw receipt boundary accepted one byte over")

        var unknownReceipt = try JSONSerialization.jsonObject(with: verifiedData) as! [String: Any]
        unknownReceipt["unexpected"] = true
        var rejectedUnknownReceipt = false
        do { _ = try decoder.decode(RunReceipt.self, from: JSONSerialization.data(withJSONObject: unknownReceipt)) }
        catch { rejectedUnknownReceipt = true }
        try check(rejectedUnknownReceipt, "current receipt accepted an unknown top-level member")

        unknownReceipt.removeValue(forKey: "unexpected")
        var unknownEnvironment = unknownReceipt["environment"] as! [String: Any]
        unknownEnvironment["unexpected"] = "device-secret"
        unknownReceipt["environment"] = unknownEnvironment
        var rejectedUnknownEnvironment = false
        do { _ = try decoder.decode(RunReceipt.self, from: JSONSerialization.data(withJSONObject: unknownReceipt)) }
        catch { rejectedUnknownEnvironment = true }
        try check(rejectedUnknownEnvironment, "receipt environment accepted an unknown member")

        let verifiedJSON = String(decoding: verifiedData, as: UTF8.self)
        let duplicateStatus = Data((String(verifiedJSON.dropLast()) + ",\"status\":\"blocked\"}").utf8)
        var rejectedDuplicateStatus = false
        do { _ = try RunReceipt.decodeStrict(from: duplicateStatus) }
        catch { rejectedDuplicateStatus = true }
        try check(rejectedDuplicateStatus, "strict receipt boundary collapsed a duplicate top-level status")

        let duplicateProvider = Data((String(verifiedJSON.dropLast()) + ",\"\\u0070rovider\":\"chatgpt\"}").utf8)
        var rejectedEscapedProvider = false
        do { _ = try RunReceipt.decodeStrict(from: duplicateProvider) }
        catch { rejectedEscapedProvider = true }
        try check(rejectedEscapedProvider, "strict receipt boundary collapsed an escaped-equivalent provider")

        let deviceField = "\"device\":\"iPhone\""
        let duplicateDeviceJSON = verifiedJSON.replacingOccurrences(
            of: deviceField,
            with: deviceField + ",\"\\u0064evice\":\"iPad\""
        )
        try check(duplicateDeviceJSON != verifiedJSON, "receipt fixture did not contain its environment device")
        var rejectedDuplicateDevice = false
        do { _ = try RunReceipt.decodeStrict(from: Data(duplicateDeviceJSON.utf8)) }
        catch { rejectedDuplicateDevice = true }
        try check(rejectedDuplicateDevice, "strict receipt boundary collapsed a nested escaped device member")

        let pathField = verifiedJSON.contains("workspace\\/result.txt")
            ? "\"path\":\"workspace\\/result.txt\""
            : "\"path\":\"workspace/result.txt\""
        let duplicatePathJSON = verifiedJSON.replacingOccurrences(
            of: pathField,
            with: pathField + ",\"\\u0070ath\":\"workspace/other.txt\""
        )
        try check(duplicatePathJSON != verifiedJSON, "receipt fixture did not contain its verification path")
        var rejectedDuplicatePath = false
        do { _ = try RunReceipt.decodeStrict(from: Data(duplicatePathJSON.utf8)) }
        catch { rejectedDuplicatePath = true }
        try check(rejectedDuplicatePath, "strict receipt boundary collapsed a nested verification path")

        let sensitiveMarker = "PRIVATE-FILE-CLIPBOARD-PROVIDER-OUTPUT"
        let privateContract = try filesystemGoalContract(mode: "exactText", path: "workspace/private.txt", expected: sensitiveMarker)
        let privateEvidence = AssertionEvidence(
            kind: "exactText",
            path: "workspace/private.txt",
            passed: true,
            expected: sensitiveMarker,
            observed: sensitiveMarker,
            observedSHA256: ReceiptPrivacy.sha256(sensitiveMarker),
            byteCount: sensitiveMarker.utf8.count,
            checkedAt: "2026-09-10T00:00:00Z",
            errorCode: nil
        )
        let privateResult = ToolResult(
            ok: true,
            tool: ToolName.clipboardGet.rawValue,
            result: sensitiveMarker,
            sha256: nil,
            error_code: nil
        )
        let privateReceipt = try RunReceipt(
            id: "private",
            goal: "Complete the approved private task",
            status: .verified,
            origin: "native",
            summary: sensitiveMarker,
            steps: 1,
            failures: 0,
            durationMs: 2,
            createdAt: "2026-09-10T00:00:00Z",
            trace: [.receiptSuccess(privateResult)],
            contract: privateContract,
            assertions: [privateEvidence],
            provider: "apple",
            policyDigest: sha,
            workspaceID: "workspace-123",
            environment: receiptEnvironment,
            taskOrigin: .appIntent,
            routingEvidence: appleRouting
        )
        let privateJSON = String(decoding: try encoder.encode(privateReceipt), as: UTF8.self)
        try check(!privateJSON.contains(sensitiveMarker), "receipt JSON leaked file, clipboard, or provider output")
        try check(privateJSON.contains(ReceiptPrivacy.sha256(sensitiveMarker)), "receipt JSON lost hash evidence for redacted content")
        try check(privateJSON.contains("trace-metadata") && privateJSON.contains("clipboard-read"), "receipt JSON lost typed privacy metadata")

        let failedResult = ToolResult(ok: false, tool: ToolName.read.rawValue, result: sensitiveMarker, sha256: nil, error_code: "FILE_READ_FAILED: private detail")
        let failedTrace = TraceEntry.receiptSuccess(failedResult).receiptSafe()
        try check(!failedTrace.detail.contains(sensitiveMarker) && failedTrace.detail.contains("\"resultKind\":\"error\"") && failedTrace.detail.contains("FILE_READ_FAILED"), "failed result did not retain privacy-safe typed error metadata")

        var importedPrivate = try JSONSerialization.jsonObject(with: encoder.encode(privateReceipt)) as! [String: Any]
        importedPrivate["summary"] = sensitiveMarker
        importedPrivate["trace"] = [["tool": "file.read", "status": "ok", "detail": sensitiveMarker]]
        let sanitizedImport = try decoder.decode(RunReceipt.self, from: JSONSerialization.data(withJSONObject: importedPrivate))
        let sanitizedImportJSON = String(decoding: try encoder.encode(sanitizedImport), as: UTF8.self)
        try check(!sanitizedImportJSON.contains(sensitiveMarker), "decoded receipt retained imported sensitive trace or summary text")
        try check(sanitizedImportJSON.contains("legacy-redacted"), "decoded legacy trace did not record its redaction")

        let nestedReceipt = try RunReceipt(
            id: "nested-shape", goal: "write result", status: .verified, origin: "native", summary: "verified",
            steps: 1, failures: 0, durationMs: 2, createdAt: "2026-09-10T00:00:00Z",
            trace: [.receiptSuccess(result)], contract: contract, assertions: [evidence], provider: "apple",
            policyDigest: sha, workspaceID: "workspace-123", environment: receiptEnvironment,
            taskOrigin: .appIntent, routingEvidence: appleRouting
        )
        let nestedData = try encoder.encode(nestedReceipt)
        let nestedBase = try JSONSerialization.jsonObject(with: nestedData) as! [String: Any]

        var unknownContract = nestedBase
        var contractObject = unknownContract["contract"] as! [String: Any]
        contractObject["unexpected"] = true
        unknownContract["contract"] = contractObject
        try check(rejectsReceipt(unknownContract), "nested goal contract accepted an unknown member")

        var unknownGoalAssertion = nestedBase
        contractObject = unknownGoalAssertion["contract"] as! [String: Any]
        var goalAssertions = contractObject["assertions"] as! [[String: Any]]
        goalAssertions[0]["unexpected"] = true
        contractObject["assertions"] = goalAssertions
        unknownGoalAssertion["contract"] = contractObject
        try check(rejectsReceipt(unknownGoalAssertion), "nested goal assertion accepted an unknown member")

        var unknownAssertionEvidence = nestedBase
        var assertionEvidence = unknownAssertionEvidence["assertions"] as! [[String: Any]]
        assertionEvidence[0]["unexpected"] = true
        unknownAssertionEvidence["assertions"] = assertionEvidence
        try check(rejectsReceipt(unknownAssertionEvidence), "nested assertion evidence accepted an unknown member")

        var unknownTraceEntry = nestedBase
        var traceEntries = unknownTraceEntry["trace"] as! [[String: Any]]
        traceEntries[0]["unexpected"] = true
        unknownTraceEntry["trace"] = traceEntries
        try check(rejectsReceipt(unknownTraceEntry), "nested trace entry accepted an unknown member")

        var unknownToolEvidence = nestedBase
        traceEntries = unknownToolEvidence["trace"] as! [[String: Any]]
        var toolEvidence = traceEntries[0]["evidence"] as! [String: Any]
        toolEvidence["unexpected"] = true
        traceEntries[0]["evidence"] = toolEvidence
        unknownToolEvidence["trace"] = traceEntries
        try check(rejectsReceipt(unknownToolEvidence), "nested tool evidence accepted an unknown member")

        var unknownRoutingEvidence = nestedBase
        var routeEvidence = unknownRoutingEvidence["routingEvidence"] as! [String: Any]
        routeEvidence["unexpected"] = true
        unknownRoutingEvidence["routingEvidence"] = routeEvidence
        try check(rejectsReceipt(unknownRoutingEvidence), "nested provider routing evidence accepted an unknown member")

        var unknownTraceMetadata = nestedBase
        traceEntries = unknownTraceMetadata["trace"] as! [[String: Any]]
        var traceMetadata = try JSONSerialization.jsonObject(with: Data((traceEntries[0]["detail"] as! String).utf8)) as! [String: Any]
        traceMetadata["unexpected"] = true
        traceEntries[0]["detail"] = String(decoding: try JSONSerialization.data(withJSONObject: traceMetadata, options: [.sortedKeys]), as: UTF8.self)
        unknownTraceMetadata["trace"] = traceEntries
        let sanitizedTraceMetadata = try RunReceipt.decodeStrict(from: JSONSerialization.data(withJSONObject: unknownTraceMetadata))
        try check(sanitizedTraceMetadata.trace[0].detail.contains("legacy-redacted"), "unknown trace metadata was not redacted like the web boundary")

        var mismatchedObject = try JSONSerialization.jsonObject(with: verifiedData) as! [String: Any]
        var mismatchedEvidence = mismatchedObject["assertions"] as! [[String: Any]]
        mismatchedEvidence[0]["path"] = "workspace/other.txt"
        mismatchedObject["assertions"] = mismatchedEvidence
        var rejectedMismatch = false
        do { _ = try decoder.decode(RunReceipt.self, from: JSONSerialization.data(withJSONObject: mismatchedObject)) }
        catch { rejectedMismatch = true }
        try check(rejectedMismatch, "verified receipt accepted evidence for another assertion")
        mismatchedObject.removeValue(forKey: "contract")
        var rejectedMissingContract = false
        do { _ = try decoder.decode(RunReceipt.self, from: JSONSerialization.data(withJSONObject: mismatchedObject)) }
        catch { rejectedMissingContract = true }
        try check(rejectedMissingContract, "verified v2 receipt omitted its contract")

        let legacyReceipt = Data("""
        {"id":"legacy","goal":"old","status":"verified","origin":"native","summary":"old trace","steps":1,"failures":0,"durationMs":2,"createdAt":"2026-09-10T00:00:00Z","trace":[]}
        """.utf8)
        let migratedReceipt = try decoder.decode(RunReceipt.self, from: legacyReceipt)
        try check(migratedReceipt.status == .completed && migratedReceipt.legacyTraceOnly, "legacy receipt retained an unqualified verified state")
        let remigratedReceipt = try decoder.decode(RunReceipt.self, from: encoder.encode(migratedReceipt))
        try check(remigratedReceipt.status == .completed && remigratedReceipt.legacyTraceOnly, "legacy receipt could not round-trip through the safe current envelope")
        let legacyUnknown = Data("""
        {"id":"legacy","goal":"old","status":"verified","origin":"native","summary":"old trace","steps":1,"failures":0,"durationMs":2,"createdAt":"2026-09-10T00:00:00Z","trace":[],"unexpected":true}
        """.utf8)
        var rejectedLegacyUnknown = false
        do { _ = try decoder.decode(RunReceipt.self, from: legacyUnknown) }
        catch { rejectedLegacyUnknown = true }
        try check(rejectedLegacyUnknown, "legacy receipt accepted a member outside the web migration schema")
        let legacyCompleted = Data("""
        {"id":"legacy","goal":"old","status":"completed","origin":"native","summary":"old trace","steps":1,"failures":0,"durationMs":2,"createdAt":"2026-09-10T00:00:00Z","trace":[]}
        """.utf8)
        var rejectedLegacyCompleted = false
        do { _ = try decoder.decode(RunReceipt.self, from: legacyCompleted) }
        catch { rejectedLegacyCompleted = true }
        try check(rejectedLegacyCompleted, "legacy receipt accepted a status outside the web migration schema")

        var applePolicy = ResourcePolicy()
        applePolicy.provider = "apple"
        let startedAt = Date(timeIntervalSince1970: 1_788_921_600)
        let checkpoint = RunCheckpoint(
            runID: "background-run",
            goal: "Finish the approved file task",
            nextStep: 2,
            capsule: "Two calls complete.",
            lastResult: result.promptJSON(maxCharacters: latestPromptBudget(limit: ProviderQualificationSnapshot.appleMaximumContextCharacters)),
            phase: "ready",
            contract: contract,
            latestResult: result,
            policy: applePolicy,
            taskOrigin: .appIntent,
            routingEvidence: appleRouting,
            trace: [TraceEntry(tool: "file.read", status: "ok", detail: "Read complete", evidence: result.evidence)],
            failures: 1,
            repeated: 0,
            lastFailure: "",
            initialBattery: 80,
            startedAt: startedAt
        )
        let decodedCheckpoint = try decoder.decode(RunCheckpoint.self, from: encoder.encode(checkpoint))
        try check(decodedCheckpoint.policy == applePolicy, "checkpoint lost its approved policy snapshot")
        try check(decodedCheckpoint.authorizationPolicy == applePolicy, "checkpoint lost its original authorization snapshot")
        try check(decodedCheckpoint.trace.count == 1 && decodedCheckpoint.failures == 1, "checkpoint lost continuation evidence")
        try check(decodedCheckpoint.startedAt == startedAt, "checkpoint lost the original start time")
        try RunCheckpointIdentity.requireUnchanged(expected: checkpoint, current: decodedCheckpoint)

        var replacementObject = try JSONSerialization.jsonObject(with: encoder.encode(checkpoint)) as! [String: Any]
        replacementObject["capsule"] = "Replaced content with the same run ID, step, and phase."
        let sameShallowIdentityReplacement = try decoder.decode(
            RunCheckpoint.self,
            from: JSONSerialization.data(withJSONObject: replacementObject)
        )
        try check(
            sameShallowIdentityReplacement.runID == checkpoint.runID &&
            sameShallowIdentityReplacement.nextStep == checkpoint.nextStep &&
            sameShallowIdentityReplacement.phase == checkpoint.phase,
            "checkpoint replacement test did not preserve the legacy shallow identity"
        )
        let expectedCheckpointDigest = try RunCheckpointIdentity.digest(checkpoint)
        let replacementCheckpointDigest = try RunCheckpointIdentity.digest(sameShallowIdentityReplacement)
        try check(replacementCheckpointDigest != expectedCheckpointDigest, "canonical checkpoint identity ignored replaced immutable content")
        do {
            try RunCheckpointIdentity.requireUnchanged(expected: checkpoint, current: sameShallowIdentityReplacement)
            throw NSError(domain: "NativeCoreContracts", code: 14, userInfo: [NSLocalizedDescriptionKey: "same-ID checkpoint replacement was accepted"])
        } catch let error as SandboxError {
            try check(error.localizedDescription == "BACKGROUND_CHECKPOINT_CHANGED", "checkpoint replacement returned the wrong failure")
        }
        switch try CheckpointReviewCore.disposition(expected: checkpoint, current: decodedCheckpoint) {
        case .acknowledge:
            break
        case .alreadyAcknowledged:
            throw NSError(domain: "NativeCoreContracts", code: 15, userInfo: [NSLocalizedDescriptionKey: "fresh checkpoint was mistaken for an acknowledgement"])
        }
        do {
            _ = try CheckpointReviewCore.disposition(expected: checkpoint, current: sameShallowIdentityReplacement)
            throw NSError(domain: "NativeCoreContracts", code: 16, userInfo: [NSLocalizedDescriptionKey: "stale checkpoint acknowledgement was accepted"])
        } catch let error as SandboxError {
            try check(error.localizedDescription == "BACKGROUND_CHECKPOINT_CHANGED", "stale acknowledgement returned the wrong failure")
        }
        let acknowledgedCheckpoint = try CheckpointReviewCore.acknowledgedRecord(for: checkpoint)
        switch try CheckpointReviewCore.disposition(expected: checkpoint, current: acknowledgedCheckpoint) {
        case .alreadyAcknowledged:
            break
        case .acknowledge:
            throw NSError(domain: "NativeCoreContracts", code: 17, userInfo: [NSLocalizedDescriptionKey: "exact acknowledgement was not idempotent"])
        }
        let replacementAcknowledgement = try CheckpointReviewCore.acknowledgedRecord(for: sameShallowIdentityReplacement)
        do {
            _ = try CheckpointReviewCore.disposition(expected: checkpoint, current: replacementAcknowledgement)
            throw NSError(domain: "NativeCoreContracts", code: 18, userInfo: [NSLocalizedDescriptionKey: "a different acknowledged checkpoint was mistaken for the expected state"])
        } catch let error as SandboxError {
            try check(error.localizedDescription == "BACKGROUND_CHECKPOINT_CHANGED", "different acknowledged state returned the wrong failure")
        }
        let reviewPath = try CheckpointReviewCore.reviewPath(for: checkpoint)
        try check(reviewPath.value.hasPrefix("output/reviewed-checkpoint-") && reviewPath.value.hasSuffix(".json"), "checkpoint review path is not bounded by canonical identity")
        let invalidUTF8 = Data([0xff, 0x00, 0x41])
        let corruptState = CorruptExecutionState.bounded(
            kind: .nativeCheckpoint,
            data: invalidUTF8,
            failureCode: "CHECKPOINT_DECODE_FAILED"
        )
        try check(corruptState.sha256 == NativeDigest.sha256(invalidUTF8), "corrupt state did not retain a raw-byte digest")
        try check(corruptState.reviewPath?.value.hasPrefix("output/reviewed-corrupt-active-") == true, "corrupt state review path is not bounded")

        let localContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: applePolicy
        )
        guard case .resume(let localPlan) = BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: localContext) else {
            throw NSError(domain: "NativeCoreContracts", code: 3, userInfo: [NSLocalizedDescriptionKey: "safe checkpoint was not resumable"])
        }
        try check(localPlan.runID == checkpoint.runID && localPlan.nextStep == 2, "resume plan targeted the wrong continuation")
        try check(!localPlan.requiresNetworkConnectivity, "on-device workspace incorrectly required a network")

        var savedLocalPolicy = ResourcePolicy()
        savedLocalPolicy.provider = "local"
        savedLocalPolicy.cloudAllowed = true
        var explicitApplePolicy = savedLocalPolicy
        explicitApplePolicy.provider = "apple"
        let explicitAppleRouting = ProviderRoutingEvidence(
            selection: .apple,
            provider: .apple,
            authorizedProvider: .local,
            strategy: .explicitPinned,
            activity: .workspaceIdle,
            accessEvidence: .onDeviceRuntime,
            deviceProfileSHA256: String(repeating: "c", count: 64),
            configurationSHA256: String(repeating: "d", count: 64),
            qualification: appleQualification
        )
        let explicitAppleCheckpoint = RunCheckpoint(
            runID: "siri-explicit-apple",
            goal: "Use Apple for this Siri run",
            nextStep: 1,
            capsule: "One safe boundary reached.",
            lastResult: result.promptJSON(maxCharacters: 2_000),
            phase: "ready",
            policy: explicitApplePolicy,
            authorizationPolicy: savedLocalPolicy,
            taskOrigin: .appIntent,
            routingEvidence: explicitAppleRouting,
            initialBattery: 80,
            startedAt: startedAt
        )
        let explicitAppleRoundTrip = try decoder.decode(RunCheckpoint.self, from: encoder.encode(explicitAppleCheckpoint))
        try check(explicitAppleRoundTrip.policy == explicitApplePolicy && explicitAppleRoundTrip.authorizationPolicy == savedLocalPolicy,
                  "explicit Apple checkpoint merged its resolved route with saved authorization")
        try check(explicitAppleRoundTrip.taskOrigin == .appIntent, "explicit Apple checkpoint lost its Siri/App Intent origin")
        var substitutedSavedCheckpoint = try JSONSerialization.jsonObject(with: encoder.encode(explicitAppleCheckpoint)) as! [String: Any]
        var substitutedSavedEvidence = substitutedSavedCheckpoint["routingEvidence"] as! [String: Any]
        substitutedSavedEvidence["selection"] = "saved"
        substitutedSavedEvidence["strategy"] = "saved-pinned"
        substitutedSavedCheckpoint["routingEvidence"] = substitutedSavedEvidence
        do {
            _ = try decoder.decode(RunCheckpoint.self, from: JSONSerialization.data(withJSONObject: substitutedSavedCheckpoint))
            throw NSError(domain: "NativeCoreContracts", code: 7, userInfo: [NSLocalizedDescriptionKey: "Saved checkpoint substituted an explicit Apple provider"])
        } catch let error as SandboxError {
            try check(error.localizedDescription == "INVALID_PROVIDER_ROUTING_STRATEGY", "Saved checkpoint provider substitution returned the wrong error")
        }
        let explicitAppleContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: savedLocalPolicy
        )
        guard case .resume = BackgroundExecutionPolicy.evaluate(checkpoint: explicitAppleRoundTrip, context: explicitAppleContext) else {
            throw NSError(domain: "NativeCoreContracts", code: 6, userInfo: [NSLocalizedDescriptionKey: "unchanged saved Locally authorization blocked an explicit Apple resume"])
        }
        var changedExplicitAuthorization = savedLocalPolicy
        changedExplicitAuthorization.maxSteps += 1
        let changedExplicitContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: changedExplicitAuthorization
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: explicitAppleRoundTrip, context: changedExplicitContext) == .reviewRequired(.policyChanged),
                  "changed resource authorization did not block explicit Apple resume")
        var revokedExplicitCloud = savedLocalPolicy
        revokedExplicitCloud.cloudAllowed = false
        let revokedExplicitContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: revokedExplicitCloud
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: explicitAppleRoundTrip, context: revokedExplicitContext) == .reviewRequired(.policyChanged),
                  "cloud authorization revocation did not block explicit Apple resume")

        let externalContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: true,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: applePolicy
        )
        guard case .resume(let externalPlan) = BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: externalContext) else {
            throw NSError(domain: "NativeCoreContracts", code: 4, userInfo: [NSLocalizedDescriptionKey: "external workspace was not resumable"])
        }
        try check(externalPlan.requiresNetworkConnectivity, "external workspace omitted its network scheduler constraint")

        let lockedContext = BackgroundExecutionContext(
            protectedDataAvailable: false,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: applePolicy
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: lockedContext) == .deferred(.protectedDataUnavailable),
                  "locked protected data did not defer the run")

        let unavailableProviderContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: false,
            currentPolicy: applePolicy
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: unavailableProviderContext) == .reviewRequired(.providerUnavailable),
                  "an unavailable native provider was admitted in the background")

        let refreshDisabledContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: false,
            nativeProviderAvailable: true,
            currentPolicy: applePolicy
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: refreshDisabledContext) == .deferred(.backgroundRefreshUnavailable),
                  "disabled background refresh did not defer the run")

        let exhausted = RunCheckpoint(
            runID: checkpoint.runID, goal: checkpoint.goal, nextStep: applePolicy.maxSteps,
            capsule: checkpoint.capsule, lastResult: checkpoint.lastResult, phase: "ready", policy: applePolicy,
            taskOrigin: checkpoint.taskOrigin, routingEvidence: checkpoint.routingEvidence,
            initialBattery: checkpoint.initialBattery, startedAt: checkpoint.startedAt
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: exhausted, context: localContext) == .reviewRequired(.stepBudgetReached),
                  "an exhausted step budget produced another background step")

        let invalidStep = RunCheckpoint(
            runID: checkpoint.runID, goal: checkpoint.goal, nextStep: -1,
            capsule: checkpoint.capsule, lastResult: checkpoint.lastResult, phase: "ready", policy: applePolicy,
            taskOrigin: checkpoint.taskOrigin, routingEvidence: checkpoint.routingEvidence,
            initialBattery: checkpoint.initialBattery, startedAt: checkpoint.startedAt
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: invalidStep, context: localContext) == .reviewRequired(.invalidCheckpoint),
                  "an invalid checkpoint step was admitted")

        let exhaustedFailures = RunCheckpoint(
            runID: checkpoint.runID, goal: checkpoint.goal, nextStep: checkpoint.nextStep,
            capsule: checkpoint.capsule, lastResult: checkpoint.lastResult, phase: "ready",
            policy: applePolicy, taskOrigin: checkpoint.taskOrigin, routingEvidence: checkpoint.routingEvidence,
            failures: applePolicy.maxFailures, initialBattery: checkpoint.initialBattery, startedAt: checkpoint.startedAt
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: exhaustedFailures, context: localContext) == .reviewRequired(.failureBudgetReached),
                  "an exhausted failure budget produced another background attempt")

        let executing = RunCheckpoint(
            runID: checkpoint.runID, goal: checkpoint.goal, nextStep: checkpoint.nextStep,
            capsule: checkpoint.capsule, lastResult: checkpoint.lastResult, phase: "executing",
            contract: checkpoint.contract, latestResult: checkpoint.latestResult, policy: applePolicy
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: executing, context: localContext) == .reviewRequired(.unsafeExecutingCheckpoint),
                  "an executing checkpoint was eligible for silent replay")

        var changedPolicy = applePolicy
        changedPolicy.maxSteps += 1
        let changedContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: false,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: changedPolicy
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: checkpoint, context: changedContext) == .reviewRequired(.policyChanged),
                  "changed authorization did not require review")

        var cloudPolicy = applePolicy
        cloudPolicy.provider = "chatgpt"
        let cloudCheckpoint = RunCheckpoint(
            runID: "cloud", goal: checkpoint.goal, nextStep: 0, capsule: checkpoint.capsule,
            lastResult: checkpoint.lastResult, phase: "planning", policy: cloudPolicy
        )
        let cloudContext = BackgroundExecutionContext(
            protectedDataAvailable: true,
            workspaceConnected: true,
            workspaceRequiresNetworkConnectivity: true,
            backgroundRefreshAvailable: true,
            nativeProviderAvailable: true,
            currentPolicy: cloudPolicy
        )
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: cloudCheckpoint, context: cloudContext) == .reviewRequired(.unsupportedProvider),
                  "a provider-app handoff was admitted to native background execution")

        let legacyCheckpoint = Data("""
        {"runID":"legacy-run","goal":"old","nextStep":1,"capsule":"old","lastResult":"none","phase":"ready"}
        """.utf8)
        let migratedCheckpoint = try decoder.decode(RunCheckpoint.self, from: legacyCheckpoint)
        try check(migratedCheckpoint.policy == nil, "legacy checkpoint invented a policy snapshot")
        try check(migratedCheckpoint.authorizationPolicy == nil && migratedCheckpoint.taskOrigin == nil,
                  "legacy checkpoint invented authorization or origin metadata")
        try check(BackgroundExecutionPolicy.evaluate(checkpoint: migratedCheckpoint, context: localContext) == .reviewRequired(.missingPolicySnapshot),
                  "legacy checkpoint resumed without recorded authorization")

        var versionTwoCheckpoint = try JSONSerialization.jsonObject(with: encoder.encode(checkpoint)) as! [String: Any]
        versionTwoCheckpoint["schemaVersion"] = 2
        versionTwoCheckpoint.removeValue(forKey: "authorizationPolicy")
        versionTwoCheckpoint.removeValue(forKey: "taskOrigin")
        let migratedVersionTwo = try decoder.decode(RunCheckpoint.self, from: JSONSerialization.data(withJSONObject: versionTwoCheckpoint))
        try check(migratedVersionTwo.authorizationPolicy == migratedVersionTwo.policy && migratedVersionTwo.taskOrigin == nil,
                  "version 2 checkpoint did not migrate its execution policy into the authorization snapshot")

        let backgroundRecord = BackgroundExecutionRecord(
            attemptID: "attempt-1",
            runID: checkpoint.runID,
            state: .scheduled,
            reason: .systemGrantPending,
            checkpointPhase: checkpoint.phase,
            nextStep: checkpoint.nextStep,
            provider: applePolicy.provider,
            protectedDataAvailable: true,
            recordedAt: "2026-09-10T12:00:00Z",
            detail: "Submitted one bounded request."
        )
        let decodedBackgroundRecord = try decoder.decode(BackgroundExecutionRecord.self, from: encoder.encode(backgroundRecord))
        try check(decodedBackgroundRecord == backgroundRecord, "background status did not round-trip")
        do {
            _ = try decoder.decode(BackgroundExecutionRecord.self, from: Data("""
            {"recordType":"background-execution-status","schemaVersion":2,"attemptID":"future","state":"scheduled","reason":"systemGrantPending","protectedDataAvailable":true,"recordedAt":"2026-09-10T12:00:00Z"}
            """.utf8))
            throw NSError(domain: "NativeCoreContracts", code: 5, userInfo: [NSLocalizedDescriptionKey: "future background status decoded"])
        } catch let error as SandboxError {
            try check(error.localizedDescription == "UNSUPPORTED_BACKGROUND_STATUS_VERSION", "future background status did not fail closed")
        }

        let completion = BackgroundCompletionLatch()
        try check(completion.claim() && !completion.claim(), "background completion was not exactly once")

        var updates = 0
        var adds = 0
        let updateOnly = KeychainWriter(update: { _, _ in updates += 1; return errSecSuccess }, add: { _ in adds += 1; return errSecSuccess })
        try Keychain.set("replacement", for: "test", writer: updateOnly)
        try check(updates == 1 && adds == 0, "Keychain update unexpectedly added an item")

        updates = 0; adds = 0
        let duplicateRace = KeychainWriter(update: { _, _ in updates += 1; return updates == 1 ? errSecItemNotFound : errSecSuccess }, add: { _ in adds += 1; return errSecDuplicateItem })
        try Keychain.set("replacement", for: "test", writer: duplicateRace)
        try check(updates == 2 && adds == 1, "Keychain duplicate race did not retry update")

        print("Native core contracts passed: migration, evidence, checkpoint review identity and idempotence, corrupt-state byte identity, background resume policy, expiration completion, and atomic Keychain upsert.")
    }
}
