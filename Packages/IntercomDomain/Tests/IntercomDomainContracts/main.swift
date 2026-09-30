import Foundation
import IntercomDomain

@main
enum IntercomDomainContracts {
    nonisolated(unsafe) static var clock = Date(timeIntervalSince1970: 1_700_000_000)

    static func nowClock() -> IntercomClock { IntercomClock { clock } }
    static func advance() { clock = clock.addingTimeInterval(1) }
    static func stamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: clock)
    }

    static func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() {
            throw NSError(domain: "IntercomDomainContracts", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
    }

    static func expect(_ body: () async throws -> Void, _ match: (IntercomError) -> Bool, _ message: String) async throws {
        do {
            try await body()
            throw NSError(domain: "IntercomDomainContracts", code: 2, userInfo: [NSLocalizedDescriptionKey: message])
        } catch let error as IntercomError {
            try check(match(error), message + " (got \(error))")
        }
    }

    static func authority() throws -> NativeAdapterAuthority { try NativeAdapterAuthority(installationID: "install-1") }
    static func user() throws -> AgentIdentity { try .user("human-owner") }
    static func agentA() throws -> AgentIdentity { try .agent("agent-a") }
    static func agentB() throws -> AgentIdentity { try .agent("agent-b") }

    static func digest(_ text: String) -> String {
        let scalars = Array(text.utf8)
        var out = ""
        for i in 0..<64 {
            let value = scalars.isEmpty ? 0 : Int(scalars[i % scalars.count])
            out.append(String(format: "%x", (value + i) % 16))
        }
        return out
    }

    static func evidence(_ note: String = "note") throws -> MessageEvidence {
        try MessageEvidence(kind: "text", digest: digest(note), byteCount: note.utf8.count, note: note)
    }

    static func seedReadyEngine(
        store: InMemoryIntercomPersistence = InMemoryIntercomPersistence(),
        scopesA: [GrantScope] = [.claimTask, .appendMessage, .handoff],
        scopesB: [GrantScope] = [.claimTask, .appendMessage, .handoff]
    ) async throws -> (IntercomDomainEngine, InMemoryIntercomPersistence) {
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "ship package", owner: try user(), authority: auth)
        advance()
        try await engine.recordAuthoritativeApprovals([
            try UserApprovalReference(grantID: "grant-a", goalID: "goal-1", user: try user(), grantee: try agentA(), scopes: scopesA, revision: 1),
            try UserApprovalReference(grantID: "grant-b", goalID: "goal-1", user: try user(), grantee: try agentB(), scopes: scopesB, revision: 1)
        ], authority: auth)
        advance()
        try await engine.transitionConnection(to: .reconnecting, authority: auth)
        advance()
        try await engine.transitionConnection(to: .ready, authority: auth)
        advance()
        return (engine, store)
    }

    static func main() async throws {
        try await testDuplicateMessageReplayAcrossRestart()
        try await testChangedIdempotencyPayloadRejected()
        try await testOfflineReconnectGatesMutations()
        try await testCompetingClaimsAndStaleRevision()
        try await testWrongHandoffOwnerAndImmutableOffer()
        try await testForbiddenEscalationAndForgedAdapterLabel()
        try await testHumanRootedGrantAndRevocation()
        try testSynthesizedGrantBypassesRejectedOnValidate()
        try testMismatchedAuditBindingsRejected()
        try await testDurableCASStaleWriterAcrossReopen()
        try await testWriteFailureRollback()
        try testSchemaAndTamperRejection()
        try testEngineInitValidatesCustomPersistenceEveryState()
        fputs("IntercomDomainContracts: all checks passed\n", stdout)
    }

    static func testDuplicateMessageReplayAcrossRestart() async throws {
        let (engine, store) = try await seedReadyEngine()
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        let time = stamp()
        let first = try await engine.appendMessage(
            idempotencyKey: "msg-1",
            goalID: "goal-1",
            taskID: "task-1",
            sender: a,
            recipient: try agentB(),
            time: time,
            evidence: evidence("body-a"),
            body: "hello"
        )
        let replay = try await engine.appendMessage(
            idempotencyKey: "msg-1",
            goalID: "goal-1",
            taskID: "task-1",
            sender: a,
            recipient: try agentB(),
            time: time,
            evidence: evidence("body-a"),
            body: "hello"
        )
        try check(first.receiptID == replay.receiptID, "same-engine idempotent replay diverged")

        let restarted = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let restartedState = await restarted.connectionState()
        try check(restartedState == .offline, "restart did not demote ready journal")
        try await restarted.transitionConnection(to: .reconnecting, authority: try authority())
        try await restarted.transitionConnection(to: .ready, authority: try authority())
        let afterRestart = try await restarted.appendMessage(
            idempotencyKey: first.idempotencyKey,
            goalID: first.goalID,
            taskID: first.taskID,
            sender: first.sender,
            recipient: first.recipient,
            time: first.time,
            evidence: first.evidence,
            body: first.body
        )
        try check(afterRestart.receiptID == first.receiptID, "restart replay minted a new receipt")
        let restartedMessages = await restarted.currentSnapshot().messages.count
        try check(restartedMessages == 1, "restart replay duplicated messages")
    }

    static func testChangedIdempotencyPayloadRejected() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        let time = stamp()
        _ = try await engine.appendMessage(
            idempotencyKey: "msg-1",
            goalID: "goal-1",
            taskID: "task-1",
            sender: a,
            recipient: try agentB(),
            time: time,
            evidence: evidence("one"),
            body: "one"
        )
        try await expect({
            _ = try await engine.appendMessage(
                idempotencyKey: "msg-1",
                goalID: "goal-1",
                taskID: "task-1",
                sender: a,
                recipient: try agentB(),
                time: time,
                evidence: evidence("two"),
                body: "two"
            )
        }, { if case .idempotencyConflict("msg-1") = $0 { return true }; return false }, "changed payload must conflict")
    }

    static func testOfflineReconnectGatesMutations() async throws {
        let store = InMemoryIntercomPersistence()
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        try await expect({
            _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: try agentA(), grantID: "grant-a")
        }, { if case .connectionNotReady(.offline) = $0 { return true }; return false }, "offline must reject claims")
        try await engine.transitionConnection(to: .reconnecting, authority: auth)
        try await expect({
            _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: try agentA(), grantID: "grant-a")
        }, { if case .connectionNotReady(.reconnecting) = $0 { return true }; return false }, "reconnecting must reject claims")
        try await engine.recordAuthoritativeApprovals([
            try UserApprovalReference(grantID: "grant-a", goalID: "goal-1", user: try user(), grantee: try agentA(), scopes: [.claimTask], revision: 1)
        ], authority: auth)
        try await engine.transitionConnection(to: .ready, authority: auth)
        let again = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let againState = await again.connectionState()
        try check(againState == .offline, "reopen did not demote ready")
    }

    static func testCompetingClaimsAndStaleRevision() async throws {
        let (engine, _) = try await seedReadyEngine()
        let claim = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: try agentA(), grantID: "grant-a")
        try await expect({
            _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision, claimant: try agentB(), grantID: "grant-b")
        }, { if case .competingClaim("task-1") = $0 { return true }; return false }, "competing claim")
        try await expect({
            _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 99, claimant: try agentA(), grantID: "grant-a")
        }, { if case .staleRevision(99, claim.revision) = $0 { return true }; return false }, "stale revision")
    }

    static func testWrongHandoffOwnerAndImmutableOffer() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1",
            taskID: "task-1",
            expectedRevision: claim.revision,
            fromOwner: a,
            toOwner: b,
            grantID: "grant-a"
        )
        try check(offer.state == .offered, "offer must store offered")
        try await expect({
            _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: b, actor: b)
        }, { if case .wrongHandoffOwner = $0 { return true }; return false }, "wrong owner")
        let ack = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        try check(ack == .acknowledged, "ack state")
        let stored = await engine.currentSnapshot().handoffs.first { $0.receiptID == offer.receiptID }
        try check(stored?.state == .offered, "offer row must stay immutable after ack")
        let done = try await engine.completeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        try check(done == .completed, "complete state")
        let snapAfter = await engine.currentSnapshot()
        let still = snapAfter.handoffs.first { $0.receiptID == offer.receiptID }
        try check(still?.state == .offered, "offer row must stay immutable after complete")
        let audits = snapAfter.audits.filter {
            $0.subjectReceiptID == offer.receiptID && ($0.action == .acknowledgeHandoff || $0.action == .completeHandoff)
        }
        try check(audits.count == 2, "transition audits missing")
        try check(audits.allSatisfy { $0.goalID == "goal-1" && $0.taskID == "task-1" }, "transition audit bindings")
    }

    static func testForbiddenEscalationAndForgedAdapterLabel() async throws {
        let (engine, _) = try await seedReadyEngine()
        try await expect({
            _ = try await engine.requestEscalation(actor: .agent(try agentA()), goalID: "goal-1", scopes: [.claimTask])
        }, { $0 == .forbiddenEscalation }, "agent escalation")
        let forged = try JSONDecoder().decode(Principal.self, from: Data(#"{"role":"nativeAdapter","identifier":"forged-install"}"#.utf8))
        try await expect({
            _ = try await engine.requestEscalation(actor: forged, goalID: "goal-1", scopes: [.handoff])
        }, { $0 == .forbiddenEscalation }, "forged adapter escalation")
        // Agent Principal cannot call revokeGrant — API requires NativeAdapterAuthority (compile-time).
        // Escalation remains the runtime proof that forged labels never mint consent.
    }

    static func testHumanRootedGrantAndRevocation() async throws {
        let (engine, _) = try await seedReadyEngine(scopesA: [.claimTask], scopesB: [.claimTask])
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        try await expect({
            _ = try await engine.appendMessage(
                idempotencyKey: "m",
                goalID: "goal-1",
                taskID: "task-1",
                sender: a,
                recipient: try agentB(),
                time: stamp(),
                evidence: evidence(),
                body: "x"
            )
        }, { if case .grantMismatch = $0 { return true }; return false }, "missing scope")

        let (engine2, _) = try await seedReadyEngine()
        let a2 = try agentA()
        _ = try await engine2.claimTask(goalID: "goal-1", taskID: "task-2", expectedRevision: 0, claimant: a2, grantID: "grant-a")
        _ = try await engine2.revokeGrant(grantID: "grant-a", expectedRevision: 1, authority: try authority())
        try await expect({
            _ = try await engine2.appendMessage(
                idempotencyKey: "m2",
                goalID: "goal-1",
                taskID: "task-2",
                sender: a2,
                recipient: try agentB(),
                time: stamp(),
                evidence: evidence(),
                body: "x"
            )
        }, { if case .grantRevoked("grant-a") = $0 { return true }; return false }, "revoked grant")
        let grants = await engine2.currentSnapshot().grants
        let grant = grants.first { $0.reference.grantID == "grant-a" }
        try check(grant?.reference.user.kind == .user, "grant must stay human-rooted")
        try check(grant?.reference.grantee.kind == .agent, "grantee must stay agent")
    }

    static func testSynthesizedGrantBypassesRejectedOnValidate() throws {
        let raw = """
        {"schemaVersion":1,"recordType":"intercom-domain-snapshot","goals":[{"goalID":"goal-1","revision":1,"statement":"x","owner":{"kind":"user","identifier":"human-owner"},"status":"open"}],"claims":[],"messages":[],"handoffs":[],"grants":[{"reference":{"grantID":"g1","goalID":"goal-1","user":{"kind":"agent","identifier":"not-human"},"grantee":{"kind":"agent","identifier":"agent-a"},"scopes":["claimTask"],"revision":1},"state":"active","recordedAt":"2023-11-14T22:13:20Z","revokedAt":null}],"audits":[{"receiptID":"receipt-1","action":"recordGoal","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:20Z","snapshotRevision":1},{"receiptID":"receipt-2","action":"recordApproval","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:21Z","snapshotRevision":2}],"idempotency":[],"connectionState":"offline","auditSequence":2,"snapshotRevision":2}
        """
        do {
            _ = try IntercomSnapshot.decodeValidated(from: Data(raw.utf8))
            throw NSError(domain: "IntercomDomainContracts", code: 3, userInfo: [NSLocalizedDescriptionKey: "agent-kind user grant accepted"])
        } catch is IntercomError {
            // fail closed
        }
    }

    static func testMismatchedAuditBindingsRejected() throws {
        let raw = """
        {"schemaVersion":1,"recordType":"intercom-domain-snapshot","goals":[{"goalID":"goal-1","revision":1,"statement":"x","owner":{"kind":"user","identifier":"human-owner"},"status":"open"}],"claims":[{"taskID":"task-1","goalID":"goal-1","revision":1,"owner":{"kind":"agent","identifier":"agent-a"},"status":"claimed","handoffHops":0,"grantID":"grant-a","openHandoffReceiptID":null}],"messages":[{"goalID":"goal-1","taskID":"task-1","sender":{"kind":"agent","identifier":"agent-a"},"recipient":{"kind":"agent","identifier":"agent-b"},"receiptID":"receipt-4","time":"2023-11-14T22:13:23Z","evidence":{"kind":"text","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","byteCount":1,"note":"n"},"idempotencyKey":"k1","body":"hi"}],"handoffs":[],"grants":[{"reference":{"grantID":"grant-a","goalID":"goal-1","user":{"kind":"user","identifier":"human-owner"},"grantee":{"kind":"agent","identifier":"agent-a"},"scopes":["appendMessage","claimTask"],"revision":1},"state":"active","recordedAt":"2023-11-14T22:13:21Z","revokedAt":null}],"audits":[{"receiptID":"receipt-1","action":"recordGoal","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:20Z","snapshotRevision":1},{"receiptID":"receipt-2","action":"recordApproval","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:21Z","snapshotRevision":2},{"receiptID":"receipt-3","action":"claimTask","goalID":"goal-1","taskID":"task-1","subjectReceiptID":"","actor":{"role":"agent","identity":{"kind":"agent","identifier":"agent-a"}},"time":"2023-11-14T22:13:22Z","snapshotRevision":3},{"receiptID":"receipt-4","action":"appendMessage","goalID":"goal-OTHER","taskID":"task-1","subjectReceiptID":"","actor":{"role":"agent","identity":{"kind":"agent","identifier":"agent-a"}},"time":"2023-11-14T22:13:23Z","snapshotRevision":4}],"idempotency":[{"key":"k1","canonicalPayload":"{}","receiptID":"receipt-4"}],"connectionState":"offline","auditSequence":4,"snapshotRevision":4}
        """
        do {
            _ = try IntercomSnapshot.decodeValidated(from: Data(raw.utf8))
            throw NSError(domain: "IntercomDomainContracts", code: 4, userInfo: [NSLocalizedDescriptionKey: "mismatched audit accepted"])
        } catch is IntercomError {
            // fail closed
        }
    }

    static func testDurableCASStaleWriterAcrossReopen() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("intercom-cas-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let storeA = try AtomicFileSnapshotStore(fileURL: file)
        let engineA = try IntercomDomainEngine(persistence: storeA, clock: nowClock())
        let auth = try authority()
        try await engineA.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let revAfterGoal = await engineA.currentSnapshot().snapshotRevision

        let storeB = try AtomicFileSnapshotStore(fileURL: file)
        let engineB = try IntercomDomainEngine(persistence: storeB, clock: nowClock())
        try await engineB.transitionConnection(to: .reconnecting, authority: auth)
        let revAfterB = await engineB.currentSnapshot().snapshotRevision
        try check(revAfterB > revAfterGoal, "second writer did not advance revision")

        try await expect({
            try await engineA.transitionConnection(to: .reconnecting, authority: auth)
        }, { if case .staleRevision(revAfterGoal, revAfterB) = $0 { return true }; return false }, "stale CAS")

        let reloaded = try IntercomDomainEngine(persistence: try AtomicFileSnapshotStore(fileURL: file), clock: nowClock())
        let reloadedRev = await reloaded.currentSnapshot().snapshotRevision
        // engineB left connection `.reconnecting`; Engine.init demotes to `.offline` and advances revision.
        try check(reloadedRev == revAfterB + 1, "durable revision lost or demote bump missing")
    }

    static func testWriteFailureRollback() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let before = await engine.currentSnapshot()
        store.failNextCommit = true
        try await expect({
            _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-fail", expectedRevision: 0, claimant: try agentA(), grantID: "grant-a")
        }, { if case .notCommitted("INJECTED_COMMIT_FAILURE") = $0 { return true }; return false }, "commit failure")
        let after = await engine.currentSnapshot()
        try check(after == before, "engine memory rolled back")
        let loaded = try store.load()
        try check(loaded == before, "store rolled back")
    }

    static func testSchemaAndTamperRejection() throws {
        let future = Data(#"{"schemaVersion":2,"recordType":"intercom-domain-snapshot","goals":[],"claims":[],"messages":[],"handoffs":[],"grants":[],"audits":[],"idempotency":[],"connectionState":"offline","auditSequence":0,"snapshotRevision":0}"#.utf8)
        do {
            _ = try IntercomSnapshot.decodeValidated(from: future)
            throw NSError(domain: "IntercomDomainContracts", code: 5, userInfo: [NSLocalizedDescriptionKey: "future schema accepted"])
        } catch let error as IntercomError {
            if case .unsupportedSchema(2) = error { /* ok */ }
            else if case .persistence = error { /* wrapped ok */ }
            else { throw error }
        }
        let tampered = Data(#"{"schemaVersion":1,"recordType":"not-intercom","goals":[],"claims":[],"messages":[],"handoffs":[],"grants":[],"audits":[],"idempotency":[],"connectionState":"offline","auditSequence":0,"snapshotRevision":0}"#.utf8)
        do {
            _ = try IntercomSnapshot.decodeValidated(from: tampered)
            throw NSError(domain: "IntercomDomainContracts", code: 6, userInfo: [NSLocalizedDescriptionKey: "tamper accepted"])
        } catch is IntercomError {
            // ok
        }
    }

    static func testEngineInitValidatesCustomPersistenceEveryState() throws {
        final class Stub: IntercomPersistence, @unchecked Sendable {
            let snapshot: IntercomSnapshot
            init(_ snapshot: IntercomSnapshot) { self.snapshot = snapshot }
            func load() throws -> IntercomSnapshot? { snapshot }
            func commit(_ snapshot: IntercomSnapshot, expectedBaseRevision: UInt64) throws {}
        }
        // Empty scopes via Codable bypass of throwing init; engine init must validate every state.
        let raw = """
        {"schemaVersion":1,"recordType":"intercom-domain-snapshot","goals":[{"goalID":"goal-1","revision":1,"statement":"x","owner":{"kind":"user","identifier":"human-owner"},"status":"open"}],"claims":[],"messages":[],"handoffs":[],"grants":[{"reference":{"grantID":"g1","goalID":"goal-1","user":{"kind":"user","identifier":"human-owner"},"grantee":{"kind":"agent","identifier":"agent-a"},"scopes":[],"revision":1},"state":"active","recordedAt":"2023-11-14T22:13:20Z","revokedAt":null}],"audits":[{"receiptID":"receipt-1","action":"recordGoal","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:20Z","snapshotRevision":1},{"receiptID":"receipt-2","action":"recordApproval","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:21Z","snapshotRevision":2}],"idempotency":[],"connectionState":"unavailable","auditSequence":2,"snapshotRevision":2}
        """
        // Decode without validate, then feed Stub so Engine.init validate is the gate.
        let snapshot = try JSONDecoder().decode(IntercomSnapshot.self, from: Data(raw.utf8))
        do {
            _ = try IntercomDomainEngine(persistence: Stub(snapshot), clock: nowClock())
            throw NSError(domain: "IntercomDomainContracts", code: 7, userInfo: [NSLocalizedDescriptionKey: "empty scopes accepted on init"])
        } catch let error as IntercomError {
            try check(
                error == .invalid("EMPTY_GRANT_SCOPES") || error == .forbiddenEscalation,
                "unexpected init error \(error)"
            )
        }
    }

}
