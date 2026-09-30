import Foundation
import XCTest
@testable import IntercomDomain

/// Required 13-case suite (LS-030 / build8-intercom).
/// Pattern: establish a valid control, mutate one invariant, assert the specific error and
/// (where durable) unchanged persisted state. Unrun until dot returns a serialized slot.
final class IntercomDomainTests: XCTestCase {
    private final class ClockBox: @unchecked Sendable {
        var value = Date(timeIntervalSince1970: 1_700_000_000)
    }

    private let clockBox = ClockBox()

    private func nowClock() -> IntercomClock {
        let box = clockBox
        return IntercomClock { box.value }
    }

    private func advance() { clockBox.value = clockBox.value.addingTimeInterval(1) }

    private func stamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: clockBox.value)
    }

    private func authority() throws -> NativeAdapterAuthority {
        try NativeAdapterAuthority(installationID: "install-1")
    }

    private func user() throws -> AgentIdentity { try .user("human-owner") }
    private func agentA() throws -> AgentIdentity { try .agent("agent-a") }
    private func agentB() throws -> AgentIdentity { try .agent("agent-b") }
    private func agentC() throws -> AgentIdentity { try .agent("agent-c") }

    private func recordGrantC(on engine: IntercomDomainEngine) async throws {
        let auth = try authority()
        try await engine.recordAuthoritativeApprovals([
            try UserApprovalReference(
                grantID: "grant-c", goalID: "goal-1", user: try user(), grantee: try agentC(),
                scopes: [.claimTask, .appendMessage, .handoff], revision: 1
            )
        ], authority: auth)
        advance()
    }

    private func digest(_ text: String) -> String {
        let scalars = Array(text.utf8)
        var out = ""
        for i in 0..<64 {
            let value = scalars.isEmpty ? 0 : Int(scalars[i % scalars.count])
            out.append(String(format: "%x", (value + i) % 16))
        }
        return out
    }

    private func evidence(_ note: String = "note") throws -> MessageEvidence {
        try MessageEvidence(kind: "text", digest: digest(note), byteCount: note.utf8.count, note: note)
    }

    private func seedReadyEngine(
        store: InMemoryIntercomPersistence = InMemoryIntercomPersistence(),
        scopesA: [GrantScope] = [.claimTask, .appendMessage, .handoff],
        scopesB: [GrantScope] = [.claimTask, .appendMessage, .handoff]
    ) async throws -> (IntercomDomainEngine, InMemoryIntercomPersistence) {
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "ship package", owner: try user(), authority: auth)
        advance()
        try await engine.recordAuthoritativeApprovals([
            try UserApprovalReference(
                grantID: "grant-a", goalID: "goal-1", user: try user(), grantee: try agentA(),
                scopes: scopesA, revision: 1
            ),
            try UserApprovalReference(
                grantID: "grant-b", goalID: "goal-1", user: try user(), grantee: try agentB(),
                scopes: scopesB, revision: 1
            )
        ], authority: auth)
        advance()
        try await engine.transitionConnection(to: .reconnecting, authority: auth)
        advance()
        try await engine.transitionConnection(to: .ready, authority: auth)
        advance()
        return (engine, store)
    }

    /// Encode a valid in-memory control snapshot, then apply a single JSON mutation.
    private func mutateEncodedControl(
        _ mutate: (inout [String: Any]) -> Void
    ) async throws -> Data {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let control = await engine.currentSnapshot()
        let encoded = try JSONEncoder().encode(control)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        mutate(&object)
        return try JSONSerialization.data(withJSONObject: object)
    }

    // MARK: - 01 duplicate / restart

    func test01_DuplicateMessageReplayAcrossRestart() async throws {
        let (engine, store) = try await seedReadyEngine()
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        let time = stamp()
        let first = try await engine.appendMessage(
            idempotencyKey: "msg-1", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: time, evidence: evidence("body-a"), body: "hello"
        )
        let replay = try await engine.appendMessage(
            idempotencyKey: "msg-1", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: time, evidence: evidence("body-a"), body: "hello"
        )
        XCTAssertEqual(first.receiptID, replay.receiptID)

        let restarted = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let restartedState = await restarted.connectionState()
        XCTAssertEqual(restartedState, .offline)
        let auth = try authority()
        try await restarted.transitionConnection(to: .reconnecting, authority: auth)
        try await restarted.transitionConnection(to: .ready, authority: auth)
        let afterRestart = try await restarted.appendMessage(
            idempotencyKey: first.idempotencyKey, goalID: first.goalID, taskID: first.taskID,
            sender: first.sender, recipient: first.recipient, time: first.time,
            evidence: first.evidence, body: first.body
        )
        XCTAssertEqual(afterRestart.receiptID, first.receiptID)
        let restartedMessageCount = await restarted.currentSnapshot().messages.count
        XCTAssertEqual(restartedMessageCount, 1)
    }

    // MARK: - 02 changed idempotency payload

    func test02_ChangedIdempotencyPayloadRejected() async throws {
        let (engine, store) = try await seedReadyEngine()
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        let time = stamp()
        _ = try await engine.appendMessage(
            idempotencyKey: "msg-1", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: time, evidence: evidence("one"), body: "one"
        )
        let before = await engine.currentSnapshot()
        do {
            _ = try await engine.appendMessage(
                idempotencyKey: "msg-1", goalID: "goal-1", taskID: "task-1",
                sender: a, recipient: try agentB(), time: time, evidence: evidence("two"), body: "two"
            )
            XCTFail("expected idempotencyConflict")
        } catch IntercomError.idempotencyConflict(let key) {
            XCTAssertEqual(key, "msg-1")
        }
        let afterConflict = await engine.currentSnapshot()
        XCTAssertEqual(afterConflict, before)
        XCTAssertEqual(try store.load(), before)
    }

    // MARK: - 03 offline / reconnect

    func test03_OfflineReconnectGatesMutations() async throws {
        let store = InMemoryIntercomPersistence()
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        do {
            _ = try await engine.claimTask(
                goalID: "goal-1", taskID: "task-1", expectedRevision: 0,
                claimant: try agentA(), grantID: "grant-a"
            )
            XCTFail("expected connectionNotReady(.offline)")
        } catch IntercomError.connectionNotReady(let state) {
            XCTAssertEqual(state, .offline)
        }
        try await engine.transitionConnection(to: .reconnecting, authority: auth)
        do {
            _ = try await engine.claimTask(
                goalID: "goal-1", taskID: "task-1", expectedRevision: 0,
                claimant: try agentA(), grantID: "grant-a"
            )
            XCTFail("expected connectionNotReady(.reconnecting)")
        } catch IntercomError.connectionNotReady(let state) {
            XCTAssertEqual(state, .reconnecting)
        }
        try await engine.recordAuthoritativeApprovals([
            try UserApprovalReference(
                grantID: "grant-a", goalID: "goal-1", user: try user(), grantee: try agentA(),
                scopes: [.claimTask], revision: 1
            )
        ], authority: auth)
        try await engine.transitionConnection(to: .ready, authority: auth)
        let again = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let againState = await again.connectionState()
        XCTAssertEqual(againState, .offline)
    }

    // MARK: - 04 competing claim / stale revision

    func test04_CompetingClaimsAndStaleRevision() async throws {
        let (engine, _) = try await seedReadyEngine()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0,
            claimant: try agentA(), grantID: "grant-a"
        )
        do {
            _ = try await engine.claimTask(
                goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
                claimant: try agentB(), grantID: "grant-b"
            )
            XCTFail("expected competingClaim")
        } catch IntercomError.competingClaim(let taskID) {
            XCTAssertEqual(taskID, "task-1")
        }
        do {
            _ = try await engine.claimTask(
                goalID: "goal-1", taskID: "task-1", expectedRevision: 99,
                claimant: try agentA(), grantID: "grant-a"
            )
            XCTFail("expected staleRevision")
        } catch IntercomError.staleRevision(let expected, let actual) {
            XCTAssertEqual(expected, 99)
            XCTAssertEqual(actual, claim.revision)
        }
    }

    // MARK: - 05 wrong owner / immutable offer / bound transition audits

    func test05_WrongHandoffOwnerImmutableOfferAndTransitionAudits() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        XCTAssertEqual(offer.state, .offered)
        do {
            _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: b, actor: b)
            XCTFail("expected wrongHandoffOwner")
        } catch IntercomError.wrongHandoffOwner {
            // specific owner fence
        }
        let ack = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        XCTAssertEqual(ack, .acknowledged)
        let storedOffer = await engine.currentSnapshot().handoffs.first { $0.receiptID == offer.receiptID }
        XCTAssertEqual(storedOffer?.state, .offered)
        let done = try await engine.completeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        XCTAssertEqual(done, .completed)
        let snap = await engine.currentSnapshot()
        XCTAssertEqual(snap.handoffs.first { $0.receiptID == offer.receiptID }?.state, .offered)
        let audits = snap.audits.filter {
            $0.subjectReceiptID == offer.receiptID
                && ($0.action == .acknowledgeHandoff || $0.action == .completeHandoff)
        }
        XCTAssertEqual(audits.count, 2)
        XCTAssertTrue(audits.allSatisfy { $0.goalID == "goal-1" && $0.taskID == "task-1" })
        XCTAssertTrue(audits.allSatisfy {
            if case .agent(let actor) = $0.actor { return actor == b }
            return false
        })
    }

    // MARK: - 06 escalation / decoded Principal is not auth

    func test06_ForbiddenEscalationAndDecodedPrincipalIsNotAuthentication() async throws {
        let (engine, store) = try await seedReadyEngine()
        let before = await engine.currentSnapshot()

        // Always-forbid escalation (agent or forged label) — consent is not a domain op.
        do {
            _ = try await engine.requestEscalation(
                actor: .agent(try agentA()), goalID: "goal-1", scopes: [.claimTask]
            )
            XCTFail("expected forbiddenEscalation")
        } catch IntercomError.forbiddenEscalation {}

        let forged = try JSONDecoder().decode(
            Principal.self,
            from: Data(#"{"role":"nativeAdapter","identifier":"forged-install"}"#.utf8)
        )
        if case .nativeAdapter(let id) = forged {
            XCTAssertEqual(id, "forged-install")
        } else {
            XCTFail("fixture must decode as nativeAdapter label")
        }
        do {
            _ = try await engine.requestEscalation(actor: forged, goalID: "goal-1", scopes: [.handoff])
            XCTFail("expected forbiddenEscalation")
        } catch IntercomError.forbiddenEscalation {}

        // Guard: privileged APIs take NativeAdapterAuthority only (non-Codable).
        // There is no recordGoal/revokeGrant/transitionConnection overload that accepts Principal,
        // so a decoded nativeAdapter label cannot authenticate privileged mutations.
        // (NativeAdapterAuthority has no Codable conformance — unlike Principal.)
        let _: NativeAdapterAuthority = try authority()

        // Durable state unchanged by escalation attempts.
        let afterEscalation = await engine.currentSnapshot()
        XCTAssertEqual(afterEscalation, before)
        XCTAssertEqual(try store.load(), before)
    }

    // MARK: - 07 human-rooted grant / mismatched scope / revocation

    func test07_HumanRootedGrantMismatchedScopeAndRevocation() async throws {
        let (engine, _) = try await seedReadyEngine(scopesA: [.claimTask], scopesB: [.claimTask])
        let a = try agentA()
        _ = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        do {
            _ = try await engine.appendMessage(
                idempotencyKey: "m", goalID: "goal-1", taskID: "task-1",
                sender: a, recipient: try agentB(), time: stamp(), evidence: evidence(), body: "x"
            )
            XCTFail("expected grantMismatch for missing appendMessage scope")
        } catch IntercomError.grantMismatch {}

        let (engine2, store2) = try await seedReadyEngine()
        let a2 = try agentA()
        _ = try await engine2.claimTask(
            goalID: "goal-1", taskID: "task-2", expectedRevision: 0, claimant: a2, grantID: "grant-a"
        )
        let beforeRevoke = await engine2.currentSnapshot()
        _ = try await engine2.revokeGrant(grantID: "grant-a", expectedRevision: 1, authority: try authority())
        do {
            _ = try await engine2.appendMessage(
                idempotencyKey: "m2", goalID: "goal-1", taskID: "task-2",
                sender: a2, recipient: try agentB(), time: stamp(), evidence: evidence(), body: "x"
            )
            XCTFail("expected grantRevoked")
        } catch IntercomError.grantRevoked(let id) {
            XCTAssertEqual(id, "grant-a")
        }
        let grant = await engine2.currentSnapshot().grants.first { $0.reference.grantID == "grant-a" }
        XCTAssertEqual(grant?.state, .revoked)
        XCTAssertEqual(grant?.reference.user.kind, .user)
        XCTAssertEqual(grant?.reference.grantee.kind, .agent)
        XCTAssertNotEqual(try store2.load(), beforeRevoke)
    }

    // MARK: - 08 Codable restore: single approval invariant (user.kind)

    func test08_CodableRestoreRejectsNonHumanApprovalUser() async throws {
        let data = try await mutateEncodedControl { object in
            var grants = object["grants"] as! [[String: Any]]
            var reference = grants[0]["reference"] as! [String: Any]
            // Single invariant: approval user.kind must be user (human-rooted).
            reference["user"] = ["kind": "agent", "identifier": "not-human"]
            grants[0]["reference"] = reference
            object["grants"] = grants
        }
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .forbiddenEscalation)
        }
    }

    // MARK: - 09 Codable restore: single audit binding invariant (message goalID)

    func test09_CodableRestoreRejectsMessageAuditGoalMismatch() async throws {
        // Valid control with claim+message, then mutate only appendMessage audit.goalID.
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        _ = try await engine.appendMessage(
            idempotencyKey: "k1", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: stamp(), evidence: evidence("n"), body: "hi"
        )
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var audits = object["audits"] as! [[String: Any]]
        var mutated = false
        for i in audits.indices where (audits[i]["action"] as? String) == "appendMessage" {
            audits[i]["goalID"] = "goal-OTHER"
            mutated = true
        }
        XCTAssertTrue(mutated, "control must include appendMessage audit")
        object["audits"] = audits
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            guard let intercom = error as? IntercomError else {
                return XCTFail("expected IntercomError, got \(error)")
            }
            switch intercom {
            case .invalid("INVARIANT_AUDIT_GOAL"), .invalid("INVARIANT_MESSAGE_AUDIT"):
                break
            default:
                XCTFail("unexpected \(intercom)")
            }
        }
        XCTAssertEqual(try store.load(), control)
    }

    // MARK: - 10 durable CAS stale writer

    func test10_DurableCASStaleWriterAcrossReopen() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-cas-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let storeA = try AtomicFileSnapshotStore(fileURL: file)
        let engineA = try IntercomDomainEngine(persistence: storeA, clock: nowClock())
        let auth = try authority()
        try await engineA.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let revAfterGoal = await engineA.currentSnapshot().snapshotRevision
        let durableAfterGoal = try storeA.load()

        let storeB = try AtomicFileSnapshotStore(fileURL: file)
        let engineB = try IntercomDomainEngine(persistence: storeB, clock: nowClock())
        try await engineB.transitionConnection(to: .reconnecting, authority: auth)
        let revAfterB = await engineB.currentSnapshot().snapshotRevision
        XCTAssertGreaterThan(revAfterB, revAfterGoal)
        let durableAfterB = try XCTUnwrap(try storeB.load())

        do {
            try await engineA.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected staleRevision from CAS")
        } catch IntercomError.staleRevision(let expected, let actual) {
            XCTAssertEqual(expected, revAfterGoal)
            XCTAssertEqual(actual, revAfterB)
        }
        // Single invariant failure must leave winner's durable bytes intact.
        XCTAssertEqual(try storeA.load(), durableAfterB)
        XCTAssertNotEqual(try storeA.load(), durableAfterGoal)

        let reloaded = try IntercomDomainEngine(
            persistence: try AtomicFileSnapshotStore(fileURL: file),
            clock: nowClock()
        )
        // engineB left connection `.reconnecting`; Engine.init demotes to `.offline` and advances revision.
        let reloadedState = await reloaded.connectionState()
        let reloadedRev = await reloaded.currentSnapshot().snapshotRevision
        XCTAssertEqual(reloadedState, .offline)
        XCTAssertEqual(reloadedRev, revAfterB + 1)
    }

    // MARK: - 11 write failure / notCommitted (no durable advance)

    func test11_WriteFailureRollback() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let before = await engine.currentSnapshot()
        store.failNextCommit = true
        do {
            _ = try await engine.claimTask(
                goalID: "goal-1", taskID: "task-fail", expectedRevision: 0,
                claimant: try agentA(), grantID: "grant-a"
            )
            XCTFail("expected notCommitted INJECTED_COMMIT_FAILURE")
        } catch IntercomError.notCommitted(let detail) {
            XCTAssertEqual(detail, "INJECTED_COMMIT_FAILURE")
        }
        let afterFail = await engine.currentSnapshot()
        XCTAssertEqual(afterFail, before)
        XCTAssertEqual(try store.load(), before)
    }

    // MARK: - 12 schema / tamper (single invariant each)

    func test12_SchemaAndTamperRejection() throws {
        let future = Data(#"{"schemaVersion":2,"recordType":"intercom-domain-snapshot","goals":[],"claims":[],"messages":[],"handoffs":[],"grants":[],"audits":[],"idempotency":[],"connectionState":"offline","auditSequence":0,"snapshotRevision":0}"#.utf8)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: future)) { error in
            XCTAssertEqual(error as? IntercomError, .unsupportedSchema(2))
        }
        let tampered = Data(#"{"schemaVersion":1,"recordType":"not-intercom","goals":[],"claims":[],"messages":[],"handoffs":[],"grants":[],"audits":[],"idempotency":[],"connectionState":"offline","auditSequence":0,"snapshotRevision":0}"#.utf8)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: tampered)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("WRONG_RECORD_TYPE"))
        }
    }

    // MARK: - 13 engine init validates empty-scopes approval on unavailable

    func test13_EngineInitValidatesEmptyScopesOnUnavailablePersistence() throws {
        final class Stub: IntercomPersistence, @unchecked Sendable {
            let snapshot: IntercomSnapshot
            init(_ snapshot: IntercomSnapshot) { self.snapshot = snapshot }
            func load() throws -> IntercomSnapshot? { snapshot }
            func commit(_ snapshot: IntercomSnapshot, expectedBaseRevision: UInt64) throws {}
        }
        // Valid structural shell; single invariant: scopes == [].
        let raw = """
        {"schemaVersion":1,"recordType":"intercom-domain-snapshot","goals":[{"goalID":"goal-1","revision":1,"statement":"x","owner":{"kind":"user","identifier":"human-owner"},"status":"open"}],"claims":[],"messages":[],"handoffs":[],"grants":[{"reference":{"grantID":"g1","goalID":"goal-1","user":{"kind":"user","identifier":"human-owner"},"grantee":{"kind":"agent","identifier":"agent-a"},"scopes":[],"revision":1},"state":"active","recordedAt":"2023-11-14T22:13:20Z","revokedAt":null}],"audits":[{"receiptID":"receipt-1","action":"recordGoal","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:20Z","snapshotRevision":1},{"receiptID":"receipt-2","action":"recordApproval","goalID":"goal-1","taskID":"","subjectReceiptID":"","actor":{"role":"nativeAdapter","identifier":"install-1"},"time":"2023-11-14T22:13:21Z","snapshotRevision":2}],"idempotency":[],"connectionState":"unavailable","auditSequence":2,"snapshotRevision":2}
        """
        let snapshot = try JSONDecoder().decode(IntercomSnapshot.self, from: Data(raw.utf8))
        XCTAssertThrowsError(try IntercomDomainEngine(persistence: Stub(snapshot), clock: nowClock())) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("EMPTY_GRANT_SCOPES"))
        }
    }

    // MARK: - Blocker regressions (message restore / handoff chronology / atomic outcomes)

    func test14_IdempotencyBijectionRejectsDuplicatedFirstRecordAsSecond() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        _ = try await engine.appendMessage(
            idempotencyKey: "k1", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: stamp(), evidence: evidence("one"), body: "one"
        )
        advance()
        _ = try await engine.appendMessage(
            idempotencyKey: "k2", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: stamp(), evidence: evidence("two"), body: "two"
        )
        let control = await engine.currentSnapshot()
        XCTAssertEqual(control.messages.count, 2)
        XCTAssertEqual(control.idempotency.count, 2)
        XCTAssertNoThrow(try control.validate())
        let durableControl = try XCTUnwrap(try store.load())
        XCTAssertEqual(durableControl, control)

        // Single mutation: replace idempotency[1] with an exact copy of idempotency[0].
        // Messages and audits stay intact — rejection must be duplicate key/receipt or bijection only.
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var idempotency = object["idempotency"] as! [[String: Any]]
        idempotency[1] = idempotency[0]
        object["idempotency"] = idempotency
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            guard let intercom = error as? IntercomError else {
                return XCTFail("expected IntercomError, got \(error)")
            }
            switch intercom {
            case .invalid("DUPLICATE_IDEMPOTENCY_KEY"),
                 .invalid("DUPLICATE_IDEMPOTENCY_RECEIPT"),
                 .invalid("INVARIANT_IDEMPOTENCY_BIJECTION"),
                 .invalid("INVARIANT_IDEMPOTENCY"):
                break
            default:
                XCTFail("unexpected \(intercom) — must not pass via unrelated message-audit invalidity")
            }
        }
        // Untouched durable control preserved.
        XCTAssertEqual(try store.load(), control)
        XCTAssertNoThrow(try control.validate())
    }

    func test15_EmptyBodyWithUpdatedCanonicalPayloadRejected() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        _ = try await engine.claimTask(goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a")
        advance()
        _ = try await engine.appendMessage(
            idempotencyKey: "k1", goalID: "goal-1", taskID: "task-1",
            sender: a, recipient: try agentB(), time: stamp(), evidence: evidence("x"), body: "hello"
        )
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var messages = object["messages"] as! [[String: Any]]
        messages[0]["body"] = ""
        var idempotency = object["idempotency"] as! [[String: Any]]
        // Craft canonical for empty body — restore must still reject empty body on reconstruct.
        let emptyCanonical = try IntercomCodec.encodeString(MessageWrite(
            goalID: "goal-1",
            taskID: "task-1",
            sender: try agentA(),
            recipient: try agentB(),
            time: messages[0]["time"] as! String,
            evidence: try evidence("x"),
            body: ""
        ))
        // MessageWrite allows empty in encode path; AttributedMessage reconstruct must reject.
        idempotency[0]["canonicalPayload"] = emptyCanonical
        object["messages"] = messages
        object["idempotency"] = idempotency
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVALID_BODY"))
        }
    }

    func test16_HandoffTaskRevisionZeroRejected() throws {
        XCTAssertThrowsError(
            try HandoffReceipt(
                receiptID: "receipt-9",
                goalID: "goal-1",
                taskID: "task-1",
                fromOwner: try agentA(),
                toOwner: try agentB(),
                state: .offered,
                hop: 1,
                taskRevision: 0,
                time: "2023-11-14T22:13:20Z",
                fromGrantID: "grant-a",
                toGrantID: "grant-b"
            )
        ) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVALID_HANDOFF_TASK_REVISION"))
        }
    }

    func test17_ForgedHighOfferTaskRevisionRejected() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        _ = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var handoffs = object["handoffs"] as! [[String: Any]]
        handoffs[0]["taskRevision"] = 99
        object["handoffs"] = handoffs
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_HANDOFF_TASK_REVISION"))
        }
    }

    func test18_CompleteWithoutAckRejected() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var audits = object["audits"] as! [[String: Any]]
        // Forge a complete without ack (and bump claim as if completed) — timeline must reject.
        let lastRev = (audits.last?["snapshotRevision"] as? NSNumber)?.uint64Value ?? 0
        audits.append([
            "receiptID": "receipt-\(audits.count + 1)",
            "action": "completeHandoff",
            "goalID": "goal-1",
            "taskID": "task-1",
            "subjectReceiptID": offer.receiptID,
            "actor": ["role": "agent", "identity": ["kind": "agent", "identifier": "agent-b"]],
            "time": "2023-11-14T22:13:30Z",
            "snapshotRevision": lastRev + 1
        ])
        object["audits"] = audits
        object["auditSequence"] = audits.count
        object["snapshotRevision"] = lastRev + 1
        var claims = object["claims"] as! [[String: Any]]
        claims[0]["owner"] = ["kind": "agent", "identifier": "agent-b"]
        claims[0]["grantID"] = "grant-b"
        claims[0]["handoffHops"] = 1
        claims[0]["status"] = "claimed"
        claims[0]["openHandoffReceiptID"] = NSNull()
        claims[0]["revision"] = ((claims[0]["revision"] as? NSNumber)?.uint64Value ?? 1) + 2
        object["claims"] = claims
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_HANDOFF_TIMELINE"))
        }
    }

    func test19_NonexistentToGrantIDRejected() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        _ = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var handoffs = object["handoffs"] as! [[String: Any]]
        handoffs[0]["toGrantID"] = "grant-missing"
        object["handoffs"] = handoffs
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_HANDOFF_GRANT"))
        }
    }

    func test20_AfterCompleteRevertOwnerToARejected() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        _ = try await engine.completeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        let control = await engine.currentSnapshot()
        XCTAssertEqual(control.claims[0].owner, b)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var claims = object["claims"] as! [[String: Any]]
        claims[0]["owner"] = ["kind": "agent", "identifier": "agent-a"]
        claims[0]["grantID"] = "grant-a"
        object["claims"] = claims
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_CLAIM_AFTER_HANDOFF"))
        }
    }

    func test21_CrossHopOwnerChainAndOutOfOrderChronology() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        // Need agent C for second hop? B hands to A as hop 2 — fromOwner B after hop1.
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer1 = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer1.receiptID, expectedOwner: a, actor: b)
        _ = try await engine.completeHandoff(receiptID: offer1.receiptID, expectedOwner: a, actor: b)
        let after1 = await engine.currentSnapshot().claims[0]
        XCTAssertEqual(after1.owner, b)
        XCTAssertEqual(after1.handoffHops, 1)
        advance()
        let offer2 = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: after1.revision,
            fromOwner: b, toOwner: a, grantID: "grant-b"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer2.receiptID, expectedOwner: b, actor: a)
        _ = try await engine.completeHandoff(receiptID: offer2.receiptID, expectedOwner: b, actor: a)
        let valid = await engine.currentSnapshot()
        XCTAssertEqual(valid.claims[0].owner, a)
        XCTAssertEqual(valid.claims[0].handoffHops, 2)
        XCTAssertNoThrow(try valid.validate())

        // Out-of-order: swap offer audit revisions so hop2 offer appears before hop1 complete.
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(valid)) as? [String: Any])
        var audits = object["audits"] as! [[String: Any]]
        guard let o1 = audits.firstIndex(where: {
            ($0["action"] as? String) == "offerHandoff" && ($0["receiptID"] as? String) == offer1.receiptID
        }),
        let c1 = audits.firstIndex(where: {
            ($0["action"] as? String) == "completeHandoff" && ($0["subjectReceiptID"] as? String) == offer1.receiptID
        }),
        let o2 = audits.firstIndex(where: {
            ($0["action"] as? String) == "offerHandoff" && ($0["receiptID"] as? String) == offer2.receiptID
        }) else {
            return XCTFail("missing handoff audits")
        }
        let revO2 = audits[o2]["snapshotRevision"] as! NSNumber
        let revC1 = audits[c1]["snapshotRevision"] as! NSNumber
        // Place hop2 offer revision before hop1 complete while keeping hop numbers.
        audits[o2]["snapshotRevision"] = NSNumber(value: revC1.uint64Value - 1)
        // Keep unique increasing receipt order but force chronology break on offer2 vs complete1.
        _ = revO2
        _ = o1
        object["audits"] = audits
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            // May fail chronology or audit revision monotonicity depending on forge.
            guard let intercom = error as? IntercomError else {
                return XCTFail("expected IntercomError, got \(error)")
            }
            switch intercom {
            case .invalid("INVARIANT_HANDOFF_CHRONOLOGY"), .invalid("INVARIANT_AUDIT_REVISION"):
                break
            default:
                XCTFail("unexpected \(intercom)")
            }
        }
    }

    func test22_RevokedOpenHistoryValidControlPreserved() async throws {
        let (engine, _) = try await seedReadyEngine()
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        _ = try await engine.revokeGrant(grantID: "grant-a", expectedRevision: 1, authority: try authority())
        let snap = await engine.currentSnapshot()
        XCTAssertEqual(try snap.derivedHandoffState(for: offer.receiptID), .revoked)
        XCTAssertEqual(snap.claims[0].status, .claimed)
        XCTAssertNil(snap.claims[0].openHandoffReceiptID)
        XCTAssertEqual(snap.claims[0].owner, a)
        XCTAssertNoThrow(try snap.validate())
    }

    func test23_AtomicPrewriteAndPrepublishAreNotCommitted() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-fault-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let before = try XCTUnwrap(try store.load())

        store.injectCommitFault = .beforeWrite
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected notCommitted prewrite")
        } catch IntercomError.notCommitted(let detail) {
            XCTAssertTrue(detail.contains("PREWRITE") || detail == "INJECTED_PREWRITE")
        }
        XCTAssertEqual(try store.load(), before)
        let memAfterPrewrite = await engine.currentSnapshot()
        XCTAssertEqual(memAfterPrewrite, before)

        store.injectCommitFault = .beforePublish
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected notCommitted prepublish")
        } catch IntercomError.notCommitted(let detail) {
            XCTAssertTrue(detail.contains("PREPUBLISH") || detail == "INJECTED_PREPUBLISH")
        }
        XCTAssertEqual(try store.load(), before)
    }

    func test24_PostpublishReconcilesMemoryWithDiskThenSurfacesCommittedUnknown() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-post-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let beforeRev = await engine.currentSnapshot().snapshotRevision

        store.injectCommitFault = .afterPublish
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected committedUnknown postpublish")
        } catch IntercomError.committedUnknown(let published, _) {
            XCTAssertGreaterThan(published, beforeRev)
        }
        let disk = try XCTUnwrap(try store.load())
        let memory = await engine.currentSnapshot()
        XCTAssertEqual(memory, disk)
        XCTAssertEqual(memory.connectionState, .reconnecting)
    }

    func test25_AttemptedPublishUnverifiedLoadIsCommittedUnknown() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-ambig-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let before = try XCTUnwrap(try store.load())

        // Discriminating path: attempted publish failure + failed verification read.
        // Cannot prove durable base unchanged → committedUnknown (not notCommitted).
        store.injectCommitFault = .attemptedPublish
        store.injectVerifyReadFault = true
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected committedUnknown unverified replace")
        } catch IntercomError.committedUnknown(_, let detail) {
            XCTAssertTrue(detail.contains("UNVERIFIED") || detail.contains("RECONCILE"))
        }
        // When verify read failed inside store, durable bytes should still be prior if inject
        // only simulated throw before replace — engine may be blocked if reconcile load also fails.
        // Prove we did not mis-classify as notCommitted with an unproven base.
        let afterDisk = try store.load()
        XCTAssertEqual(afterDisk, before)
    }

    func test26_AttemptedPublishWithProvenUnchangedBaseIsNotCommitted() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-proven-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let before = try XCTUnwrap(try store.load())
        store.injectCommitFault = .attemptedPublish
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected notCommitted when base proven unchanged")
        } catch IntercomError.notCommitted {
            // ok
        }
        XCTAssertEqual(try store.load(), before)
        let memory = await engine.currentSnapshot()
        XCTAssertEqual(memory, before)
    }

    func test27_BlockedRetryWhenReconcileLoadFails() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-block-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)

        store.injectCommitFault = .afterPublish
        store.injectLoadFault = true // reconcile load after committedUnknown fails
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected committedUnknown with reconcile load failure")
        } catch IntercomError.committedUnknown(_, let detail) {
            XCTAssertTrue(detail.contains("RECONCILE_LOAD_FAILED") || detail.contains("POSTPUBLISH"))
        }
        // Retry must stay blocked until reconcile succeeds.
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected blocked retry")
        } catch IntercomError.committedUnknown(_, let detail) {
            XCTAssertTrue(detail.contains("RECONCILE_REQUIRED") || detail.contains("RECONCILE_LOAD_FAILED"))
        }
        // Explicit reconcile after load works again.
        try await engine.reconcileFromPersistence()
        let disk = try XCTUnwrap(try store.load())
        let memory = await engine.currentSnapshot()
        XCTAssertEqual(memory, disk)
    }

    func test28_ReadbackFaultIsCommittedUnknownWithMemoryDiskAgree() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-readback-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        let beforeRev = await engine.currentSnapshot().snapshotRevision

        // Discriminating from afterPublish: explicit .readback injection after durable publish.
        store.injectCommitFault = .readback
        do {
            try await engine.transitionConnection(to: .reconnecting, authority: auth)
            XCTFail("expected committedUnknown readback")
        } catch IntercomError.committedUnknown(let published, let detail) {
            XCTAssertGreaterThan(published, beforeRev)
            XCTAssertTrue(detail.contains("READBACK") || detail.contains("INJECTED_READBACK"))
        }
        let disk = try XCTUnwrap(try store.load())
        let memory = await engine.currentSnapshot()
        XCTAssertEqual(memory, disk)
        XCTAssertEqual(memory.connectionState, .reconnecting)
    }

    func test29_InitDemotionCommittedUnknownReconcilesToOffline() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-init-demote-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        try await engine.transitionConnection(to: .reconnecting, authority: auth)
        let pre = try XCTUnwrap(try store.load())
        XCTAssertEqual(pre.connectionState, .reconnecting)
        let preRev = pre.snapshotRevision

        // Fresh store/engine: init demotion commit hits .readback after publish → committedUnknown path.
        let store2 = try AtomicFileSnapshotStore(fileURL: file)
        store2.injectCommitFault = .readback
        let restarted = try IntercomDomainEngine(persistence: store2, clock: nowClock())
        let state = await restarted.connectionState()
        let mem = await restarted.currentSnapshot()
        let disk = try XCTUnwrap(try store2.load())
        XCTAssertEqual(state, .offline)
        XCTAssertEqual(mem, disk)
        XCTAssertEqual(disk.connectionState, .offline)
        XCTAssertEqual(disk.snapshotRevision, preRev + 1)
        // Further mutation must not be blocked by a stale reconcile flag after init reconcile.
        try await restarted.transitionConnection(to: .reconnecting, authority: auth)
        let after = await restarted.connectionState()
        XCTAssertEqual(after, .reconnecting)
    }

    /// r2 blocker: unpublished demotion `committedUnknown` must not swallow into a READY engine.
    func test30_InitDemotionUnpublishedUnknownMustNotReturnReady() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("intercom-init-unpub-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("snapshot.json")
        let store = try AtomicFileSnapshotStore(fileURL: file)
        let engine = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let auth = try authority()
        try await engine.recordGoal(goalID: "goal-1", statement: "x", owner: try user(), authority: auth)
        try await engine.transitionConnection(to: .reconnecting, authority: auth)
        try await engine.transitionConnection(to: .ready, authority: auth)
        let control = try XCTUnwrap(try store.load())
        XCTAssertEqual(control.connectionState, .ready)
        XCTAssertNoThrow(try control.validate())

        // Fresh store: demotion publish attempt fails unverified — durable base stays READY.
        let store2 = try AtomicFileSnapshotStore(fileURL: file)
        store2.injectCommitFault = .attemptedPublish
        store2.injectVerifyReadFault = true
        do {
            _ = try IntercomDomainEngine(persistence: store2, clock: nowClock())
            XCTFail("init must fail closed; must not return a READY instance on unpublished committedUnknown")
        } catch IntercomError.committedUnknown {
            // expected fail-closed
        }

        let durable = try XCTUnwrap(try store2.load())
        XCTAssertEqual(durable, control)
        XCTAssertEqual(durable.connectionState, .ready)
    }

    // MARK: - r2 restore grant scope (single-invariant)

    private func completedHandoffControl() async throws -> (IntercomSnapshot, InMemoryIntercomPersistence) {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        _ = try await engine.completeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        let control = await engine.currentSnapshot()
        XCTAssertNoThrow(try control.validate())
        XCTAssertEqual(control.claims[0].owner, b)
        XCTAssertEqual(control.claims[0].grantID, "grant-b")
        XCTAssertEqual(try store.load(), control)
        return (control, store)
    }

    func test31_CompletedHandoffControlValidatesWithGrantScopes() async throws {
        let (control, store) = try await completedHandoffControl()
        XCTAssertNoThrow(try control.validate())
        XCTAssertEqual(try store.load(), control)
    }

    func test32_RestoreRejectsCompletedHistoryWhenFromGrantLacksHandoffScope() async throws {
        let (control, store) = try await completedHandoffControl()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var grants = object["grants"] as! [[String: Any]]
        var mutated = false
        for i in grants.indices {
            var reference = grants[i]["reference"] as! [String: Any]
            if (reference["grantID"] as? String) == "grant-a" {
                // Single invariant: drop only .handoff from A; identity/goal unchanged.
                reference["scopes"] = ["appendMessage", "claimTask"]
                grants[i]["reference"] = reference
                mutated = true
            }
        }
        XCTAssertTrue(mutated)
        object["grants"] = grants
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_HANDOFF_GRANT_SCOPE"))
        }
        XCTAssertEqual(try store.load(), control)
        XCTAssertNoThrow(try control.validate())
    }

    func test33_RestoreRejectsWhenClaimGrantLacksClaimTaskScope() async throws {
        let (control, store) = try await completedHandoffControl()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var grants = object["grants"] as! [[String: Any]]
        var mutated = false
        for i in grants.indices {
            var reference = grants[i]["reference"] as! [String: Any]
            if (reference["grantID"] as? String) == "grant-b" {
                // Single invariant on current claim grant (B): drop only .claimTask.
                // Keep .handoff so from-side history is not the failing axis.
                reference["scopes"] = ["appendMessage", "handoff"]
                grants[i]["reference"] = reference
                mutated = true
            }
        }
        XCTAssertTrue(mutated)
        object["grants"] = grants
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            // Claim validation runs before handoff toGrant scope; expect claim-scope rejection.
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_CLAIM_GRANT_SCOPE"))
        }
        XCTAssertEqual(try store.load(), control)
        XCTAssertNoThrow(try control.validate())
    }

    func test34_RevokedOpenHistoryStillValidatesWithScopesIntact() async throws {
        // Retains valid revoked-open history (scopes remain on stored grants).
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        _ = try await engine.revokeGrant(grantID: "grant-a", expectedRevision: 1, authority: try authority())
        let snap = await engine.currentSnapshot()
        XCTAssertEqual(try snap.derivedHandoffState(for: offer.receiptID), .revoked)
        XCTAssertEqual(snap.claims[0].handoffHops, 0)
        XCTAssertEqual(snap.claims[0].status, .claimed)
        XCTAssertNil(snap.claims[0].openHandoffReceiptID)
        XCTAssertEqual(snap.claims[0].owner, a)
        XCTAssertTrue(snap.audits.contains {
            $0.action == .cancelHandoff && $0.subjectReceiptID == offer.receiptID
        })
        XCTAssertNoThrow(try snap.validate())
        XCTAssertEqual(try store.load(), snap)
        // Revoke emits durable cancel evidence in the same transaction (B8-INTERCOM-RECOVERY).
        // Re-offer after revoke of a *recipient* grant is covered by recovery tests; revoking the
        // owner grant still refuses new offers until a fresh active scoped grant exists.
    }

    func test35_RestoreRejectsOpenHandoffWhenToGrantLacksClaimTaskScope() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        _ = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let control = await engine.currentSnapshot()
        XCTAssertNoThrow(try control.validate())
        // Claim still on grant-a (has claimTask). Single invariant: strip claimTask from toGrant only (grant-b).
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var grants = object["grants"] as! [[String: Any]]
        var mutated = false
        for i in grants.indices {
            var reference = grants[i]["reference"] as! [String: Any]
            if (reference["grantID"] as? String) == "grant-b" {
                reference["scopes"] = ["appendMessage", "handoff"]
                grants[i]["reference"] = reference
                mutated = true
            }
        }
        XCTAssertTrue(mutated)
        object["grants"] = grants
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_HANDOFF_GRANT_SCOPE"))
        }
        XCTAssertEqual(try store.load(), control)
    }

    // MARK: - B8-INTERCOM-RECOVERY (36+)

    func test36_CancelOpenThenReofferToAuthorizedAgentC() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        try await recordGrantC(on: engine)
        let a = try agentA()
        let b = try agentB()
        let c = try agentC()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offerAB = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        XCTAssertEqual(offerAB.hop, 1)
        let beforeCancel = await engine.currentSnapshot()
        let cancelled = try await engine.cancelHandoff(
            receiptID: offerAB.receiptID, expectedRevision: beforeCancel.claims[0].revision, actor: a
        )
        XCTAssertEqual(cancelled, .revoked)
        let afterCancel = await engine.currentSnapshot()
        XCTAssertEqual(try afterCancel.derivedHandoffState(for: offerAB.receiptID), .revoked)
        XCTAssertEqual(afterCancel.claims[0].handoffHops, 0)
        XCTAssertEqual(afterCancel.claims[0].owner, a)
        XCTAssertEqual(afterCancel.claims[0].grantID, "grant-a")
        XCTAssertNil(afterCancel.claims[0].openHandoffReceiptID)
        XCTAssertEqual(afterCancel.handoffs.first { $0.receiptID == offerAB.receiptID }?.state, .offered)
        XCTAssertTrue(afterCancel.audits.contains {
            $0.action == .cancelHandoff && $0.subjectReceiptID == offerAB.receiptID
        })
        XCTAssertNoThrow(try afterCancel.validate())

        let offerAC = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: afterCancel.claims[0].revision,
            fromOwner: a, toOwner: c, grantID: "grant-a"
        )
        XCTAssertNotEqual(offerAC.receiptID, offerAB.receiptID)
        XCTAssertEqual(offerAC.hop, 1)
        XCTAssertEqual(offerAC.toOwner, c)
        let snap = await engine.currentSnapshot()
        XCTAssertEqual(snap.handoffs.count, 2)
        XCTAssertEqual(try snap.derivedHandoffState(for: offerAB.receiptID), .revoked)
        XCTAssertEqual(try snap.derivedHandoffState(for: offerAC.receiptID), .offered)
        XCTAssertEqual(snap.claims[0].handoffHops, 0)
        XCTAssertNoThrow(try snap.validate())
        XCTAssertEqual(try store.load(), snap)
    }

    func test37_DuplicateCancelIsIdempotentAndLeavesDurableEvidence() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let rev = (await engine.currentSnapshot()).claims[0].revision
        let first = try await engine.cancelHandoff(receiptID: offer.receiptID, expectedRevision: rev, actor: a)
        XCTAssertEqual(first, .revoked)
        let afterFirst = await engine.currentSnapshot()
        let second = try await engine.cancelHandoff(
            receiptID: offer.receiptID, expectedRevision: afterFirst.claims[0].revision, actor: a
        )
        XCTAssertEqual(second, .revoked)
        let afterSecond = await engine.currentSnapshot()
        XCTAssertEqual(afterSecond, afterFirst)
        XCTAssertEqual(
            afterSecond.audits.filter { $0.action == .cancelHandoff && $0.subjectReceiptID == offer.receiptID }.count,
            1
        )
        XCTAssertEqual(try store.load(), afterFirst)
    }

    func test38_StaleCancelRevisionRejectedWithoutMutation() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let control = await engine.currentSnapshot()
        do {
            _ = try await engine.cancelHandoff(receiptID: offer.receiptID, expectedRevision: 0, actor: a)
            XCTFail("expected staleRevision")
        } catch IntercomError.staleRevision(let expected, let actual) {
            XCTAssertEqual(expected, 0)
            XCTAssertEqual(actual, control.claims[0].revision)
        }
        XCTAssertEqual(await engine.currentSnapshot(), control)
        XCTAssertEqual(try store.load(), control)
    }

    func test39_CancelSurvivesRestartThenReoffer() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        try await recordGrantC(on: engine)
        let a = try agentA()
        let b = try agentB()
        let c = try agentC()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offerAB = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let rev = (await engine.currentSnapshot()).claims[0].revision
        _ = try await engine.cancelHandoff(receiptID: offerAB.receiptID, expectedRevision: rev, actor: a)
        let durable = try store.load()!
        XCTAssertNoThrow(try durable.validate())

        let restarted = try IntercomDomainEngine(persistence: store, clock: nowClock())
        let loaded = await restarted.currentSnapshot()
        XCTAssertEqual(try loaded.derivedHandoffState(for: offerAB.receiptID), .revoked)
        XCTAssertEqual(loaded.claims[0].handoffHops, 0)
        // Init demotes READY→offline; reconnect before mutation.
        let auth = try authority()
        try await restarted.transitionConnection(to: .reconnecting, authority: auth)
        advance()
        try await restarted.transitionConnection(to: .ready, authority: auth)
        advance()
        let offerAC = try await restarted.offerHandoff(
            goalID: "goal-1", taskID: "task-1",
            expectedRevision: (await restarted.currentSnapshot()).claims[0].revision,
            fromOwner: a, toOwner: c, grantID: "grant-a"
        )
        XCTAssertEqual(offerAC.hop, 1)
        XCTAssertNotEqual(offerAC.receiptID, offerAB.receiptID)
        let afterRestartOffer = await restarted.currentSnapshot()
        XCTAssertNoThrow(try afterRestartOffer.validate())
    }

    func test40_CompletedHandoffCancelDenied() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        _ = try await engine.completeHandoff(receiptID: offer.receiptID, expectedOwner: a, actor: b)
        let control = await engine.currentSnapshot()
        XCTAssertEqual(control.claims[0].handoffHops, 1)
        do {
            _ = try await engine.cancelHandoff(
                receiptID: offer.receiptID, expectedRevision: control.claims[0].revision, actor: a
            )
            XCTFail("expected handoffNotReady")
        } catch IntercomError.handoffNotReady(let receiptID) {
            XCTAssertEqual(receiptID, offer.receiptID)
        }
        let afterDenied = await engine.currentSnapshot()
        XCTAssertEqual(afterDenied, control)
        XCTAssertEqual(try store.load(), control)
    }

    func test41_RevokeGrantCancelsOpenAttemptSameTransactionThenReoffer() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        try await recordGrantC(on: engine)
        let a = try agentA()
        let b = try agentB()
        let c = try agentC()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offerAB = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.acknowledgeHandoff(receiptID: offerAB.receiptID, expectedOwner: a, actor: b)
        let before = await engine.currentSnapshot()
        _ = try await engine.revokeGrant(grantID: "grant-b", expectedRevision: 1, authority: try authority())
        let after = await engine.currentSnapshot()
        XCTAssertEqual(try after.derivedHandoffState(for: offerAB.receiptID), .revoked)
        XCTAssertEqual(after.claims[0].owner, a)
        XCTAssertEqual(after.claims[0].grantID, "grant-a")
        XCTAssertEqual(after.claims[0].handoffHops, 0)
        XCTAssertNil(after.claims[0].openHandoffReceiptID)
        let cancelAudits = after.audits.filter {
            $0.action == .cancelHandoff && $0.subjectReceiptID == offerAB.receiptID
        }
        XCTAssertEqual(cancelAudits.count, 1)
        if case .nativeAdapter = cancelAudits[0].actor {} else {
            XCTFail("revoke-path cancel must be nativeAdapter actor")
        }
        let revokeIdx = after.audits.lastIndex { $0.action == .revokeGrant }!
        let cancelIdx = after.audits.firstIndex {
            $0.action == .cancelHandoff && $0.subjectReceiptID == offerAB.receiptID
        }!
        XCTAssertLessThan(cancelIdx, revokeIdx)
        XCTAssertNoThrow(try after.validate())
        XCTAssertNotEqual(after, before)

        let offerAC = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: after.claims[0].revision,
            fromOwner: a, toOwner: c, grantID: "grant-a"
        )
        XCTAssertEqual(offerAC.hop, 1)
        XCTAssertNotEqual(offerAC.receiptID, offerAB.receiptID)
        let finalSnap = await engine.currentSnapshot()
        XCTAssertEqual(try store.load(), finalSnap)
    }

    func test42_ForgedCrossGoalCancelRejectedOnRestore() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let rev = (await engine.currentSnapshot()).claims[0].revision
        _ = try await engine.cancelHandoff(receiptID: offer.receiptID, expectedRevision: rev, actor: a)
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var audits = object["audits"] as! [[String: Any]]
        var mutated = false
        for i in audits.indices {
            if (audits[i]["action"] as? String) == "cancelHandoff" {
                audits[i]["goalID"] = "goal-forged"
                mutated = true
            }
        }
        XCTAssertTrue(mutated)
        object["audits"] = audits
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data))
        XCTAssertEqual(try store.load(), control)
        XCTAssertNoThrow(try control.validate())
    }

    func test43_ForgedCrossTaskCancelRejectedOnRestore() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        let rev = (await engine.currentSnapshot()).claims[0].revision
        _ = try await engine.cancelHandoff(receiptID: offer.receiptID, expectedRevision: rev, actor: a)
        let control = await engine.currentSnapshot()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var audits = object["audits"] as! [[String: Any]]
        var mutated = false
        for i in audits.indices {
            if (audits[i]["action"] as? String) == "cancelHandoff" {
                audits[i]["taskID"] = "task-forged"
                mutated = true
            }
        }
        XCTAssertTrue(mutated)
        object["audits"] = audits
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: data))
        XCTAssertEqual(try store.load(), control)
    }

    func test44_ForgedDuplicateCancelAndAttemptReorderRejected() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        try await recordGrantC(on: engine)
        let a = try agentA()
        let b = try agentB()
        let c = try agentC()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offerAB = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        var rev = (await engine.currentSnapshot()).claims[0].revision
        _ = try await engine.cancelHandoff(receiptID: offerAB.receiptID, expectedRevision: rev, actor: a)
        rev = (await engine.currentSnapshot()).claims[0].revision
        _ = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: rev,
            fromOwner: a, toOwner: c, grantID: "grant-a"
        )
        let control = await engine.currentSnapshot()
        XCTAssertNoThrow(try control.validate())

        // Duplicate cancel evidence for the same attempt.
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var audits = object["audits"] as! [[String: Any]]
        let lastRev = (audits.last?["snapshotRevision"] as? NSNumber)?.uint64Value ?? 0
        audits.append([
            "receiptID": "receipt-\(audits.count + 1)",
            "action": "cancelHandoff",
            "goalID": "goal-1",
            "taskID": "task-1",
            "subjectReceiptID": offerAB.receiptID,
            "actor": ["role": "agent", "identity": ["kind": "agent", "identifier": "agent-a"]],
            "time": "2023-11-14T22:14:00Z",
            "snapshotRevision": lastRev + 1
        ])
        object["audits"] = audits
        object["auditSequence"] = audits.count
        object["snapshotRevision"] = lastRev + 1
        let dupData = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: dupData)) { error in
            XCTAssertEqual(error as? IntercomError, .invalid("INVARIANT_HANDOFF_TIMELINE"))
        }

        // Attempt reorder: swap offer audit revisions chronologically illegally.
        var reorder = try XCTUnwrap(JSONSerialization.jsonObject(with: try JSONEncoder().encode(control)) as? [String: Any])
        var reorderAudits = reorder["audits"] as! [[String: Any]]
        var offerIndexes: [Int] = []
        for i in reorderAudits.indices where (reorderAudits[i]["action"] as? String) == "offerHandoff" {
            offerIndexes.append(i)
        }
        XCTAssertEqual(offerIndexes.count, 2)
        let rev0 = reorderAudits[offerIndexes[0]]["snapshotRevision"] as! NSNumber
        let rev1 = reorderAudits[offerIndexes[1]]["snapshotRevision"] as! NSNumber
        reorderAudits[offerIndexes[0]]["snapshotRevision"] = rev1
        reorderAudits[offerIndexes[1]]["snapshotRevision"] = rev0
        reorder["audits"] = reorderAudits
        let reorderData = try JSONSerialization.data(withJSONObject: reorder)
        XCTAssertThrowsError(try IntercomSnapshot.decodeValidated(from: reorderData))
        XCTAssertEqual(try store.load(), control)
    }

    func test45_CancelDoesNotTransferOrReviveAuthorization() async throws {
        let store = InMemoryIntercomPersistence()
        let (engine, _) = try await seedReadyEngine(store: store)
        let a = try agentA()
        let b = try agentB()
        let claim = try await engine.claimTask(
            goalID: "goal-1", taskID: "task-1", expectedRevision: 0, claimant: a, grantID: "grant-a"
        )
        advance()
        let offer = try await engine.offerHandoff(
            goalID: "goal-1", taskID: "task-1", expectedRevision: claim.revision,
            fromOwner: a, toOwner: b, grantID: "grant-a"
        )
        _ = try await engine.revokeGrant(grantID: "grant-a", expectedRevision: 1, authority: try authority())
        let afterRevoke = await engine.currentSnapshot()
        XCTAssertEqual(try afterRevoke.derivedHandoffState(for: offer.receiptID), .revoked)
        XCTAssertEqual(afterRevoke.claims[0].owner, a)
        XCTAssertEqual(afterRevoke.claims[0].grantID, "grant-a")
        // Owner grant revoked: cannot re-offer (no revive). Recipient grant alone is insufficient.
        do {
            _ = try await engine.offerHandoff(
                goalID: "goal-1", taskID: "task-1",
                expectedRevision: afterRevoke.claims[0].revision,
                fromOwner: a, toOwner: b, grantID: "grant-a"
            )
            XCTFail("expected grantRevoked")
        } catch IntercomError.grantRevoked(let grantID) {
            XCTAssertEqual(grantID, "grant-a")
        }
        let afterRefuse = await engine.currentSnapshot()
        XCTAssertEqual(afterRefuse, afterRevoke)
        XCTAssertEqual(try store.load(), afterRevoke)
    }
}
