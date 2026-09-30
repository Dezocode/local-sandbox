import Foundation

/// Platform-neutral Intercom journal.
/// User approvals enter only as external references from a native-adapter authority handle.
/// Agents cannot mint consent, widen a grant, or revoke one.
///
/// Privileged APIs require non-Codable `NativeAdapterAuthority`. Codable `Principal` is an
/// audit label only — decoded `nativeAdapter` JSON cannot authenticate or call privileged APIs.
///
/// `NativeAdapterAuthority`'s public constructor is a **trusted HOST-ONLY** capability mint:
/// it is not user authentication and confers no privilege from a decoded label.
public actor IntercomDomainEngine {
    private let persistence: any IntercomPersistence
    private let clock: IntercomClock
    private var snapshot: IntercomSnapshot
    /// When set, durable publish may have advanced while in-memory state is stale or load failed.
    /// All mutations refuse until `reconcileFromPersistence()` succeeds.
    private var blockedReconcile: (publishedRevision: UInt64, detail: String)?

    public init(persistence: any IntercomPersistence, clock: IntercomClock = .system) throws {
        self.persistence = persistence
        self.clock = clock
        let loaded = try persistence.load() ?? .empty
        // Validate every restore path for every connection state and custom persistence.
        try loaded.validate()
        self.blockedReconcile = nil
        if loaded.connectionState == .ready || loaded.connectionState == .reconnecting {
            let base = loaded.snapshotRevision
            guard base < UInt64.max else {
                throw IntercomError.persistence("REVISION_EXHAUSTED")
            }
            var demoted = loaded
            demoted.connectionState = .offline
            demoted.snapshotRevision += 1
            try demoted.validate()
            // Memory stays at pre-demotion until publish succeeds or reconcile advances it.
            self.snapshot = loaded
            do {
                try Self.applyCommit(
                    persistence: persistence,
                    working: demoted,
                    expectedBaseRevision: base,
                    snapshot: &self.snapshot,
                    blockedReconcile: &self.blockedReconcile
                )
            } catch let error as IntercomError {
                // Demotion must land offline. If reconcile reloads unchanged READY/reconnecting
                // (unpublished / unverified publish), fail closed — do not return a live READY engine.
                if case .committedUnknown = error {
                    if self.blockedReconcile != nil { throw error }
                    try self.snapshot.validate()
                    guard self.snapshot.connectionState == .offline else { throw error }
                } else {
                    throw error
                }
            }
        } else {
            self.snapshot = loaded
        }
    }

    /// Reload durable snapshot after `committedUnknown`. Required before retry when blocked.
    public func reconcileFromPersistence() throws {
        try performReconcile()
    }

    public func currentSnapshot() -> IntercomSnapshot { snapshot }

    public func connectionState() -> ConnectionState { snapshot.connectionState }

    public func handoffState(receiptID: String) throws -> HandoffState {
        try snapshot.derivedHandoffState(for: receiptID)
    }

    /// Always refuses. Consent is not a domain operation.
    public func requestEscalation(actor: Principal, goalID: String, scopes: [GrantScope]) throws -> UserApprovalReference {
        _ = actor
        _ = goalID
        _ = scopes
        throw IntercomError.forbiddenEscalation
    }

    @discardableResult
    public func recordGoal(
        goalID: String,
        statement: String,
        owner: AgentIdentity,
        authority: NativeAdapterAuthority
    ) throws -> GoalRecord {
        try requireWritable()
        let actor = authority.auditLabel
        let goal = try GoalRecord(goalID: goalID, revision: 1, statement: statement, owner: owner, status: .open)
        if let existing = snapshot.goals.first(where: { $0.goalID == goal.goalID }) {
            guard existing == goal else { throw IntercomError.invalid("GOAL_CONFLICT") }
            return existing
        }
        try commitIfChanged { snapshot in
            guard snapshot.goals.count < IntercomLimits.maxGoals else {
                throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
            }
            snapshot.goals.append(goal)
            try touch(&snapshot, action: .recordGoal, goalID: goal.goalID, taskID: "", subjectReceiptID: "", actor: actor)
            return true
        }
        return goal
    }

    public func recordAuthoritativeApprovals(
        _ approvals: [UserApprovalReference],
        authority: NativeAdapterAuthority
    ) throws {
        try requireWritable()
        let actor = authority.auditLabel
        try commitIfChanged { snapshot in
            var changed = false
            for approval in approvals {
                let normalized = try UserApprovalReference(
                    grantID: approval.grantID,
                    goalID: approval.goalID,
                    user: approval.user,
                    grantee: approval.grantee,
                    scopes: approval.scopes,
                    revision: approval.revision
                )
                guard snapshot.goals.contains(where: { $0.goalID == normalized.goalID }) else {
                    throw IntercomError.invalid("UNKNOWN_GOAL")
                }
                if let existing = snapshot.grants.first(where: { $0.reference.grantID == normalized.grantID }) {
                    guard existing.reference == normalized else {
                        throw IntercomError.grantMismatch(grantID: normalized.grantID)
                    }
                    continue
                }
                let pairTaken = snapshot.grants.contains {
                    $0.state == .active
                        && $0.reference.goalID == normalized.goalID
                        && $0.reference.grantee == normalized.grantee
                }
                guard !pairTaken else { throw IntercomError.grantMismatch(grantID: normalized.grantID) }
                guard snapshot.grants.count < IntercomLimits.maxGrants else {
                    throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
                }
                let stored = try StoredGrant(
                    reference: normalized,
                    state: .active,
                    recordedAt: self.timestamp(),
                    revokedAt: nil
                )
                snapshot.grants.append(stored)
                try touch(&snapshot, action: .recordApproval, goalID: normalized.goalID, taskID: "", subjectReceiptID: "", actor: actor)
                changed = true
            }
            return changed
        }
    }

    @discardableResult
    public func revokeGrant(grantID: String, expectedRevision: UInt64, authority: NativeAdapterAuthority) throws -> StoredGrant {
        try requireWritable()
        let actor = authority.auditLabel
        let validatedID = try IntercomID.validate(grantID, field: "GRANT_ID")
        guard let existing = snapshot.grants.first(where: { $0.reference.grantID == validatedID }) else {
            throw IntercomError.grantMismatch(grantID: validatedID)
        }
        guard existing.reference.revision == expectedRevision else {
            throw IntercomError.staleRevision(expected: expectedRevision, actual: existing.reference.revision)
        }
        if existing.state == .revoked { return existing }
        try commitIfChanged { snapshot in
            guard let index = snapshot.grants.firstIndex(where: { $0.reference.grantID == validatedID }) else {
                throw IntercomError.grantMismatch(grantID: validatedID)
            }
            // Same transaction: durable cancel evidence for each affected open attempt, then revoke.
            // Never transfers ownership or revives authorization.
            for taskIndex in snapshot.claims.indices {
                guard let openID = snapshot.claims[taskIndex].openHandoffReceiptID,
                      let offer = snapshot.handoffs.first(where: { $0.receiptID == openID }),
                      offer.fromGrantID == validatedID || offer.toGrantID == validatedID else { continue }
                try self.bumpRevision(&snapshot.claims[taskIndex].revision)
                snapshot.claims[taskIndex].status = .claimed
                snapshot.claims[taskIndex].openHandoffReceiptID = nil
                try touch(
                    &snapshot,
                    action: .cancelHandoff,
                    goalID: offer.goalID,
                    taskID: offer.taskID,
                    subjectReceiptID: offer.receiptID,
                    actor: actor
                )
            }
            snapshot.grants[index].state = .revoked
            snapshot.grants[index].revokedAt = self.timestamp()
            try touch(&snapshot, action: .revokeGrant, goalID: snapshot.grants[index].reference.goalID, taskID: "", subjectReceiptID: "", actor: actor)
            return true
        }
        guard let revoked = snapshot.grants.first(where: { $0.reference.grantID == validatedID }) else {
            throw IntercomError.grantMismatch(grantID: validatedID)
        }
        return revoked
    }

    @discardableResult
    public func transitionConnection(to next: ConnectionState, authority: NativeAdapterAuthority) throws -> ConnectionState {
        try requireWritable()
        let actor = authority.auditLabel
        if snapshot.connectionState == next { return next }
        guard Self.transitions[snapshot.connectionState, default: []].contains(next) else {
            throw IntercomError.illegalConnectionTransition(from: snapshot.connectionState, to: next)
        }
        try commitIfChanged { snapshot in
            snapshot.connectionState = next
            try touch(&snapshot, action: .connectionTransition, goalID: "", taskID: "", subjectReceiptID: "", actor: actor)
            return true
        }
        return next
    }

    @discardableResult
    public func claimTask(
        goalID: String,
        taskID: String,
        expectedRevision: UInt64,
        claimant: AgentIdentity,
        grantID: String
    ) throws -> TaskClaim {
        try requireWritable()
        let claimant = try requireAgent(claimant)
        let goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        let taskID = try IntercomID.validate(taskID, field: "TASK_ID")
        let grantID = try IntercomID.validate(grantID, field: "GRANT_ID")
        try requireReady()
        guard snapshot.goals.contains(where: { $0.goalID == goalID }) else {
            throw IntercomError.invalid("UNKNOWN_GOAL")
        }
        _ = try requireActiveGrant(snapshot, grantID: grantID, goalID: goalID, grantee: claimant, scope: .claimTask)
        if let existing = snapshot.claims.first(where: { $0.taskID == taskID }) {
            guard existing.goalID == goalID else { throw IntercomError.invalid("TASK_GOAL_MISMATCH") }
            guard existing.revision == expectedRevision else {
                throw IntercomError.staleRevision(expected: expectedRevision, actual: existing.revision)
            }
            guard existing.owner == claimant else { throw IntercomError.competingClaim(taskID: taskID) }
            return existing
        }
        guard expectedRevision == 0 else {
            throw IntercomError.staleRevision(expected: expectedRevision, actual: 0)
        }
        let claim = try TaskClaim(
            taskID: taskID,
            goalID: goalID,
            revision: 1,
            owner: claimant,
            status: .claimed,
            handoffHops: 0,
            grantID: grantID,
            openHandoffReceiptID: nil
        )
        try commitIfChanged { snapshot in
            guard snapshot.claims.count < IntercomLimits.maxClaims else {
                throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
            }
            snapshot.claims.append(claim)
            try touch(&snapshot, action: .claimTask, goalID: goalID, taskID: taskID, subjectReceiptID: "", actor: Principal.agent(claimant))
            return true
        }
        return claim
    }

    @discardableResult
    public func appendMessage(
        idempotencyKey: String,
        goalID: String,
        taskID: String,
        sender: AgentIdentity,
        recipient: AgentIdentity,
        time: String,
        evidence: MessageEvidence,
        body: String
    ) throws -> AttributedMessage {
        try requireWritable()
        let sender = try requireAgent(sender)
        let recipient = try recipient.validated()
        let goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        let taskID = try IntercomID.validate(taskID, field: "TASK_ID")
        let idempotencyKey = try IntercomID.validate(idempotencyKey, field: "IDEMPOTENCY_KEY", maximumLength: IntercomLimits.maxIdempotencyKeyLength)
        let time = try IntercomTime.validate(time)
        let evidence = try evidence.validated()
        let body = try IntercomText.validate(body, field: "BODY", maximumBytes: IntercomLimits.maxMessageBodyBytes, allowEmpty: false)
        let canonical = try IntercomCodec.encodeString(MessageWrite(
            goalID: goalID,
            taskID: taskID,
            sender: sender,
            recipient: recipient,
            time: time,
            evidence: evidence,
            body: body
        ))
        if let record = snapshot.idempotency.first(where: { $0.key == idempotencyKey }) {
            guard record.canonicalPayload == canonical,
                  let original = snapshot.messages.first(where: { $0.receiptID == record.receiptID }) else {
                throw IntercomError.idempotencyConflict(key: idempotencyKey)
            }
            return original
        }
        try requireReady()
        guard snapshot.goals.contains(where: { $0.goalID == goalID }) else {
            throw IntercomError.invalid("UNKNOWN_GOAL")
        }
        guard let task = snapshot.claims.first(where: { $0.taskID == taskID }), task.goalID == goalID else {
            throw IntercomError.invalid("UNKNOWN_TASK")
        }
        guard task.owner == sender else { throw IntercomError.invalid("NOT_TASK_OWNER") }
        _ = try requireActiveGrant(snapshot, grantID: task.grantID, goalID: goalID, grantee: sender, scope: .appendMessage)
        guard snapshot.messages.count < IntercomLimits.maxMessages else {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        var written: AttributedMessage?
        try commitIfChanged { snapshot in
            let audit = try touch(&snapshot, action: .appendMessage, goalID: goalID, taskID: taskID, subjectReceiptID: "", actor: Principal.agent(sender))
            let message = try AttributedMessage(
                goalID: goalID,
                taskID: taskID,
                sender: sender,
                recipient: recipient,
                receiptID: audit.receiptID,
                time: time,
                evidence: evidence,
                idempotencyKey: idempotencyKey,
                body: body
            )
            snapshot.messages.append(message)
            snapshot.idempotency.append(IdempotencyRecord(key: idempotencyKey, canonicalPayload: canonical, receiptID: message.receiptID))
            written = message
            return true
        }
        guard let written else { throw IntercomError.invalid("INVARIANT_MESSAGE_AUDIT") }
        return written
    }

    @discardableResult
    public func offerHandoff(
        goalID: String,
        taskID: String,
        expectedRevision: UInt64,
        fromOwner: AgentIdentity,
        toOwner: AgentIdentity,
        grantID: String
    ) throws -> HandoffReceipt {
        try requireWritable()
        let fromOwner = try requireAgent(fromOwner)
        let toOwner = try requireAgent(toOwner)
        guard fromOwner != toOwner else { throw IntercomError.invalid("HANDOFF_TO_SELF") }
        let goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        let taskID = try IntercomID.validate(taskID, field: "TASK_ID")
        let grantID = try IntercomID.validate(grantID, field: "GRANT_ID")
        guard let task = snapshot.claims.first(where: { $0.taskID == taskID }), task.goalID == goalID else {
            throw IntercomError.invalid("UNKNOWN_TASK")
        }
        guard task.revision == expectedRevision else {
            throw IntercomError.staleRevision(expected: expectedRevision, actual: task.revision)
        }
        if let openID = task.openHandoffReceiptID,
           let open = snapshot.handoffs.first(where: { $0.receiptID == openID }) {
            if open.fromOwner == fromOwner, open.toOwner == toOwner, open.fromGrantID == grantID {
                return open
            }
            throw IntercomError.invalid("HANDOFF_ALREADY_OPEN")
        }
        guard task.owner == fromOwner else { throw IntercomError.competingClaim(taskID: taskID) }
        guard task.handoffHops < IntercomLimits.maxHandoffHops else {
            throw IntercomError.handoffBoundExceeded(taskID: taskID)
        }
        try requireReady()
        _ = try requireActiveGrant(snapshot, grantID: grantID, goalID: goalID, grantee: fromOwner, scope: .handoff)
        guard task.grantID == grantID else { throw IntercomError.grantMismatch(grantID: grantID) }
        let recipientGrant = try requireGranteeGrant(snapshot, goalID: goalID, grantee: toOwner, scope: .claimTask)
        var created: HandoffReceipt?
        try commitIfChanged { snapshot in
            guard let index = snapshot.claims.firstIndex(where: { $0.taskID == taskID }) else {
                throw IntercomError.invalid("UNKNOWN_TASK")
            }
            try self.bumpRevision(&snapshot.claims[index].revision)
            let audit = try touch(&snapshot, action: .offerHandoff, goalID: goalID, taskID: taskID, subjectReceiptID: "", actor: Principal.agent(fromOwner))
            let receipt = try HandoffReceipt(
                receiptID: audit.receiptID,
                goalID: goalID,
                taskID: taskID,
                fromOwner: fromOwner,
                toOwner: toOwner,
                state: .offered,
                hop: snapshot.claims[index].handoffHops + 1,
                taskRevision: snapshot.claims[index].revision,
                time: self.timestamp(),
                fromGrantID: grantID,
                toGrantID: recipientGrant.reference.grantID
            )
            guard snapshot.handoffs.count < IntercomLimits.maxHandoffs else {
                throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
            }
            snapshot.handoffs.append(receipt)
            snapshot.claims[index].status = .handoffPending
            snapshot.claims[index].openHandoffReceiptID = receipt.receiptID
            created = receipt
            return true
        }
        guard let created else { throw IntercomError.invalid("INVARIANT_OPEN_HANDOFF") }
        return created
    }

    @discardableResult
    public func acknowledgeHandoff(
        receiptID: String,
        expectedOwner: AgentIdentity,
        actor: AgentIdentity
    ) throws -> HandoffState {
        try transitionHandoff(receiptID: receiptID, expectedOwner: expectedOwner, actor: actor, completing: false)
    }

    @discardableResult
    public func completeHandoff(
        receiptID: String,
        expectedOwner: AgentIdentity,
        actor: AgentIdentity
    ) throws -> HandoffState {
        try transitionHandoff(receiptID: receiptID, expectedOwner: expectedOwner, actor: actor, completing: true)
    }

    /// Cancel an uncompleted handoff **attempt** (`receiptID`). Does not transfer ownership,
    /// revive grants, or change scopes. Idempotent if already cancelled/revoked.
    /// `claim.handoffHops` is unchanged so a later offer may target the same hop slot.
    @discardableResult
    public func cancelHandoff(
        receiptID: String,
        expectedRevision: UInt64,
        actor: AgentIdentity
    ) throws -> HandoffState {
        try requireWritable()
        let actor = try requireAgent(actor)
        let receiptID = try IntercomID.validate(receiptID, field: "RECEIPT_ID")
        guard let receipt = snapshot.handoffs.first(where: { $0.receiptID == receiptID }) else {
            throw IntercomError.invalid("UNKNOWN_HANDOFF")
        }
        guard receipt.state == .offered else { throw IntercomError.invalid("HANDOFF_MUST_BE_OFFER_RECORD") }
        let current = try snapshot.derivedHandoffState(for: receiptID)
        if current == .revoked { return .revoked }
        if current == .completed {
            throw IntercomError.handoffNotReady(receiptID: receiptID)
        }
        guard current == .offered || current == .acknowledged else {
            throw IntercomError.handoffNotReady(receiptID: receiptID)
        }
        guard actor == receipt.fromOwner else {
            throw IntercomError.wrongHandoffOwner(expected: actor.identifier, actual: receipt.fromOwner.identifier)
        }
        guard let task = snapshot.claims.first(where: { $0.taskID == receipt.taskID }),
              task.goalID == receipt.goalID else {
            throw IntercomError.invalid("UNKNOWN_TASK")
        }
        guard task.revision == expectedRevision else {
            throw IntercomError.staleRevision(expected: expectedRevision, actual: task.revision)
        }
        guard task.openHandoffReceiptID == receipt.receiptID, task.owner == receipt.fromOwner else {
            throw IntercomError.invalid("INVARIANT_OPEN_HANDOFF")
        }
        try requireReady()
        _ = try requireActiveGrant(
            snapshot,
            grantID: receipt.fromGrantID,
            goalID: receipt.goalID,
            grantee: receipt.fromOwner,
            scope: .handoff
        )
        try commitIfChanged { snapshot in
            guard let taskIndex = snapshot.claims.firstIndex(where: { $0.taskID == receipt.taskID }) else {
                throw IntercomError.invalid("UNKNOWN_TASK")
            }
            try self.bumpRevision(&snapshot.claims[taskIndex].revision)
            snapshot.claims[taskIndex].status = .claimed
            snapshot.claims[taskIndex].openHandoffReceiptID = nil
            // Ownership and grantID unchanged — cancel is not a transfer.
            try touch(
                &snapshot,
                action: .cancelHandoff,
                goalID: receipt.goalID,
                taskID: receipt.taskID,
                subjectReceiptID: receipt.receiptID,
                actor: Principal.agent(actor)
            )
            return true
        }
        return try snapshot.derivedHandoffState(for: receiptID)
    }

    private func transitionHandoff(
        receiptID: String,
        expectedOwner: AgentIdentity,
        actor: AgentIdentity,
        completing: Bool
    ) throws -> HandoffState {
        try requireWritable()
        let actor = try requireAgent(actor)
        let expectedOwner = try requireAgent(expectedOwner)
        let receiptID = try IntercomID.validate(receiptID, field: "RECEIPT_ID")
        guard let receipt = snapshot.handoffs.first(where: { $0.receiptID == receiptID }) else {
            throw IntercomError.invalid("UNKNOWN_HANDOFF")
        }
        // Original offer record stays immutable in storage.
        guard receipt.state == .offered else { throw IntercomError.invalid("HANDOFF_MUST_BE_OFFER_RECORD") }
        guard expectedOwner == receipt.fromOwner else {
            throw IntercomError.wrongHandoffOwner(expected: expectedOwner.identifier, actual: receipt.fromOwner.identifier)
        }
        guard actor == receipt.toOwner else {
            throw IntercomError.wrongHandoffOwner(expected: actor.identifier, actual: receipt.toOwner.identifier)
        }
        let current = try snapshot.derivedHandoffState(for: receiptID)
        if current == .revoked { throw IntercomError.grantRevoked(grantID: receipt.fromGrantID) }
        if completing {
            if current == .completed { return .completed }
            guard current == .acknowledged else { throw IntercomError.handoffNotReady(receiptID: receiptID) }
        } else {
            if current == .acknowledged { return .acknowledged }
            guard current == .offered else { throw IntercomError.handoffNotReady(receiptID: receiptID) }
        }
        try requireReady()
        _ = try requireActiveGrant(snapshot, grantID: receipt.fromGrantID, goalID: receipt.goalID, grantee: receipt.fromOwner, scope: .handoff)
        _ = try requireActiveGrant(snapshot, grantID: receipt.toGrantID, goalID: receipt.goalID, grantee: receipt.toOwner, scope: .claimTask)
        guard let task = snapshot.claims.first(where: { $0.taskID == receipt.taskID }),
              task.goalID == receipt.goalID,
              task.openHandoffReceiptID == receipt.receiptID,
              task.owner == receipt.fromOwner else {
            throw IntercomError.invalid("INVARIANT_OPEN_HANDOFF")
        }
        try commitIfChanged { snapshot in
            guard let taskIndex = snapshot.claims.firstIndex(where: { $0.taskID == receipt.taskID }),
                  snapshot.handoffs.contains(where: { $0.receiptID == receiptID }) else {
                throw IntercomError.invalid("UNKNOWN_HANDOFF")
            }
            // Never mutate the stored offer receipt; append transition audit only.
            if completing {
                guard snapshot.claims[taskIndex].handoffHops < IntercomLimits.maxHandoffHops else {
                    throw IntercomError.handoffBoundExceeded(taskID: receipt.taskID)
                }
                try self.bumpRevision(&snapshot.claims[taskIndex].revision)
                snapshot.claims[taskIndex].owner = receipt.toOwner
                snapshot.claims[taskIndex].grantID = receipt.toGrantID
                snapshot.claims[taskIndex].handoffHops += 1
                snapshot.claims[taskIndex].status = .claimed
                snapshot.claims[taskIndex].openHandoffReceiptID = nil
                try touch(
                    &snapshot,
                    action: .completeHandoff,
                    goalID: receipt.goalID,
                    taskID: receipt.taskID,
                    subjectReceiptID: receipt.receiptID,
                    actor: Principal.agent(actor)
                )
            } else {
                try self.bumpRevision(&snapshot.claims[taskIndex].revision)
                try touch(
                    &snapshot,
                    action: .acknowledgeHandoff,
                    goalID: receipt.goalID,
                    taskID: receipt.taskID,
                    subjectReceiptID: receipt.receiptID,
                    actor: Principal.agent(actor)
                )
            }
            return true
        }
        return try snapshot.derivedHandoffState(for: receiptID)
    }

    private static let transitions: [ConnectionState: Set<ConnectionState>] = [
        .offline: [.reconnecting],
        .reconnecting: [.ready, .unavailable, .offline],
        .ready: [.offline, .unavailable],
        .unavailable: [.reconnecting, .offline]
    ]

    private func requireWritable() throws {
        if let blocked = blockedReconcile {
            throw IntercomError.committedUnknown(
                publishedRevision: blocked.publishedRevision,
                detail: "RECONCILE_REQUIRED:\(blocked.detail)"
            )
        }
    }

    private func performReconcile() throws {
        guard let blocked = blockedReconcile else {
            if let loaded = try persistence.load() {
                try loaded.validate()
                snapshot = loaded
            }
            return
        }
        do {
            guard let loaded = try persistence.load() else {
                throw IntercomError.committedUnknown(
                    publishedRevision: blocked.publishedRevision,
                    detail: "RECONCILE_EMPTY:\(blocked.detail)"
                )
            }
            try loaded.validate()
            snapshot = loaded
            blockedReconcile = nil
        } catch let error as IntercomError {
            if case .committedUnknown = error { throw error }
            throw IntercomError.committedUnknown(
                publishedRevision: blocked.publishedRevision,
                detail: "RECONCILE_LOAD_FAILED:\(blocked.detail)"
            )
        } catch {
            throw IntercomError.committedUnknown(
                publishedRevision: blocked.publishedRevision,
                detail: "RECONCILE_LOAD_FAILED:\(blocked.detail)"
            )
        }
    }

    private func requireAgent(_ identity: AgentIdentity) throws -> AgentIdentity {
        guard identity.kind == .agent else { throw IntercomError.forbiddenEscalation }
        return try identity.validated()
    }

    private func requireReady() throws {
        guard snapshot.connectionState == .ready else {
            throw IntercomError.connectionNotReady(snapshot.connectionState)
        }
    }

    private func requireActiveGrant(
        _ snapshot: IntercomSnapshot,
        grantID: String,
        goalID: String,
        grantee: AgentIdentity,
        scope: GrantScope
    ) throws -> StoredGrant {
        guard let grant = snapshot.grants.first(where: { $0.reference.grantID == grantID }) else {
            throw IntercomError.grantMismatch(grantID: grantID)
        }
        guard grant.state == .active else { throw IntercomError.grantRevoked(grantID: grantID) }
        guard grant.reference.goalID == goalID,
              grant.reference.grantee == grantee,
              grant.reference.scopes.contains(scope) else {
            throw IntercomError.grantMismatch(grantID: grantID)
        }
        return grant
    }

    private func requireGranteeGrant(
        _ snapshot: IntercomSnapshot,
        goalID: String,
        grantee: AgentIdentity,
        scope: GrantScope
    ) throws -> StoredGrant {
        let matches = snapshot.grants.filter {
            $0.state == .active
                && $0.reference.goalID == goalID
                && $0.reference.grantee == grantee
                && $0.reference.scopes.contains(scope)
        }
        guard matches.count == 1, let grant = matches.first else {
            throw IntercomError.grantMismatch(grantID: grantee.identifier)
        }
        return grant
    }

    private func timestamp() -> String {
        IntercomTime.format(clock.now())
    }

    private func bumpRevision(_ revision: inout UInt64) throws {
        guard revision < UInt64.max else { throw IntercomError.persistence("REVISION_EXHAUSTED") }
        revision += 1
    }

    @discardableResult
    private func touch(
        _ snapshot: inout IntercomSnapshot,
        action: AuditAction,
        goalID: String,
        taskID: String,
        subjectReceiptID: String,
        actor: Principal
    ) throws -> AuditReceipt {
        guard snapshot.audits.count < IntercomLimits.maxAudits else {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        guard snapshot.snapshotRevision < UInt64.max, snapshot.auditSequence < UInt64.max else {
            throw IntercomError.persistence("REVISION_EXHAUSTED")
        }
        snapshot.snapshotRevision += 1
        snapshot.auditSequence += 1
        let receipt = try AuditReceipt(
            receiptID: "receipt-\(snapshot.auditSequence)",
            action: action,
            goalID: goalID,
            taskID: taskID,
            subjectReceiptID: subjectReceiptID,
            actor: actor,
            time: timestamp(),
            snapshotRevision: snapshot.snapshotRevision
        )
        snapshot.audits.append(receipt)
        return receipt
    }

    private func commitIfChanged(_ body: (inout IntercomSnapshot) throws -> Bool) throws {
        try requireWritable()
        let base = snapshot.snapshotRevision
        var working = snapshot
        let changed = try body(&working)
        guard changed else { return }
        try working.validate()
        try Self.applyCommit(
            persistence: persistence,
            working: working,
            expectedBaseRevision: base,
            snapshot: &snapshot,
            blockedReconcile: &blockedReconcile
        )
    }

    /// Shared by `commitIfChanged` and init demotion: no fake rollback after publish.
    private static func applyCommit(
        persistence: any IntercomPersistence,
        working: IntercomSnapshot,
        expectedBaseRevision: UInt64,
        snapshot: inout IntercomSnapshot,
        blockedReconcile: inout (publishedRevision: UInt64, detail: String)?
    ) throws {
        do {
            try persistence.commit(working, expectedBaseRevision: expectedBaseRevision)
            snapshot = working
            blockedReconcile = nil
        } catch IntercomError.notCommitted(let detail) {
            // Disk unchanged — keep prior memory; safe to retry same base.
            throw IntercomError.notCommitted(detail)
        } catch IntercomError.committedUnknown(let publishedRevision, let detail) {
            // Publish may have advanced. Reconcile memory from load before any retry.
            do {
                guard let loaded = try persistence.load() else {
                    blockedReconcile = (publishedRevision, detail)
                    throw IntercomError.committedUnknown(
                        publishedRevision: publishedRevision,
                        detail: "RECONCILE_EMPTY:\(detail)"
                    )
                }
                try loaded.validate()
                snapshot = loaded
                blockedReconcile = nil
                throw IntercomError.committedUnknown(
                    publishedRevision: loaded.snapshotRevision,
                    detail: detail
                )
            } catch let error as IntercomError {
                if case .committedUnknown = error {
                    throw error
                }
                blockedReconcile = (publishedRevision, detail)
                // Memory left at pre-commit while disk may be advanced — retry blocked.
                throw IntercomError.committedUnknown(
                    publishedRevision: publishedRevision,
                    detail: "RECONCILE_LOAD_FAILED:\(detail)"
                )
            } catch {
                blockedReconcile = (publishedRevision, detail)
                throw IntercomError.committedUnknown(
                    publishedRevision: publishedRevision,
                    detail: "RECONCILE_LOAD_FAILED:\(detail)"
                )
            }
        } catch {
            throw error
        }
    }
}
