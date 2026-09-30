import Foundation

/// Bounds for the schema-v1 journal. The native adapter cannot raise these from inside an agent call.
public enum IntercomLimits {
    public static let maxHandoffHops = 8
    public static let maxSnapshotBytes = 1_048_576
    public static let maxMessageBodyBytes = 16_384
    public static let maxEvidenceNoteBytes = 2_048
    public static let maxGoalStatementBytes = 4_096
    public static let maxMessages = 2_000
    public static let maxHandoffs = 2_000
    public static let maxAudits = 8_000
    public static let maxGrants = 500
    public static let maxGoals = 500
    public static let maxClaims = 2_000
    public static let maxIdentifierLength = 128
    public static let maxIdempotencyKeyLength = 200
}

public enum IntercomError: Error, Equatable, Sendable {
    case invalid(String)
    case staleRevision(expected: UInt64, actual: UInt64)
    case competingClaim(taskID: String)
    case wrongHandoffOwner(expected: String, actual: String)
    case forbiddenEscalation
    case grantRevoked(grantID: String)
    case grantMismatch(grantID: String)
    case idempotencyConflict(key: String)
    case connectionNotReady(ConnectionState)
    case illegalConnectionTransition(from: ConnectionState, to: ConnectionState)
    case handoffBoundExceeded(taskID: String)
    case handoffNotReady(receiptID: String)
    case unsupportedSchema(Int)
    case persistence(String)
    /// Failed before durable publish; on-disk base is unchanged.
    case notCommitted(String)
    /// Durable publish may have advanced; memory must reconcile from load before retry. Not a rollback.
    case committedUnknown(publishedRevision: UInt64, detail: String)

    public var code: String {
        switch self {
        case .invalid(let value): return value
        case .staleRevision: return "STALE_REVISION"
        case .competingClaim: return "COMPETING_CLAIM"
        case .wrongHandoffOwner: return "WRONG_HANDOFF_OWNER"
        case .forbiddenEscalation: return "FORBIDDEN_ESCALATION"
        case .grantRevoked: return "GRANT_REVOKED"
        case .grantMismatch: return "GRANT_MISMATCH"
        case .idempotencyConflict: return "IDEMPOTENCY_CONFLICT"
        case .connectionNotReady: return "CONNECTION_NOT_READY"
        case .illegalConnectionTransition: return "ILLEGAL_CONNECTION_TRANSITION"
        case .handoffBoundExceeded: return "HANDOFF_BOUND_EXCEEDED"
        case .handoffNotReady: return "HANDOFF_NOT_READY"
        case .unsupportedSchema: return "UNSUPPORTED_SCHEMA"
        case .persistence(let value): return value
        case .notCommitted(let value): return "NOT_COMMITTED:\(value)"
        case .committedUnknown: return "COMMITTED_UNKNOWN"
        }
    }
}

/// Local journal availability. `ready` means the adapter completed an explicit reconnect.
/// It is not a network session and not a live dot, Muse, or provider connection.
public enum ConnectionState: String, Codable, Sendable, CaseIterable, Equatable {
    case offline
    case reconnecting
    case unavailable
    case ready
}

public enum GrantScope: String, Codable, Sendable, Equatable, Hashable, CaseIterable {
    case claimTask
    case appendMessage
    case handoff
}

public enum GrantState: String, Codable, Sendable, Equatable {
    case active
    case revoked
}

public enum GoalStatus: String, Codable, Sendable, Equatable {
    case open
}

public enum TaskStatus: String, Codable, Sendable, Equatable {
    case claimed
    case handoffPending
}

public enum HandoffState: String, Codable, Sendable, Equatable {
    case offered
    case acknowledged
    case completed
    case revoked
}

public enum AuditAction: String, Codable, Sendable, Equatable {
    case recordGoal
    case recordApproval
    case revokeGrant
    case connectionTransition
    case claimTask
    case appendMessage
    case offerHandoff
    case acknowledgeHandoff
    case completeHandoff
    /// Durable cancel of an uncompleted handoff attempt (receiptID is the attempt id).
    case cancelHandoff
}

public struct AgentIdentity: Codable, Sendable, Equatable, Hashable {
    public enum Kind: String, Codable, Sendable, Equatable, Hashable {
        case agent
        case user
    }

    public let kind: Kind
    public let identifier: String

    public init(kind: Kind, identifier: String) throws {
        self.kind = kind
        self.identifier = try IntercomID.validate(identifier, field: "IDENTITY")
    }

    public static func agent(_ identifier: String) throws -> AgentIdentity {
        try AgentIdentity(kind: .agent, identifier: identifier)
    }

    public static func user(_ identifier: String) throws -> AgentIdentity {
        try AgentIdentity(kind: .user, identifier: identifier)
    }

    public func validated() throws -> AgentIdentity {
        try AgentIdentity(kind: kind, identifier: identifier)
    }
}

/// Codable actor label only. Decoding `nativeAdapter` does **not** authenticate the caller.
/// Privileged engine APIs do **not** accept `Principal`; they require non-Codable
/// `NativeAdapterAuthority` minted in-process by the native adapter after its own auth checks.
/// Agent-supplied JSON that claims `role: nativeAdapter` or a human label is never consent.
public enum Principal: Sendable, Equatable {
    case nativeAdapter(String)
    case agent(AgentIdentity)

    /// Audit/storage label only — not a capability token.
    public static func auditNativeAdapter(_ identifier: String) throws -> Principal {
        .nativeAdapter(try IntercomID.validate(identifier, field: "INSTALLATION_ID"))
    }

    public static func verifiedAgent(_ identity: AgentIdentity) throws -> Principal {
        guard identity.kind == .agent else { throw IntercomError.forbiddenEscalation }
        return .agent(try identity.validated())
    }
}

/// In-process capability handle for privileged journal mutations.
/// **Not Codable** and cannot be reconstructed from decoded agent JSON.
/// Constructing this value does **not** by itself authenticate a user or prove SandboxStore
/// session checks; only the native adapter may mint it after those checks (integration gap:
/// unproven in this package — see README/HANDOFF).
public struct NativeAdapterAuthority: Sendable, Equatable {
    public let installationID: String

    public init(installationID: String) throws {
        self.installationID = try IntercomID.validate(installationID, field: "INSTALLATION_ID")
    }

    /// Label written into audit receipts. Never treat this label as re-entry authentication.
    public var auditLabel: Principal { .nativeAdapter(installationID) }
}

extension Principal: Codable {
    private enum CodingKeys: String, CodingKey {
        case role
        case identifier
        case identity
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .role) {
        case "nativeAdapter":
            self = .nativeAdapter(try IntercomID.validate(container.decode(String.self, forKey: .identifier), field: "INSTALLATION_ID"))
        case "agent":
            let identity = try container.decode(AgentIdentity.self, forKey: .identity)
            guard identity.kind == .agent else {
                throw DecodingError.dataCorruptedError(forKey: .identity, in: container, debugDescription: "FORBIDDEN_ESCALATION")
            }
            self = .agent(try identity.validated())
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .role,
                in: container,
                debugDescription: "UNKNOWN_PRINCIPAL"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .nativeAdapter(let identifier):
            try container.encode("nativeAdapter", forKey: .role)
            try container.encode(identifier, forKey: .identifier)
        case .agent(let identity):
            try container.encode("agent", forKey: .role)
            try container.encode(identity, forKey: .identity)
        }
    }
}

/// Authoritative user approval supplied by the native adapter. Constructing this value does not create consent.
public struct UserApprovalReference: Codable, Sendable, Equatable, Hashable {
    public let grantID: String
    public let goalID: String
    public let user: AgentIdentity
    public let grantee: AgentIdentity
    public let scopes: [GrantScope]
    public let revision: UInt64

    public init(
        grantID: String,
        goalID: String,
        user: AgentIdentity,
        grantee: AgentIdentity,
        scopes: [GrantScope],
        revision: UInt64
    ) throws {
        guard user.kind == .user, grantee.kind == .agent else {
            throw IntercomError.forbiddenEscalation
        }
        self.grantID = try IntercomID.validate(grantID, field: "GRANT_ID")
        self.goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        self.user = try user.validated()
        self.grantee = try grantee.validated()
        let normalized = Array(Set(scopes)).sorted { $0.rawValue < $1.rawValue }
        guard !normalized.isEmpty else { throw IntercomError.invalid("EMPTY_GRANT_SCOPES") }
        guard revision >= 1 else { throw IntercomError.invalid("INVALID_GRANT_REVISION") }
        self.scopes = normalized
        self.revision = revision
    }
}

public struct StoredGrant: Codable, Sendable, Equatable {
    public let reference: UserApprovalReference
    public internal(set) var state: GrantState
    public let recordedAt: String
    public internal(set) var revokedAt: String?

    public init(reference: UserApprovalReference, state: GrantState, recordedAt: String, revokedAt: String?) throws {
        // Reconstruct the full approval contract on every restore path.
        self.reference = try UserApprovalReference(
            grantID: reference.grantID,
            goalID: reference.goalID,
            user: reference.user,
            grantee: reference.grantee,
            scopes: reference.scopes,
            revision: reference.revision
        )
        self.state = state
        self.recordedAt = try IntercomTime.validate(recordedAt)
        if let revokedAt {
            self.revokedAt = try IntercomTime.validate(revokedAt)
        } else {
            self.revokedAt = nil
        }
        if state == .active {
            guard self.revokedAt == nil else { throw IntercomError.invalid("INVARIANT_GRANT_STATE") }
        } else {
            guard self.revokedAt != nil else { throw IntercomError.invalid("INVARIANT_GRANT_STATE") }
        }
    }
}

public struct GoalRecord: Codable, Sendable, Equatable {
    public let goalID: String
    public let revision: UInt64
    public let statement: String
    public let owner: AgentIdentity
    public let status: GoalStatus

    public init(goalID: String, revision: UInt64, statement: String, owner: AgentIdentity, status: GoalStatus) throws {
        guard owner.kind == .user else { throw IntercomError.forbiddenEscalation }
        guard revision >= 1 else { throw IntercomError.invalid("INVALID_GOAL_REVISION") }
        self.goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        self.revision = revision
        self.statement = try IntercomText.validate(statement, field: "STATEMENT", maximumBytes: IntercomLimits.maxGoalStatementBytes, allowEmpty: false)
        self.owner = try owner.validated()
        self.status = status
    }
}

public struct TaskClaim: Codable, Sendable, Equatable {
    public let taskID: String
    public let goalID: String
    public internal(set) var revision: UInt64
    public internal(set) var owner: AgentIdentity
    public internal(set) var status: TaskStatus
    public internal(set) var handoffHops: Int
    public internal(set) var grantID: String
    public internal(set) var openHandoffReceiptID: String?

    public init(
        taskID: String,
        goalID: String,
        revision: UInt64,
        owner: AgentIdentity,
        status: TaskStatus,
        handoffHops: Int,
        grantID: String,
        openHandoffReceiptID: String?
    ) throws {
        guard owner.kind == .agent else { throw IntercomError.forbiddenEscalation }
        guard revision >= 1 else { throw IntercomError.invalid("INVALID_TASK_REVISION") }
        guard (0...IntercomLimits.maxHandoffHops).contains(handoffHops) else {
            throw IntercomError.handoffBoundExceeded(taskID: taskID)
        }
        self.taskID = try IntercomID.validate(taskID, field: "TASK_ID")
        self.goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        self.revision = revision
        self.owner = try owner.validated()
        self.status = status
        self.handoffHops = handoffHops
        self.grantID = try IntercomID.validate(grantID, field: "GRANT_ID")
        if let openHandoffReceiptID {
            self.openHandoffReceiptID = try IntercomID.validate(openHandoffReceiptID, field: "RECEIPT_ID")
        } else {
            self.openHandoffReceiptID = nil
        }
    }
}

public struct MessageEvidence: Codable, Sendable, Equatable, Hashable {
    public let kind: String
    public let digest: String
    public let byteCount: Int
    public let note: String

    public init(kind: String, digest: String, byteCount: Int, note: String) throws {
        self.kind = try IntercomID.validate(kind, field: "EVIDENCE_KIND")
        guard digest.count == 64, digest.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw IntercomError.invalid("INVALID_EVIDENCE")
        }
        guard (0...10_000_000).contains(byteCount) else { throw IntercomError.invalid("INVALID_EVIDENCE") }
        self.digest = digest
        self.byteCount = byteCount
        self.note = try IntercomText.validate(note, field: "EVIDENCE_NOTE", maximumBytes: IntercomLimits.maxEvidenceNoteBytes, allowEmpty: true)
    }

    public func validated() throws -> MessageEvidence {
        try MessageEvidence(kind: kind, digest: digest, byteCount: byteCount, note: note)
    }
}

public struct AttributedMessage: Codable, Sendable, Equatable {
    public let goalID: String
    public let taskID: String
    public let sender: AgentIdentity
    public let recipient: AgentIdentity
    public let receiptID: String
    public let time: String
    public let evidence: MessageEvidence
    public let idempotencyKey: String
    public let body: String

    public init(
        goalID: String,
        taskID: String,
        sender: AgentIdentity,
        recipient: AgentIdentity,
        receiptID: String,
        time: String,
        evidence: MessageEvidence,
        idempotencyKey: String,
        body: String
    ) throws {
        guard sender.kind == .agent else { throw IntercomError.forbiddenEscalation }
        self.goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        self.taskID = try IntercomID.validate(taskID, field: "TASK_ID")
        self.sender = try sender.validated()
        self.recipient = try recipient.validated()
        self.receiptID = try IntercomID.validate(receiptID, field: "RECEIPT_ID")
        self.time = try IntercomTime.validate(time)
        self.evidence = try evidence.validated()
        self.idempotencyKey = try IntercomID.validate(idempotencyKey, field: "IDEMPOTENCY_KEY", maximumLength: IntercomLimits.maxIdempotencyKeyLength)
        self.body = try IntercomText.validate(body, field: "BODY", maximumBytes: IntercomLimits.maxMessageBodyBytes, allowEmpty: false)
    }
}

/// Immutable offer authority. Lifecycle after offer is derived from append-only transition audits.
///
/// **Attempt identity:** `receiptID` is the unique handoff **attempt** identifier (never reused).
/// **`hop`:** the completed-hop index this attempt would occupy if it completes (`claim.handoffHops + 1`
/// at offer time). Cancelled/revoked attempts do **not** increment `claim.handoffHops`; a later
/// attempt may reuse the same hop number. Completed hops alone define ownership transfer count.
public struct HandoffReceipt: Codable, Sendable, Equatable {
    public let receiptID: String
    public let goalID: String
    public let taskID: String
    public let fromOwner: AgentIdentity
    public let toOwner: AgentIdentity
    /// Always `.offered` in durable storage. Never rewritten after commit.
    public let state: HandoffState
    public let hop: Int
    public let taskRevision: UInt64
    public let time: String
    public let fromGrantID: String
    public let toGrantID: String

    public init(
        receiptID: String,
        goalID: String,
        taskID: String,
        fromOwner: AgentIdentity,
        toOwner: AgentIdentity,
        state: HandoffState,
        hop: Int,
        taskRevision: UInt64,
        time: String,
        fromGrantID: String,
        toGrantID: String
    ) throws {
        guard fromOwner.kind == .agent, toOwner.kind == .agent else { throw IntercomError.forbiddenEscalation }
        guard fromOwner != toOwner else { throw IntercomError.invalid("HANDOFF_TO_SELF") }
        guard state == .offered else { throw IntercomError.invalid("HANDOFF_MUST_BE_OFFER_RECORD") }
        guard taskRevision >= 1 else { throw IntercomError.invalid("INVALID_HANDOFF_TASK_REVISION") }
        guard (1...IntercomLimits.maxHandoffHops).contains(hop) else {
            throw IntercomError.handoffBoundExceeded(taskID: taskID)
        }
        self.receiptID = try IntercomID.validate(receiptID, field: "RECEIPT_ID")
        self.goalID = try IntercomID.validate(goalID, field: "GOAL_ID")
        self.taskID = try IntercomID.validate(taskID, field: "TASK_ID")
        self.fromOwner = try fromOwner.validated()
        self.toOwner = try toOwner.validated()
        self.state = state
        self.hop = hop
        self.taskRevision = taskRevision
        self.time = try IntercomTime.validate(time)
        self.fromGrantID = try IntercomID.validate(fromGrantID, field: "GRANT_ID")
        self.toGrantID = try IntercomID.validate(toGrantID, field: "GRANT_ID")
    }
}

public struct AuditReceipt: Codable, Sendable, Equatable {
    public let receiptID: String
    public let action: AuditAction
    public let goalID: String
    public let taskID: String
    /// For handoff transition audits, the immutable offer `HandoffReceipt.receiptID`. Empty otherwise.
    public let subjectReceiptID: String
    public let actor: Principal
    public let time: String
    public let snapshotRevision: UInt64

    public init(
        receiptID: String,
        action: AuditAction,
        goalID: String,
        taskID: String,
        subjectReceiptID: String = "",
        actor: Principal,
        time: String,
        snapshotRevision: UInt64
    ) throws {
        self.receiptID = try IntercomID.validate(receiptID, field: "RECEIPT_ID")
        self.action = action
        self.goalID = try goalID.isEmpty ? "" : IntercomID.validate(goalID, field: "GOAL_ID")
        self.taskID = try taskID.isEmpty ? "" : IntercomID.validate(taskID, field: "TASK_ID")
        self.subjectReceiptID = try subjectReceiptID.isEmpty
            ? ""
            : IntercomID.validate(subjectReceiptID, field: "SUBJECT_RECEIPT_ID")
        switch actor {
        case .nativeAdapter(let identifier):
            self.actor = try Principal.auditNativeAdapter(identifier)
        case .agent(let identity):
            self.actor = try Principal.verifiedAgent(identity)
        }
        self.time = try IntercomTime.validate(time)
        guard snapshotRevision >= 1 else { throw IntercomError.invalid("INVALID_SNAPSHOT_REVISION") }
        self.snapshotRevision = snapshotRevision
    }
}

struct IdempotencyRecord: Codable, Sendable, Equatable {
    let key: String
    let canonicalPayload: String
    let receiptID: String
}

struct MessageWrite: Codable, Equatable {
    var goalID: String
    var taskID: String
    var sender: AgentIdentity
    var recipient: AgentIdentity
    var time: String
    var evidence: MessageEvidence
    var body: String
}

public struct IntercomClock: Sendable {
    public var now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date) {
        self.now = now
    }

    public static let system = IntercomClock { Date() }
}

public struct IntercomSnapshot: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1
    public static let currentRecordType = "intercom-domain-snapshot"

    public let schemaVersion: Int
    public let recordType: String
    public internal(set) var goals: [GoalRecord]
    public internal(set) var claims: [TaskClaim]
    public internal(set) var messages: [AttributedMessage]
    public internal(set) var handoffs: [HandoffReceipt]
    public internal(set) var grants: [StoredGrant]
    public internal(set) var audits: [AuditReceipt]
    var idempotency: [IdempotencyRecord]
    public internal(set) var connectionState: ConnectionState
    public internal(set) var auditSequence: UInt64
    public internal(set) var snapshotRevision: UInt64

    public static let empty = IntercomSnapshot(
        schemaVersion: currentSchemaVersion,
        recordType: currentRecordType,
        goals: [],
        claims: [],
        messages: [],
        handoffs: [],
        grants: [],
        audits: [],
        idempotency: [],
        connectionState: .offline,
        auditSequence: 0,
        snapshotRevision: 0
    )

    public func derivedHandoffState(for receiptID: String) throws -> HandoffState {
        guard let offer = handoffs.first(where: { $0.receiptID == receiptID }) else {
            throw IntercomError.invalid("UNKNOWN_HANDOFF")
        }
        let transitions = audits.filter {
            ($0.action == .acknowledgeHandoff || $0.action == .completeHandoff || $0.action == .cancelHandoff)
                && $0.subjectReceiptID == receiptID
        }.sorted { $0.snapshotRevision < $1.snapshotRevision }
        if transitions.contains(where: { $0.action == .completeHandoff }) {
            return .completed
        }
        // Explicit cancel evidence closes the attempt without ownership transfer.
        if transitions.contains(where: { $0.action == .cancelHandoff }) {
            return .revoked
        }
        let fromRevoked = grants.first(where: { $0.reference.grantID == offer.fromGrantID })?.state == .revoked
        let toRevoked = grants.first(where: { $0.reference.grantID == offer.toGrantID })?.state == .revoked
        if fromRevoked || toRevoked {
            return .revoked
        }
        if transitions.contains(where: { $0.action == .acknowledgeHandoff }) {
            return .acknowledged
        }
        return .offered
    }

    public static func decodeValidated(from data: Data) throws -> IntercomSnapshot {
        try IntercomCodec.decodeSnapshot(data)
    }

    public func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw IntercomError.unsupportedSchema(schemaVersion)
        }
        guard recordType == Self.currentRecordType else {
            throw IntercomError.invalid("WRONG_RECORD_TYPE")
        }
        guard goals.count <= IntercomLimits.maxGoals,
              claims.count <= IntercomLimits.maxClaims,
              messages.count <= IntercomLimits.maxMessages,
              handoffs.count <= IntercomLimits.maxHandoffs,
              grants.count <= IntercomLimits.maxGrants,
              audits.count <= IntercomLimits.maxAudits else {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        try requireUnique(goals.map(\.goalID), "GOAL")
        try requireUnique(claims.map(\.taskID), "TASK")
        try requireUnique(messages.map(\.receiptID), "MESSAGE")
        try requireUnique(messages.map(\.idempotencyKey), "IDEMPOTENCY_KEY")
        try requireUnique(handoffs.map(\.receiptID), "HANDOFF")
        try requireUnique(grants.map(\.reference.grantID), "GRANT")
        try requireUnique(audits.map(\.receiptID), "AUDIT")
        guard auditSequence == UInt64(audits.count) else {
            throw IntercomError.invalid("INVARIANT_AUDIT_SEQUENCE")
        }

        var previousAuditRevision: UInt64 = 0
        for (offset, audit) in audits.enumerated() {
            guard audit.receiptID == "receipt-\(offset + 1)" else {
                throw IntercomError.invalid("INVARIANT_RECEIPT_ID")
            }
            guard audit.snapshotRevision > previousAuditRevision, audit.snapshotRevision <= snapshotRevision else {
                throw IntercomError.invalid("INVARIANT_AUDIT_REVISION")
            }
            previousAuditRevision = audit.snapshotRevision
            _ = try AuditReceipt(
                receiptID: audit.receiptID,
                action: audit.action,
                goalID: audit.goalID,
                taskID: audit.taskID,
                subjectReceiptID: audit.subjectReceiptID,
                actor: audit.actor,
                time: audit.time,
                snapshotRevision: audit.snapshotRevision
            )
            if !audit.goalID.isEmpty {
                guard goals.contains(where: { $0.goalID == audit.goalID }) else {
                    throw IntercomError.invalid("INVARIANT_AUDIT_GOAL")
                }
            }
            if !audit.taskID.isEmpty {
                guard let claim = claims.first(where: { $0.taskID == audit.taskID }),
                      claim.goalID == audit.goalID else {
                    throw IntercomError.invalid("INVARIANT_AUDIT_TASK")
                }
            }
            switch audit.action {
            case .offerHandoff, .acknowledgeHandoff, .completeHandoff, .appendMessage, .claimTask:
                guard case .agent = audit.actor else {
                    throw IntercomError.invalid("INVARIANT_AUDIT_ACTOR")
                }
            case .cancelHandoff:
                // Owner cancel (agent) or same-transaction grant revoke (native adapter).
                break
            case .recordGoal, .recordApproval, .revokeGrant, .connectionTransition:
                guard case .nativeAdapter = audit.actor else {
                    throw IntercomError.invalid("INVARIANT_AUDIT_ACTOR")
                }
            }
            if audit.action == .acknowledgeHandoff || audit.action == .completeHandoff || audit.action == .cancelHandoff {
                guard !audit.subjectReceiptID.isEmpty,
                      handoffs.contains(where: { $0.receiptID == audit.subjectReceiptID }) else {
                    throw IntercomError.invalid("INVARIANT_AUDIT_SUBJECT")
                }
            }
        }

        for goal in goals {
            _ = try GoalRecord(goalID: goal.goalID, revision: goal.revision, statement: goal.statement, owner: goal.owner, status: goal.status)
        }

        for grant in grants {
            // Full approval reconstruction: user.kind, grantee.kind, scopes, revision.
            _ = try StoredGrant(
                reference: grant.reference,
                state: grant.state,
                recordedAt: grant.recordedAt,
                revokedAt: grant.revokedAt
            )
            guard goals.contains(where: { $0.goalID == grant.reference.goalID }) else {
                throw IntercomError.invalid("INVARIANT_GRANT_GOAL")
            }
            let approvalAudits = audits.filter {
                $0.action == .recordApproval && $0.goalID == grant.reference.goalID
            }
            guard !approvalAudits.isEmpty else {
                throw IntercomError.invalid("INVARIANT_GRANT_AUDIT")
            }
        }
        let activePairs = grants.filter { $0.state == .active }.map { "\($0.reference.goalID)|\($0.reference.grantee.identifier)" }
        try requireUnique(activePairs, "ACTIVE_GRANTEE")

        for claim in claims {
            _ = try TaskClaim(
                taskID: claim.taskID,
                goalID: claim.goalID,
                revision: claim.revision,
                owner: claim.owner,
                status: claim.status,
                handoffHops: claim.handoffHops,
                grantID: claim.grantID,
                openHandoffReceiptID: claim.openHandoffReceiptID
            )
            guard goals.contains(where: { $0.goalID == claim.goalID }) else {
                throw IntercomError.invalid("INVARIANT_CLAIM_GOAL")
            }
            guard let grant = grants.first(where: { $0.reference.grantID == claim.grantID }) else {
                throw IntercomError.invalid("INVARIANT_CLAIM_GRANT")
            }
            guard grant.reference.goalID == claim.goalID, grant.reference.grantee == claim.owner else {
                throw IntercomError.invalid("INVARIANT_CLAIM_GRANT")
            }
            // Current claim grant must authorize claimTask (restore-time scope, not identity alone).
            guard grant.reference.scopes.contains(.claimTask) else {
                throw IntercomError.invalid("INVARIANT_CLAIM_GRANT_SCOPE")
            }
            try validateTaskHandoffReplay(for: claim)
        }

        for handoff in handoffs {
            _ = try HandoffReceipt(
                receiptID: handoff.receiptID,
                goalID: handoff.goalID,
                taskID: handoff.taskID,
                fromOwner: handoff.fromOwner,
                toOwner: handoff.toOwner,
                state: handoff.state,
                hop: handoff.hop,
                taskRevision: handoff.taskRevision,
                time: handoff.time,
                fromGrantID: handoff.fromGrantID,
                toGrantID: handoff.toGrantID
            )
            guard claims.contains(where: { $0.taskID == handoff.taskID && $0.goalID == handoff.goalID }) else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TASK")
            }
            // Nonexistent / mismatched grants fail closed (includes forged toGrantID).
            guard let fromGrant = grants.first(where: { $0.reference.grantID == handoff.fromGrantID }),
                  fromGrant.reference.goalID == handoff.goalID,
                  fromGrant.reference.grantee == handoff.fromOwner else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_GRANT")
            }
            guard fromGrant.reference.scopes.contains(.handoff) else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_GRANT_SCOPE")
            }
            guard let toGrant = grants.first(where: { $0.reference.grantID == handoff.toGrantID }),
                  toGrant.reference.goalID == handoff.goalID,
                  toGrant.reference.grantee == handoff.toOwner else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_GRANT")
            }
            guard toGrant.reference.scopes.contains(.claimTask) else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_GRANT_SCOPE")
            }
            guard let offerAudit = audits.first(where: {
                $0.receiptID == handoff.receiptID && $0.action == .offerHandoff
            }) else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_AUDIT")
            }
            guard offerAudit.goalID == handoff.goalID,
                  offerAudit.taskID == handoff.taskID,
                  offerAudit.subjectReceiptID.isEmpty || offerAudit.subjectReceiptID == handoff.receiptID,
                  case .agent(let actor) = offerAudit.actor,
                  actor == handoff.fromOwner,
                  offerAudit.snapshotRevision >= 1 else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_AUDIT")
            }
            let acks = audits.filter {
                $0.action == .acknowledgeHandoff && $0.subjectReceiptID == handoff.receiptID
            }.sorted { $0.snapshotRevision < $1.snapshotRevision }
            let completes = audits.filter {
                $0.action == .completeHandoff && $0.subjectReceiptID == handoff.receiptID
            }.sorted { $0.snapshotRevision < $1.snapshotRevision }
            let cancels = audits.filter {
                $0.action == .cancelHandoff && $0.subjectReceiptID == handoff.receiptID
            }.sorted { $0.snapshotRevision < $1.snapshotRevision }
            for transition in acks + completes {
                guard transition.goalID == handoff.goalID,
                      transition.taskID == handoff.taskID,
                      case .agent(let actor) = transition.actor,
                      actor == handoff.toOwner else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_TRANSITION_AUDIT")
                }
            }
            for cancel in cancels {
                guard cancel.goalID == handoff.goalID,
                      cancel.taskID == handoff.taskID else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_TRANSITION_AUDIT")
                }
                switch cancel.actor {
                case .agent(let actor):
                    guard actor == handoff.fromOwner else {
                        throw IntercomError.invalid("INVARIANT_HANDOFF_TRANSITION_AUDIT")
                    }
                case .nativeAdapter:
                    break
                }
            }
            // Per-offer timeline: offer → exactly one ack → exactly one complete (or cancel/revoke).
            try validateOfferTimeline(
                handoff: handoff,
                offerAudit: offerAudit,
                acks: acks,
                completes: completes,
                cancels: cancels
            )
        }

        // Reconstruct every message; enforce unique keys/receipts and exact message↔idempotency bijection.
        for message in messages {
            _ = try AttributedMessage(
                goalID: message.goalID,
                taskID: message.taskID,
                sender: message.sender,
                recipient: message.recipient,
                receiptID: message.receiptID,
                time: message.time,
                evidence: message.evidence,
                idempotencyKey: message.idempotencyKey,
                body: message.body
            )
        }
        guard idempotency.count == messages.count else {
            throw IntercomError.invalid("INVARIANT_IDEMPOTENCY")
        }
        let messageReceipts = messages.map(\.receiptID)
        let messageKeys = messages.map(\.idempotencyKey)
        let recordReceipts = idempotency.map(\.receiptID)
        let recordKeys = idempotency.map(\.key)
        try requireUnique(messageReceipts, "MESSAGE")
        try requireUnique(messageKeys, "IDEMPOTENCY_KEY")
        try requireUnique(recordReceipts, "IDEMPOTENCY_RECEIPT")
        try requireUnique(recordKeys, "IDEMPOTENCY_KEY")
        guard Set(messageReceipts) == Set(recordReceipts), Set(messageKeys) == Set(recordKeys) else {
            throw IntercomError.invalid("INVARIANT_IDEMPOTENCY_BIJECTION")
        }
        let messageByReceipt = Dictionary(uniqueKeysWithValues: messages.map { ($0.receiptID, $0) })
        for record in idempotency {
            guard let message = messageByReceipt[record.receiptID],
                  message.idempotencyKey == record.key else {
                throw IntercomError.invalid("INVARIANT_IDEMPOTENCY_BIJECTION")
            }
            let canonical = try IntercomCodec.encodeString(MessageWrite(
                goalID: message.goalID,
                taskID: message.taskID,
                sender: message.sender,
                recipient: message.recipient,
                time: message.time,
                evidence: message.evidence,
                body: message.body
            ))
            guard canonical == record.canonicalPayload else {
                throw IntercomError.invalid("INVARIANT_IDEMPOTENCY")
            }
            guard let audit = audits.first(where: {
                $0.receiptID == message.receiptID && $0.action == .appendMessage
            }) else {
                throw IntercomError.invalid("INVARIANT_MESSAGE_AUDIT")
            }
            guard audit.goalID == message.goalID,
                  audit.taskID == message.taskID,
                  case .agent(let actor) = audit.actor,
                  actor == message.sender,
                  audit.snapshotRevision >= 1 else {
                throw IntercomError.invalid("INVARIANT_MESSAGE_AUDIT")
            }
        }
    }

    /// Per-offer: offer → exactly one ack → exactly one complete; cancel/revoke forbids completes
    /// and allows at most one ack only when offer-revision-ordered. Attempt id = offer receiptID.
    private func validateOfferTimeline(
        handoff: HandoffReceipt,
        offerAudit: AuditReceipt,
        acks: [AuditReceipt],
        completes: [AuditReceipt],
        cancels: [AuditReceipt]
    ) throws {
        let lifecycle = try derivedHandoffState(for: handoff.receiptID)
        switch lifecycle {
        case .offered:
            guard acks.isEmpty, completes.isEmpty, cancels.isEmpty else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
            }
        case .acknowledged:
            guard acks.count == 1, completes.isEmpty, cancels.isEmpty,
                  offerAudit.snapshotRevision < acks[0].snapshotRevision else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
            }
        case .completed:
            guard acks.count == 1, completes.count == 1, cancels.isEmpty,
                  offerAudit.snapshotRevision < acks[0].snapshotRevision,
                  acks[0].snapshotRevision < completes[0].snapshotRevision else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
            }
        case .revoked:
            guard completes.isEmpty, cancels.count <= 1 else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
            }
            if acks.count > 1 {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
            }
            if let ack = acks.first {
                guard offerAudit.snapshotRevision < ack.snapshotRevision else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
                }
            }
            if let cancel = cancels.first {
                let prior = acks.first?.snapshotRevision ?? offerAudit.snapshotRevision
                guard prior < cancel.snapshotRevision else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
                }
            }
        }
    }

    /// Revision-ordered attempt replay: receiptID = attempt id; `claim.handoffHops` counts
    /// completions only. Cancelled/revoked attempts are retained and may be followed by a new
    /// offer for the same hop slot without erasing history.
    private func validateTaskHandoffReplay(for claim: TaskClaim) throws {
        let claimAudits = audits.filter {
            $0.action == .claimTask && $0.taskID == claim.taskID && $0.goalID == claim.goalID
        }.sorted { $0.snapshotRevision < $1.snapshotRevision }
        guard let firstClaim = claimAudits.first, case .agent(let initialOwner) = firstClaim.actor else {
            throw IntercomError.invalid("INVARIANT_CLAIM_AUDIT")
        }

        // Chronological by offer audit revision (attempt order), not hop uniqueness.
        let offers = handoffs
            .filter { $0.taskID == claim.taskID && $0.goalID == claim.goalID }
            .compactMap { offer -> (HandoffReceipt, AuditReceipt)? in
                guard let offerAudit = audits.first(where: {
                    $0.receiptID == offer.receiptID && $0.action == .offerHandoff
                }) else { return nil }
                return (offer, offerAudit)
            }
            .sorted { $0.1.snapshotRevision < $1.1.snapshotRevision }

        guard offers.count == handoffs.filter({ $0.taskID == claim.taskID && $0.goalID == claim.goalID }).count else {
            throw IntercomError.invalid("INVARIANT_HANDOFF_AUDIT")
        }

        let completedOffers = try offers.map(\.0).filter {
            try derivedHandoffState(for: $0.receiptID) == .completed
        }
        let completedHopSet = Set(completedOffers.map(\.hop))
        guard completedHopSet.count == completedOffers.count else {
            throw IntercomError.invalid("INVARIANT_HANDOFF_HOPS")
        }
        if claim.handoffHops == 0 {
            guard completedOffers.isEmpty else { throw IntercomError.invalid("INVARIANT_HANDOFF_HOPS") }
        } else {
            guard completedHopSet == Set(1...claim.handoffHops) else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_HOPS")
            }
        }

        var expectedOwner = initialOwner
        var expectedGrantID: String?
        var completedHops = 0
        var expectedRevision: UInt64 = 1
        var openOffer: HandoffReceipt?
        var priorTerminalAuditRevision: UInt64?
        var sawOpenAttempt = false

        for (index, pair) in offers.enumerated() {
            let offer = pair.0
            let offerAudit = pair.1
            if sawOpenAttempt {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
            }
            guard offer.hop == completedHops + 1 else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_HOPS")
            }
            if index == 0 {
                guard offerAudit.snapshotRevision > firstClaim.snapshotRevision else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_CHRONOLOGY")
                }
            } else {
                guard let priorTerminal = priorTerminalAuditRevision,
                      offerAudit.snapshotRevision > priorTerminal else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_CHRONOLOGY")
                }
            }

            guard offer.fromOwner == expectedOwner else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_CHAIN")
            }
            if let expectedGrantID {
                guard offer.fromGrantID == expectedGrantID else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_CHAIN")
                }
            } else {
                expectedGrantID = offer.fromGrantID
            }

            expectedRevision += 1
            guard offer.taskRevision == expectedRevision else {
                throw IntercomError.invalid("INVARIANT_HANDOFF_TASK_REVISION")
            }

            let lifecycle = try derivedHandoffState(for: offer.receiptID)
            let acks = audits.filter {
                $0.action == .acknowledgeHandoff && $0.subjectReceiptID == offer.receiptID
            }
            let completes = audits.filter {
                $0.action == .completeHandoff && $0.subjectReceiptID == offer.receiptID
            }.sorted { $0.snapshotRevision < $1.snapshotRevision }
            let cancels = audits.filter {
                $0.action == .cancelHandoff && $0.subjectReceiptID == offer.receiptID
            }.sorted { $0.snapshotRevision < $1.snapshotRevision }

            switch lifecycle {
            case .offered:
                openOffer = offer
                sawOpenAttempt = true
                priorTerminalAuditRevision = nil
            case .acknowledged:
                expectedRevision += 1
                openOffer = offer
                sawOpenAttempt = true
                priorTerminalAuditRevision = nil
            case .completed:
                expectedRevision += 1
                expectedRevision += 1
                expectedOwner = offer.toOwner
                expectedGrantID = offer.toGrantID
                completedHops += 1
                guard let completeAudit = completes.first else {
                    throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
                }
                priorTerminalAuditRevision = completeAudit.snapshotRevision
            case .revoked:
                if !acks.isEmpty {
                    expectedRevision += 1
                }
                expectedRevision += 1 // cancel or revoke clears open (one claim bump)
                openOffer = nil
                if let cancel = cancels.first {
                    priorTerminalAuditRevision = cancel.snapshotRevision
                } else {
                    // Legacy / grant-only revoke path: terminal is the revokeGrant audit after offer.
                    let revokeAudits = audits.filter {
                        $0.action == .revokeGrant && $0.goalID == offer.goalID
                    }.sorted { $0.snapshotRevision < $1.snapshotRevision }
                    guard let revoke = revokeAudits.first(where: {
                        $0.snapshotRevision > offerAudit.snapshotRevision
                    }) else {
                        throw IntercomError.invalid("INVARIANT_HANDOFF_TIMELINE")
                    }
                    priorTerminalAuditRevision = revoke.snapshotRevision
                }
                // Ownership/grant unchanged — cancel never transfers or revives auth.
            }
        }

        if offers.isEmpty {
            guard initialOwner == claim.owner else {
                throw IntercomError.invalid("INVARIANT_CLAIM_AUDIT")
            }
        }

        guard claim.handoffHops == completedHops else {
            throw IntercomError.invalid("INVARIANT_HANDOFF_HOPS")
        }
        guard claim.owner == expectedOwner else {
            throw IntercomError.invalid("INVARIANT_CLAIM_AFTER_HANDOFF")
        }
        if let expectedGrantID {
            guard claim.grantID == expectedGrantID else {
                throw IntercomError.invalid("INVARIANT_CLAIM_AFTER_HANDOFF")
            }
        }
        guard claim.revision == expectedRevision else {
            throw IntercomError.invalid("INVARIANT_CLAIM_TASK_REVISION")
        }

        switch claim.status {
        case .claimed:
            guard claim.openHandoffReceiptID == nil, openOffer == nil else {
                throw IntercomError.invalid("INVARIANT_OPEN_HANDOFF")
            }
        case .handoffPending:
            guard let open = openOffer,
                  claim.openHandoffReceiptID == open.receiptID,
                  open.fromOwner == claim.owner,
                  open.hop == claim.handoffHops + 1 else {
                throw IntercomError.invalid("INVARIANT_OPEN_HANDOFF")
            }
            let openState = try derivedHandoffState(for: open.receiptID)
            guard openState == .offered || openState == .acknowledged else {
                throw IntercomError.invalid("INVARIANT_OPEN_HANDOFF")
            }
        }
    }
}

enum IntercomCodec {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    static func encodeString<T: Encodable>(_ value: T) throws -> String {
        let data = try encode(value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw IntercomError.persistence("SNAPSHOT_ENCODE_FAILED")
        }
        return string
    }

    static func decodeSnapshot(_ data: Data) throws -> IntercomSnapshot {
        guard data.count <= IntercomLimits.maxSnapshotBytes else {
            throw IntercomError.persistence("SNAPSHOT_TOO_LARGE")
        }
        let snapshot: IntercomSnapshot
        do {
            snapshot = try JSONDecoder().decode(IntercomSnapshot.self, from: data)
        } catch let error as IntercomError {
            throw error
        } catch {
            throw IntercomError.persistence("SNAPSHOT_DECODE_FAILED")
        }
        try snapshot.validate()
        return snapshot
    }
}

enum IntercomID {
    static func validate(_ value: String, field: String, maximumLength: Int = IntercomLimits.maxIdentifierLength) throws -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:")
        guard (1...maximumLength).contains(value.count), value.allSatisfy({ allowed.contains($0) }) else {
            throw IntercomError.invalid("INVALID_\(field)")
        }
        return value
    }
}

enum IntercomText {
    static func validate(_ value: String, field: String, maximumBytes: Int, allowEmpty: Bool) throws -> String {
        guard !value.contains("\u{0000}"),
              (allowEmpty ? 0 : 1)...maximumBytes ~= value.utf8.count else {
            throw IntercomError.invalid("INVALID_\(field)")
        }
        return value
    }
}

enum IntercomTime {
    static func validate(_ value: String) throws -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        guard formatter.date(from: value) != nil else { throw IntercomError.invalid("INVALID_TIME") }
        return value
    }

    static func format(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}

private func requireUnique(_ values: [String], _ field: String) throws {
    var seen = Set<String>()
    for value in values {
        guard seen.insert(value).inserted else { throw IntercomError.invalid("DUPLICATE_\(field)") }
    }
}
