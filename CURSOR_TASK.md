# LS-030 — Cursor Intercom domain allocation

From dot, coordinating for the user. Parent confirmed exclusive Cursor ownership of `Packages/IntercomDomain/` and its tests in this isolated checkout. Canonical integration and workbooks belong to the main implementation worker. Baseline is committed Local Sandbox HEAD 1a7ecd5; substantial canonical uncommitted changes are deliberately not copied or changed.

Implement a production platform-neutral Swift package for shared native iOS/macOS Intercom domain logic, not a separate demo app. Foundation only; no network/provider/UI, credential access, private APIs, installs, remote pushes, or edits outside the package and this handoff. Preserve canonical repo untouched.

Contract: Codable/Sendable AgentIdentity, GoalRecord, TaskClaim, AttributedMessage, HandoffReceipt, ConnectionState. Transactions: claimTask(expectedRevision), appendMessage(idempotencyKey), acknowledge/completeHandoff(expectedOwner), revokeGrant. Every message carries goalID/taskID/sender/recipient/receiptID/time/evidence. Agents cannot create or self-grant user authorization. Typed owner identities and approval references; fail closed for revoked/mismatched grants. Native SandboxStore adapter supplies approved path and authoritative user approvals.

Implement revision/conflict control, idempotent message replay across restart, bounded handoff ownership transitions, explicit offline/reconnecting/unavailable states, audit receipts, and a transactional persistence abstraction with atomic file snapshot implementation and schema version. Reject same idempotency key with changed payload. No fabricated live dot/Muse/provider connections.

Add meaningful tests for duplicate/restart, offline/reconnect, competing claims, stale revisions, wrong handoff owner, forbidden escalation and revocation. Write README integration API and limitations. Do lightweight code implementation now. Do not run Swift/Xcode builds until dot coordinates a low-concurrency slot due recent Mac heat/freezing. Record commands/results only if actually executed. No heavy model runs or system changes.

Use existing Cursor subscription/default included model only. Stop before paid overage, upgrade, credentials or permission expansion. On completion report files, API, evidence and remaining blockers; canonical tracker owner will integrate. Never claim full Build8 readiness from this package.
