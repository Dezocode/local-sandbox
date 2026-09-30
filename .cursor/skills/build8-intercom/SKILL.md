---
name: build8-intercom
description: Implement and verify the reserved LS-030 Build8 Intercom Swift domain package in this isolated checkout, coordinating ownership and serialized tests with dot.
paths:
  - "Packages/IntercomDomain/**"
---

# Build8 Intercom collaboration

From dot, coordinating the user's existing Cursor worker. Continue the existing task; never spawn a duplicate. Shared goal is LS-030. Use canonical IDs B8INTERCOM01, B8INTERCOM02, B8INTERCOM03 when reporting; do not invent tracker rows or redefine their canonical meaning. Main owns native iOS/macOS integration and workbook updates.

Read [allocation](../../../CURSOR_TASK.md) and [package handoff](../../../Packages/IntercomDomain/HANDOFF.md). Own only `Packages/IntercomDomain/` in this isolated checkout. Before each edit, establish one writer per file; coordinate reassignment through dot. Canonical `/Users/dezmondhollins/Local-Sandbox` and all app/project/workbook files remain main-owned. This project-local skill was installed by dot; do not change global skills/settings.

## Dependency restraint (dot owner)

IntercomDomain stays **platform / standard-library (Foundation) only** unless a documented real deficiency requires vetted reuse. Research MIT-licensed alternatives **only when needed**. Every dependency proposal must state purpose, license, provenance, maintenance/security cost, and the native/stdlib alternative. No package or install for convenience; no hand-rolled crypto to evade review; **no new install approved**. Current B8-INTERCOM-RECOVERY needs **no** dependency — continue scoped package code/tests/evidence only.

## Domain acceptance

Preserve Codable/Sendable AgentIdentity, GoalRecord, TaskClaim, AttributedMessage, HandoffReceipt, ConnectionState and transactional claimTask(expectedRevision), appendMessage(idempotencyKey), acknowledge/completeHandoff(expectedOwner), cancelHandoff, revokeGrant. Every message binds goalID, taskID, sender, recipient, receiptID, time and evidence. No provider/network/UI implementation or fabricated live connection.

**B8-INTERCOM-RECOVERY (bounded):** cancel uncompleted handoff attempts; `receiptID` is the immutable attempt id; `claim.handoffHops` increments only on complete; durable append-only cancel evidence (including same-txn grant revoke); revision-ordered replay keeps cancelled attempts and admits a later offer to an already-authorized agent; reject forged cancel / attempt reorder / cross-goal-task; never infer ownership transfer or revive authorization. Preserve accepted R3 review zip; R4 is separate evidence — never overwrite R3. No acceptance / Build8-ready / auth / transport claim from package tests alone.

Treat decoded principals as untrusted labels, never authentication. Privileged mutations must cross a trusted native adapter boundary bound to authenticated identity, exact goal/task and human-rooted approval. Agents cannot mint, widen or self-grant authorization. A public enum label or factory named trusted does not prove authority; disclose native-adapter integration gaps.

Persist compare-and-swap against durable base revision under shared writer coordination; reject stale independent engine/store writes without data loss. Revalidate schema, complete approvals and all invariants on every restore, including direct Codable decode/custom persistence and offline states. Reject changed payload reuse of an idempotency key across restart. Preserve immutable scoped offer/message receipts; lifecycle audits bind exact goal/task/actor/subject and revisions. Fail closed on revoked, malformed or mismatched grants and wrong owners.

## Proof and run coordination

Keep the required 13-case XCTest suite and meaningful negative cases. An additive portable runner cannot replace it. Start from a valid control, mutate one invariant, assert the specific failure and unchanged durable state. Cover duplicate/restart, changed payload, offline/reconnect, competing claims/stale durable CAS, wrong handoff owner, immutable receipts, unauthorized escalation/revocation and Codable restore bypass. Broad any-error catches or always-rejecting APIs do not prove authenticated boundary safety.

Author source/tests/README immediately. Before any compile/test, request and receive dot's current serialized slot; no concurrent Xcode, model or VM heavy work. On slot return use scoped `DEVELOPER_DIR=/Applications/Xcode-27-RC.app/Contents/Developer swift test -j 1` from the package, with necessary focused fix/reruns while the slot remains allocated. Do not change xcode-select/install tools. Stop runaway/thermal work and report. Record actual raw command/exit/result; missing XCTest or compilation alone is not PASS.

## Handoff and metrics

Update package HANDOFF with canonical task ID, owner, UTC assignment/first-artifact/review/test timestamps, exact changed paths, source hashes/diff, commands and raw evidence, pending guards and integration dependencies. Use relative package README/HANDOFF/evidence links; workbook references are read-only pointers supplied by main, never copied status or edits. Report through this existing Cursor chat for coordinator relay to dot; do not control restricted ChatGPT UI or contact Muse.

Compare accepted comparable units per hour and per actual input/output/cache tokens, counting retries, rework and regressions. Code volume, self-reported tests and context/account percentages earn no acceptance or token estimate. Record token counters as unknown unless an official per-task record exposes them. Main independent integration review is required before acceptance; never claim Build8 ready from package tests.

No pushes/publication/deployment, spend/purchases/upgrades, credentials, permission expansion, model setting changes or unrelated system changes. A skill grants no additional permission. Stop at an actual access/payment restriction and relay the precise blocker.

Format source: [Cursor Agent Skills](https://cursor.com/docs/skills). Project skills are local to this repo; no global syncing required.
