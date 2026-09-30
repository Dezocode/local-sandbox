# IntercomDomain

Foundation-only, platform-neutral Swift package for shared native iOS/macOS Intercom journal logic.

This package is **not** a live agent bus, provider client, UI, or credential store. It does not open network sessions and does not fabricate live dot, Muse, or provider connections.

Canonical task IDs (report only; workbook owned by main): **B8INTERCOM01**, **B8INTERCOM02**, **B8INTERCOM03**. Bounded recovery: **B8-INTERCOM-RECOVERY**.

## Ownership

| Surface | Owner |
|---|---|
| `Packages/IntercomDomain/` sources + package tests | Cursor Intercom worker (this package) |
| Native SandboxStore adapter, app/project wiring, workbooks, canonical Local Sandbox | Main implementation worker |
| Push / PR / deploy / publication / credentials | Out of scope for this package |

## Dependency policy

Platform / standard-library (Foundation) only unless a documented real deficiency needs vetted reuse. No convenience packages, no hand-rolled crypto to evade review, no new installs approved. Dependency proposals (MIT-only research when needed) must state purpose, license, provenance, maintenance/security cost, and native alternative. **B8-INTERCOM-RECOVERY introduces no dependency.**

## Trust boundary (critical)

- `Principal` is a **Codable audit label**, not authentication. Decoded `role: nativeAdapter` JSON **cannot** call privileged APIs.
- Privileged mutations require non-Codable `NativeAdapterAuthority`. Its **public constructor is trusted HOST ONLY** — minting it does not authenticate a user, and a decoded label never becomes privilege.
- User approvals are authoritative **external references** (`UserApprovalReference`). Agents cannot self-grant, escalate (`requestEscalation` always throws), or revoke.

## Public API

Types: `AgentIdentity`, `GoalRecord`, `TaskClaim`, `AttributedMessage`, `HandoffReceipt`, `ConnectionState`, `NativeAdapterAuthority`, `UserApprovalReference`, `StoredGrant`, `AuditReceipt`, `IntercomSnapshot`, `IntercomError` (includes `notCommitted` / `committedUnknown`).

Engine: privileged ops take `authority: NativeAdapterAuthority`. Agent ops: `claimTask`, `appendMessage`, `offerHandoff`, `acknowledgeHandoff`, `completeHandoff`, `cancelHandoff`. After `committedUnknown`, call `reconcileFromPersistence()` before retry.

**Handoff attempts:** offer `receiptID` is the unique attempt id (never reused). `claim.handoffHops` counts **completed** transfers only. `cancelHandoff` (owner) or grant `revokeGrant` (same transaction) append durable cancel evidence for uncompleted attempts without transferring ownership or reviving grants; a later offer may target the same hop slot while retaining history.

Persistence: durable `commit(_:expectedBaseRevision:)` CAS; `AtomicFileSnapshotStore` uses flock + atomic replace. `notCommitted` only when the durable base is **proven unchanged**; unknown/unreadable disk after attempted publish is `committedUnknown` (no fake rollback).

## Status

R3 accepted as narrow trusted-HOST journal only (immutable review zip SHA `3ee0c1ae…`). R4 is recovery source/evidence — **FULL PACKAGE acceptance still pending.** See `HANDOFF.md`.

## Documented gaps / unmet (not claimed)

- Exact grantID + approvalRevision audit binding — pending (schema-v1)
- Host namespace / task scope; old-claim reclaim still needs a fresh active scoped grant after owner-grant revoke
- Concurrent cross-process flock stress tests
- Power-loss durability without fsync/crash proof
- Native SandboxStore mint of `NativeAdapterAuthority` after real user auth
- Single-core proof (package `--jobs 1` ≠ compiler `-j 1` ≠ single core)
- Narrow trusted-HOST journal acceptance may follow independent review only; native authentication / remote transport remain outside / unproven

## Build / test (lease only)

```bash
python3 /Users/dezmondhollins/Documents/Codex/2026-09-30/task/build-lease.py \
  --label cursor-intercom-tests \
  --receipt /ABS/Packages/IntercomDomain/evidence/lease-receipt-<UTC>.json \
  --wait-seconds 600 \
  -- /usr/bin/env DEVELOPER_DIR=/Applications/Xcode-27-RC.app/Contents/Developer COPYFILE_DISABLE=1 \
     swift test --jobs 1 -Xswiftc -j -Xswiftc 1 --build-path /tmp/IntercomDomain-swift-build
```

Evidence: `evidence/B8INTERCOM01.md`, `evidence/B8INTERCOM02.md`, `evidence/B8INTERCOM03.md`, `evidence/raw/`, lease receipts under `evidence/`.
