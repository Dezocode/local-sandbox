# IntercomDomain

Foundation-only, platform-neutral Swift package for shared native iOS/macOS Intercom journal logic.

This package is **not** a live agent bus, provider client, UI, or credential store. It does not open network sessions and does not fabricate live dot, Muse, or provider connections.

Canonical task IDs (report only; workbook owned by main): **B8INTERCOM01**, **B8INTERCOM02**, **B8INTERCOM03**. Bounded recovery task: **B8-INTERCOM-RECOVERY**.

## Ownership

| Surface | Owner |
|---|---|
| `Packages/IntercomDomain/` sources + package tests | Cursor Intercom worker (this package) |
| Native SandboxStore adapter, app/project wiring, workbooks, canonical Local Sandbox | Main implementation worker |
| Push / PR / deploy / publication / credentials | Cloud-agent git/PR workflow only when authorized |

## Trust boundary (critical)

- `Principal` is a **Codable audit label**, not authentication. Decoded `role: nativeAdapter` JSON **cannot** call privileged APIs.
- Privileged mutations require non-Codable `NativeAdapterAuthority`. Its **public constructor is trusted HOST ONLY** — minting it does not authenticate a user, and a decoded label never becomes privilege.
- User approvals are authoritative **external references** (`UserApprovalReference`). Agents cannot self-grant, escalate (`requestEscalation` always throws), or revoke.

## Public API

Types: `AgentIdentity`, `GoalRecord`, `TaskClaim`, `AttributedMessage`, `HandoffReceipt`, `ConnectionState`, `NativeAdapterAuthority`, `UserApprovalReference`, `StoredGrant`, `AuditReceipt`, `IntercomSnapshot`, `IntercomError` (includes `notCommitted` / `committedUnknown`).

Engine: privileged ops take `authority: NativeAdapterAuthority`. Agent ops: `claimTask`, `appendMessage`, `offerHandoff`, `acknowledgeHandoff`, `completeHandoff`, `cancelHandoff(receiptID, expectedRevision, actor)`. After `committedUnknown`, call `reconcileFromPersistence()` before retry.

**Handoff attempt vs completed hop:** offer `receiptID` is the unique attempt id. `claim.handoffHops` increments only on complete. Cancel closes an uncompleted attempt without ownership transfer; a later offer may reuse the same hop slot under a new attempt id. `revokeGrant` writes same-txn cancel evidence for affected open offers, then revokes — never transfers ownership or revives authorization.

Persistence: durable `commit(_:expectedBaseRevision:)` CAS; `AtomicFileSnapshotStore` uses flock + atomic replace. `notCommitted` only when the durable base is **proven unchanged**; unknown/unreadable disk after attempted publish is `committedUnknown` (no fake rollback).

## Status (narrow; no acceptance claim)

R3 trusted-HOST journal review zip preserved (`3ee0c1ae…`). B8-INTERCOM-RECOVERY adds cancel→re-offer for uncompleted attempts. **FULL PACKAGE acceptance still pending.** Not Build8-ready; not native auth; not remote transport. See `HANDOFF.md` for hashes, receipts, and unmet limitations.

## Documented gaps / unmet (not claimed)

- Exact grantID + approvalRevision audit binding — pending (schema-v1)
- Host namespace / task scope; old-claim regrant/reclaim after owner-grant revoke still needs a fresh active scoped grant
- Concurrent cross-process flock stress tests
- Power-loss durability without fsync/crash proof
- Native SandboxStore mint of `NativeAdapterAuthority` after real user auth
- Single-core proof (package `--jobs 1` ≠ compiler `-j 1` ≠ single core)
- Narrow trusted-HOST journal acceptance may follow independent review only; native authentication / remote transport remain outside / unproven
- Recovery unit is bounded cancel→reassign only — **not** revocation-recovery-complete beyond that path; **no** acceptance claim

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
