# IntercomDomain handoff

## Canonical IDs

B8INTERCOM01 · B8INTERCOM02 · B8INTERCOM03 (workbook rows owned by main; this file is package evidence only)

**Bounded recovery task:** `B8-INTERCOM-RECOVERY` (cancel uncompleted handoff → re-offer to already-authorized agent; attempt id ≠ completed-hop count)

## Owner / status

- **Package owner:** Cursor Intercom worker (`Packages/IntercomDomain/` exclusive)
- **Admitted task (UI):** 2026-09-30T20:42Z
- **First artifacts:** Package/Models **20:53:11Z**; Persistence/Engine **20:54:54Z**
- **Skill:** `build8-intercom` (project-local) — includes dependency restraint (Foundation/stdlib only; no new install)
- **R3 (accepted narrow trusted-HOST journal):** preserve immutable  
  `…/task-2/review-votes/Build8-Intercom-review-r3.zip`  
  SHA-256 `3ee0c1ae15ecae6410bfac17639782e6eebd3709f25e9c2d9e329547ff4e0e47` — **never overwrite**
- **R4:** recovery source/evidence (this turn) — **not an acceptance claim**
- **FULL PACKAGE acceptance:** **PENDING** (not claimed)
- **Not claimed:** Build8 ready, publication, native integration, auth/transport, single-core compute

## B8-INTERCOM-RECOVERY milestone (first implementation + tests)

### Behavior shipped (narrow)
- `AuditAction.cancelHandoff` + engine `cancelHandoff(receiptID:expectedRevision:actor:)` for uncompleted attempts only
- Immutable offer `receiptID` = unique **attempt** id; `claim.handoffHops` increments **only** on complete
- Revision-ordered attempt replay retains cancelled/revoked attempts; admits later offer for same hop slot
- Durable append-only cancel evidence; grant `revokeGrant` cancels affected open offers in the **same transaction**
- Deterministic duplicate cancel (idempotent; single cancel audit); reject forged cancel / reorder / cross-goal-task on validate
- Never transfers ownership or revives revoked authorization on cancel

### Tests
- Keep prior **35**; additive recovery **36–45**
- Lease-only verification (see R4 receipt below when present)

### Explicit non-claims
- Not revocation-recovery-complete beyond this bounded cancel→reassign path
- Not Build8-ready / not full package publication
- Not native auth or remote transport
- No new SPM/system dependency introduced

## Authoritative leased command spelling

```text
python3 /Users/dezmondhollins/Documents/Codex/2026-09-30/task/build-lease.py \
  --label cursor-intercom-tests \
  --receipt …/Packages/IntercomDomain/evidence/lease-receipt-<UTC>.json \
  --wait-seconds 600 \
  -- /usr/bin/env DEVELOPER_DIR=/Applications/Xcode-27-RC.app/Contents/Developer COPYFILE_DISABLE=1 \
     swift test --jobs 1 -Xswiftc -j -Xswiftc 1 --build-path /tmp/IntercomDomain-swift-build
```

`--jobs 1` = SwiftPM package jobs; `-Xswiftc -j -Xswiftc 1` = swiftc parallel **commands**. Not single-core proof.

## Preserved earlier evidence (selected)

| When | Exit | Artifact | Note |
|---|---:|---|---|
| 22:14:33Z | 0 | lease-receipt + jobs1 log | freeze correctness milestone 29/29 |
| 22:22:11Z | 0 | r2-fix | init demotion fail-closed 30/30 |
| 22:24:31Z | 0 | r2-scopes | grant-scope restore 35/35 |

## Unmet limitations (explicit)

1. Exact **grantID + approvalRevision** audit binding on claim/handoff audits — schema-v1 fields absent; pending
2. Host **namespace / task scope** isolation — host-owned
3. **Old-claim regrant/reclaim** after owner-grant revocation — still requires a fresh active scoped grant (cancel does not revive)
4. Concurrent **cross-process flock** stress tests — absent
5. **Power-loss durability** — no claim without host fsync/crash proof
6. **NativeAdapterAuthority** public ctor is trusted **HOST ONLY** — not user auth; SandboxStore mint unproven
7. Package XCTest PASS ≠ workbook acceptance ≠ Build8 ready ≠ publishable unit; native authentication / remote transport outside / unproven

## Tokens

unknown
