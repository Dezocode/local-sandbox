# IntercomDomain handoff

## Canonical IDs

B8INTERCOM01 · B8INTERCOM02 · B8INTERCOM03 (workbook rows owned by main; this file is package evidence only)  
**B8-INTERCOM-RECOVERY** — bounded cancel→re-offer unit (no acceptance claim)

## Owner / status

- **Package owner:** Cursor Intercom worker (`Packages/IntercomDomain/` exclusive)
- **Admitted task (UI):** 2026-09-30T20:42Z
- **First artifacts:** Package/Models **20:53:11Z**; Persistence/Engine **20:54:54Z**
- **Skill:** `build8-intercom` (project-local) — updated with recovery guards
- **R3 (preserve; never overwrite):** review zip SHA-256 `3ee0c1ae15ecae6410bfac17639782e6eebd3709f25e9c2d9e329547ff4e0e47`
- **R4 recovery milestone:** cancel uncompleted handoff attempt + re-offer to already-authorized agent; XCTest 36+ added; lease suite pending/recorded below
- **FULL PACKAGE acceptance:** **PENDING** (not claimed)
- **Not claimed:** Build8 ready, publication, native auth, remote transport, revocation-recovery-complete beyond this bounded path

## B8-INTERCOM-RECOVERY behavior

- `AuditAction.cancelHandoff`; offer `receiptID` = attempt id; `claim.handoffHops` only on complete
- Engine: `cancelHandoff(receiptID, expectedRevision, actor)`; idempotent if already revoked; denies completed
- `revokeGrant`: same-txn durable cancel evidence for affected open offers, then revoke — no ownership transfer / grant revive
- Validate: forged cross-goal/task cancel, duplicate cancel, reorder, completed+cancel fail closed
- After cancel (owner grant still active), new offer to another agent with valid scoped active grant is allowed

## Authoritative leased command (R4)

```text
python3 /Users/dezmondhollins/Documents/Codex/2026-09-30/task/build-lease.py \
  --label cursor-intercom-tests \
  --receipt …/Packages/IntercomDomain/evidence/lease-receipt-r4-<UTC>.json \
  --wait-seconds 600 \
  -- /usr/bin/env DEVELOPER_DIR=/Applications/Xcode-27-RC.app/Contents/Developer COPYFILE_DISABLE=1 \
     swift test --jobs 1 -Xswiftc -j -Xswiftc 1 --build-path /tmp/IntercomDomain-swift-build
```

Raw log + command record under `evidence/raw/`. Fill receipt/hash lines after lease completes.

## Preserved earlier evidence

| When | Exit | Artifact | Note |
|---|---:|---|---|
| 22:14:33Z | 0 | `swift-test-jobs1-2026-09-30T22-14-33Z.log` | 29 XCTest baseline |
| 22:22:11Z | 0 | `swift-test-r2-fix-…` | r2 init demotion fix 30/30 |
| 22:24:31Z | 0 | `swift-test-r2-scopes-…` | r2 grant scopes (R3 source) |

## Unmet limitations (explicit)

1. Exact **grantID + approvalRevision** audit binding on claim/handoff audits — schema-v1 fields absent; pending
2. Host **namespace / task scope** isolation — host-owned
3. **Old-claim regrant/reclaim** after **owner** grant revocation — still needs a fresh active scoped grant (cancel does not revive)
4. Concurrent **cross-process flock** stress tests — absent
5. **Power-loss durability** — no claim without host fsync/crash proof
6. **NativeAdapterAuthority** public ctor is trusted **HOST ONLY** — not user auth; SandboxStore mint unproven
7. Package XCTest PASS ≠ workbook acceptance ≠ Build8 ready ≠ publishable unit; native authentication / remote transport outside / unproven
8. Recovery is **bounded cancel→reassign only** — not broader revocation-recovery-complete; **no** acceptance claim

## Tokens

unknown
