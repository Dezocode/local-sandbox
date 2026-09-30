# IntercomDomain handoff

## Canonical IDs

B8INTERCOM01 · B8INTERCOM02 · B8INTERCOM03 (workbook rows owned by main; this file is package evidence only)  
**B8-INTERCOM-RECOVERY** — bounded cancel→re-offer unit (**no acceptance claim**)

## Owner / status

- **Package owner:** Cursor Intercom worker (`Packages/IntercomDomain/` exclusive)
- **Admitted task (UI):** 2026-09-30T20:42Z
- **First artifacts:** Package/Models **20:53:11Z**; Persistence/Engine **20:54:54Z**
- **Skill:** `build8-intercom` (project-local) — recovery guards recorded
- **R3 (preserve; never overwrite):** review zip SHA-256 `3ee0c1ae15ecae6410bfac17639782e6eebd3709f25e9c2d9e329547ff4e0e47`
- **R4 recovery milestone (implementation + leased XCTest):** cancel uncompleted handoff attempt + re-offer to already-authorized agent; **45 XCTest / 0 failures**
- **FULL PACKAGE acceptance:** **PENDING** (not claimed)
- **Not claimed:** Build8 ready, publication, native auth, remote transport, revocation-recovery-complete beyond this bounded path

## B8-INTERCOM-RECOVERY behavior

- `AuditAction.cancelHandoff`; offer `receiptID` = attempt id; `claim.handoffHops` only on complete
- Engine: `cancelHandoff(receiptID, expectedRevision, actor)`; idempotent if already revoked; denies completed
- `revokeGrant`: same-txn durable cancel evidence for affected open offers, then revoke — no ownership transfer / grant revive
- Validate: forged cross-goal/task cancel, duplicate cancel, reorder, completed+cancel fail closed
- After cancel (owner grant still active), new offer to another agent with valid scoped active grant is allowed

## R4 leased suite (authoritative)

```text
python3 /Users/dezmondhollins/Documents/Codex/2026-09-30/task/build-lease.py \
  --label cursor-intercom-tests \
  --receipt …/Packages/IntercomDomain/evidence/lease-receipt-r4-2026-09-30T22-49-34Z.json \
  --wait-seconds 600 \
  -- /usr/bin/env DEVELOPER_DIR=/Applications/Xcode-27-RC.app/Contents/Developer COPYFILE_DISABLE=1 \
     swift test --jobs 1 -Xswiftc -j -Xswiftc 1 --build-path /tmp/IntercomDomain-swift-build
```

- Window: **2026-09-30T22:49:34Z–22:49:40Z**
- Wrapper exit **0**; status **FINISHED**
- waitSeconds **0.000482**; executionSeconds **5.739709** (wait ≠ execution)
- Result: **45 XCTest / 0 failures** (prior 35 retained + recovery 36–45)
- Raw: [`evidence/raw/swift-test-r4-2026-09-30T22-49-34Z.log`](evidence/raw/swift-test-r4-2026-09-30T22-49-34Z.log)  
  SHA-256 `a300e1ed75063edb6eaa7a4f03a68f1da5468beff061efd6e73c0b0e33a0e2f3`
- Command: [`evidence/raw/command-r4-2026-09-30T22-49-34Z.txt`](evidence/raw/command-r4-2026-09-30T22-49-34Z.txt)  
  SHA-256 `007cbacb8842ca89b0acccce5ebcbfe23e4b90cd682311f8caa27af05c83f392`
- Receipt: [`evidence/lease-receipt-r4-2026-09-30T22-49-34Z.json`](evidence/lease-receipt-r4-2026-09-30T22-49-34Z.json)  
  SHA-256 `0bc30243b23dbe90b43c297c8ce6e6534ebab8ac64b2e5134a0d5a4dc295b1db`

Earlier R4 compile failures (await-in-autoclosure) preserved as failed receipts `…22-48-38Z` / `…22-49-13Z` — not PASS.

## R4 source hashes (no acceptance claim)

```
56cc3122068b98e42d32d4f0688cdb39dc28baf3dcbe04fd04299c17fdf7c697  Package.swift
ff9952486083175bd2610d313ffaab23953d8b114af7db074ff99a203ded7b75  Sources/IntercomDomain/Models.swift
69ac50576e947c4928624a51cf974450492ed7f106624778c6de996b00cdb5d2  Sources/IntercomDomain/Persistence.swift
e04b6ce9f7cfa705c7bfa5def0363da2371ccbff3a4811aeb45d918ad2c9f9a8  Sources/IntercomDomain/IntercomDomainEngine.swift
1f85c9c6e501b4a0aef21b6896c860e30d15d77b012ec3dfa571a5fe889faa18  Tests/IntercomDomainTests/IntercomDomainTests.swift
3aeeb46166d1e2d958ba85d929f7aa32eac7c6c359c8ebc7f841ef7f419c5597  Tests/IntercomDomainContracts/main.swift
```

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
