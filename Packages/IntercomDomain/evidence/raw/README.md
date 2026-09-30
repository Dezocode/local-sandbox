# Scoped swift test raw transcripts

Full stdout+stderr for lease-wrapped package tests under
`DEVELOPER_DIR=/Applications/Xcode-27-RC.app/Contents/Developer`.
UI chat truncation is not evidence; these files are.
Lease status comes from wrapper exit + receipt JSON only (not process inspection).

**Freeze:** after 2026-09-30T22:14:33Z milestone — no further package builds unless review requests.

| UTC start | UTC end | Exit | waitSeconds | executionSeconds | Log / receipt | Note |
|---|---|---:|---:|---:|---|---|
| 2026-09-30T21:45:57Z | 2026-09-30T21:45:59Z | 0 | n/a (pre-lease) | n/a | `swift-test-j1-2026-09-30T21-45-57Z.log` (`b67f9130…`) | preserved original **13/13** narrow PASS |
| 2026-09-30T22:11:31Z | 2026-09-30T22:11:32Z | **64** | 0.609 | 0.127 | `lease-receipt-…22-11-31Z.json` + `swift-test-j1-…22-11-31Z.log` | preserved FAILED: glued `-j1` |
| 2026-09-30T22:11:43Z | 2026-09-30T22:11:46Z | **1** | 0.0007 | 2.175 | `lease-receipt-…22-11-43Z.json` + `swift-test-j1-…22-11-43Z.log` | preserved FAILED: Engine bare `throw` |
| 2026-09-30T22:13:39Z | 2026-09-30T22:13:47Z | 0 | 0.0005 | 8.045 | `lease-receipt-…22-13-39Z.json` + `swift-test-j1-…22-13-39Z.log` | 29/29 spaced `-j 1` (superseded spelling) |
| 2026-09-30T22:14:33Z | 2026-09-30T22:14:37Z | **0** | **0.000471** | **4.130309** | `swift-test-jobs1-…22-14-33Z.log` (`e649c64b…`) + receipt (`28cef04b…`) + `command-…22-14-33Z.txt` (`f2f0342a…`) | **freeze milestone:** `--jobs 1 -Xswiftc -j -Xswiftc 1`; 29/29; FULL PACKAGE acceptance pending |

Latest symlink: `swift-test-j1-latest.log` → `swift-test-jobs1-2026-09-30T22-14-33Z.log`.

## Jobs distinction (corrected claim)

- `swift test --jobs 1` — SwiftPM **package** job parallelism.
- `-Xswiftc -j -Xswiftc 1` — swiftc **compiler** parallel-command count (`-j <n>` per `swiftc -help`).
- **Not** single-core proof.
