# B8INTERCOM03 — Persistence CAS and XCTest evidence

- **Owner:** Cursor Intercom package worker
- **Slot:** **RELEASED** 2026-09-30T21:46:58Z — no further reruns
- **Authoritative raw transcript:** [`raw/swift-test-j1-2026-09-30T21-45-57Z.log`](raw/swift-test-j1-2026-09-30T21-45-57Z.log)
- **Log SHA-256:** `b67f91306576b7842740affd5216e000ed8584ddd4542d4b27f0888046c077cc` (4322 bytes)
- **UTC:** `2026-09-30T21:45:57Z` → `2026-09-30T21:45:59Z` · **EXIT 0**
- **Result in log:** `Executed 13 tests, with 0 failures` (XCTest). Portable runner not acceptance.
- **Failed-run history:** [`raw/README.md`](raw/README.md)
- **Native auth gap:** `NativeAdapterAuthority` is not user/session authentication; SandboxStore mint after real auth is main-owned and unproven.

## Delivery timestamps (evidence-corrected)

| Event | UTC |
|---|---|
| Admitted task (UI 3:42 PM) | 2026-09-30T20:42Z (minute) |
| First artifacts Package+Models | 2026-09-30T20:53:11Z |
| Persistence+Engine | 2026-09-30T20:54:54Z |
| Initial review/send bracket | 2026-09-30T20:54:54Z–20:57:45Z |

## Source / log hashes at release

```
bb2a0cb438b48eb9e5a53901dd279da9ca0445582f61db1877b8beb4da6ad56c  Sources/IntercomDomain/IntercomDomainEngine.swift
ef5538b3ee5c2d5c5b08e302c473116f15eff6516964d0e3bef4995ad6795caa  Sources/IntercomDomain/Models.swift
03777c3bb0620487de413699e89d5621b96ffa63086179ffe1c9d1fb0c24a8dd  Sources/IntercomDomain/Persistence.swift
7a3cb599019bb783dcceac7439092de6020fa4e2169276829dbe64a8d3a7eddc  Tests/IntercomDomainTests/IntercomDomainTests.swift
56cc3122068b98e42d32d4f0688cdb39dc28baf3dcbe04fd04299c17fdf7c697  Package.swift
b67f91306576b7842740affd5216e000ed8584ddd4542d4b27f0888046c077cc  evidence/raw/swift-test-j1-2026-09-30T21-45-57Z.log
```
