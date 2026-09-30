# B8INTERCOM02 — Approvals and trust boundary

- **Owner:** Cursor Intercom package worker
- **Guard:** Decoded `Principal.nativeAdapter` is not authentication; privileged APIs require non-Codable `NativeAdapterAuthority`
- **Gap:** Authority init does not prove native user/session checks (adapter dependency)
- **Paths:** `Models.swift` (`NativeAdapterAuthority`, `UserApprovalReference`), engine privileged APIs
- **Tests:** `test06`, `test07`, `test08`, `test13` (restore/scope/revocation)
