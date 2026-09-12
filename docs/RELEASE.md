# Release evidence and remaining gates

Version 0.3 engineering qualification in progress, 10 September 2026. This document does not claim that the release gates have passed.

## Evidence categories

| Goal | Current artifact | Remaining gate |
|---|---|---|
| Oracle guidance | Built-in task packet compiler and compact policy | Live frontier model qualification |
| Account identity | ChatGPT host identity; standalone or linked Apple web sessions; no email merge | Registered production Apple identifiers, secrets, domain, and live account tests |
| Native bearer | Nonce-bound Apple exchange; journaled pending-to-active handshake; receive-time expiry validation; exact-token retirement queue | Production Apple exchange, deployed retention Cron, and signed-device activation, refresh, lock, background, and revocation tests |
| Dashboard | Nested iOS-style views, durable state, file edits, receipts, and encrypted draft journal | User acceptance and browser lifecycle tests on the target phone |
| Shortcuts | Nine iOS 26 App Shortcuts, including Begin Provider Check, Record Provider Check, Qualify Apple Intelligence, and Apply Oracle Recommendation. iOS 27 also adds Run Long Apple Task | Automatic native registration plus Apple-confirmed personal Shortcut installation and device testing |
| File sandbox | D1 owner-scoped workspace; recursive native scoped-folder implementation | Real iCloud conflict, symlink, provider, and revocation tests |
| Autosave | Journal-first 650 ms coordinators for the dashboard, local vault, and native editor | Browser suspension and native crash, relaunch, conflict, and storage-pressure tests |
| Encrypted sync | Client-side AES-GCM records, recovery envelopes, stable pages of at most four records, and mutation revisions | Live cross-device recovery, mutation, loss, and 512 KiB transport tests |
| Resource consent | Saved sliders and portable policy; native admission/monitor | Device memory, battery, and thermal validation |
| Retry behavior | Exact patches, version/hash checks, pending call journal | Crash injection on device |
| Micro-model workflow | One-action contract, bounded inputs, compact state | Locally AI / LM Link benchmark |
| Provider qualification | Every task route requires five exact probes, protected device-local epochs, 80% schema and assertion thresholds, sufficient context/tool coverage, zero integrity faults, and deterministic ranking | Physical-device runs against the installed Apple runtime and provider actions |
| Subscription apps | ChatGPT/Grok/Grokbot/Claude named Shortcuts, no model APIs | Verify actual installed app actions and text return |
| Apple Intelligence | Runtime-aware direct route plus iOS 27 `LongRunningIntent` execution | Supported device and enabled model |
| Native background | Bounded `BGProcessingTask` continuation for approved Apple Intelligence runs | Physical-device scheduling, expiration, lock, and exactly-once completion tests |
| Siri | Native App Shortcuts with a payload-only configured-provider handoff | Voice and Share Sheet acceptance |
| iCloud | Folder picker, bookmark, coordinated reads/writes | User folder selection and device validation |
| Native app | Xcode project, source, icons, privacy manifest, and portable Swift contract suites | Full Xcode build, simulator tests, signing, TestFlight, regression, and accessibility testing |
| GitHub sync | Dashboard proxy, direct local client, native client, conflict-checked commits, and worktree patch importer | Live account tests and source repository publication |
| Cursor Origin | Owner-bound hosted installation, repository discovery, and manual read-only mirror refresh | Production Origin App credentials and live repository tests |
| Deployment split | Hosted capabilities and generated static self-host capability manifest | Safari Home Screen and deployed static-package smoke tests |
| App Store | Submission checklist | Metadata, privacy review, signed archive, review approval |

## Required Apple acceptance

- Keep `UILaunchScreen` (or an approved launch storyboard) in the submitted app metadata when building with the iOS 27 SDK, as required by [Apple TN3208](https://developer.apple.com/documentation/technotes/tn3208-preparing-your-apps-launch-screen-to-meet-app-store-requirements). The generated and checked-in `Info.plist` use `UILaunchScreen`, and the Xcode metadata contracts guard it. That source check does not replace App Store Connect acceptance of the signed archive.
- Build and run on the actual iPhones with your developer team. Record each exact hardware model and OS from Xcode `devicectl`; the app's `UIDevice` label is only a generic product family. On iPhone 18 Pro Max, complete one bounded Foundation Models task online and in Airplane Mode. Select a lower-device test phone, such as an iPhone 14 Pro, explicitly before testing; prove the unavailable Apple path and complete the same workspace task through a configured native Shortcut. Preserve the iOS 26 deployment target, explicit provider selection, and cloud-consent boundary.
- With Xcode 27 and a signed iOS 27 device, verify `LongRunningIntent.performBackgroundTask`, progress reporting, and cancellation that leaves a reviewable checkpoint with no later side effect. Separately on iOS 26, verify Siri discovery of Begin Oracle Task, Run Bounded Task, and Apply Validated Action and complete the payload-only provider loop.
- Confirm that installing the native app registers all nine iOS 26 App Shortcuts. iOS 27 adds Run Long Apple Task as the tenth action. A personal provider Shortcut does not count as installed until the user reviews it and confirms Apple's Add Shortcut and permission screens.
- From a locked iPhone, invoke each protected App Intent and cancel the local unlock; verify zero file, qualification, routing, or checkpoint mutation. Repeat after successful local unlock. An invocation from an unlocked Watch must still require the executing iPhone to unlock. For Begin → lock → Apply and Begin Provider Check → lock → Record Provider Check, verify pending state survives unchanged until local unlock. Open Local Sandbox may run while locked only while its intent body remains data-free.
- For each provider, run `strict-json`, `read-tool`, `list-tool`, `patch-tool`, and `bounded-context` through the exact installed action. Use Begin Provider Check and Record Provider Check for external apps. Run the Apple suite from Apps & Shortcuts, then use Apply Oracle Recommendation only after qualification.
- Require all five completed probe types, at least an 80% local schema-validation pass rate, at least an 80% exact-assertion pass rate, and zero integrity faults. The first suite requires at least four schema-valid responses and four passing assertions. Every task route, including direct Apple Intelligence, requires that full base qualification plus all three tool probes and enough tested context for that task. An external Siri route also requires an observed App Intent return for every probe. Treat that value only as evidence that returned text reached Record Provider Check. Do not treat it as proof of unattended execution, the response source, the provider account, or the active model. Manual-return routes are never eligible for unattended Siri. Capture live physical-device evidence for unattended acceptance.
- Keep evidence for seven days within one device, full OS major, minor, and patch version, OS build descriptor, app version and build, provider, and adapter name and mode epoch. Store at most 240 attempts in the protected ledger. Admit at most one attempt for each provider, probe, and UTC day. Score only the 20 freshest attempts in the window.
- Verify the deterministic rank order: schema-validation rate, then assertion pass rate. For equal external-provider scores, use lower observed App Intent round-trip time in 500 ms buckets. Record Apple in-process model time separately and never compare it with the external round trip. Use Apple Intelligence, Locally, ChatGPT, Claude, Grok, and Grokbot as the remaining fixed tie order. Do not label either timing as pure provider inference latency. Saved and explicit routes never substitute. Best local considers only Apple Intelligence and Locally. Its cold start applies only while neither has comparable evidence: it targets available Apple, otherwise Locally, but blocks execution until that route has a current task-qualified suite. As soon as either has comparable evidence, it uses the measured rank and blocks if its selected route does not qualify. No route may switch provider after the first action.
- Confirm that each external provider owns its authentication and subscription. Local Sandbox must claim only local validation of a user- or Shortcut-returned challenge response, never provider login state, response origin, or personal Shortcut contents. Capture live visual evidence on the physical device showing the provider app, selected action, reviewed Shortcut, and returned result. Verify that the dashboard shows only Local Sandbox's own run and ordered handoff-hash evidence, not another provider app's live activity or cross-app telemetry.
- Test standalone web Apple sign-in, deliberate linking to a ChatGPT-owned workspace, owner-conflict rejection, token refresh, and revocation.
- Test native nonce binding, identity-token replay rejection, schema-v2 pending exchange, exact pending-journal readback, active-only sync and refresh, and 15-minute bearer expiry. Keep admission blocked during the foreground Apple credential check, activation replay, and mandatory fresh server refresh. Exercise response latency and the 30-second server-ahead skew bound. Confirm that concurrent same-token refreshes retain the later valid expiry and that a stale response cannot restore authority after Lock.
- Confirm that explicit Lock and disconnect use one serialized capture, batch stage, and checked handoff for every pending or active session before any matching bearer or journal clear. Force each checked read, queue write, readback, and remote revoke failure. A failed stage must leave the original evidence stored and blocked. A failed revoke must leave the exact queue evidence for proactive and manual retry. Confirm that a successful retry removes only the matching debt, that unrelated queue entries remain, and that device wall-clock changes never clear debt. Treat queue `expiresAt` only as a conservative server-grant horizon.
- Force a post-exchange failure in pending-journal persistence, durable staging, and remote revocation. Confirm `APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED`, no local admission, pending-session denial for sync and refresh, and durable server retention until provider revocation succeeds. Confirm that background removes in-memory and admission authority while retaining exact Keychain evidence. Confirm that profile cleanup verifies non-identity state before its identity-last commit, and that the native UI disables conflicting lifecycle controls throughout an Apple authorization ceremony. Exercise deletion-attempt schema v3 with its exact bearer expiry and a legacy schema-v2 discard with the conservative attempt-deadline plus 30-day and 30-second fallback.
- Select only the intended LocalSandbox folder and verify access after relaunch.
- Create, read, append, patch, and read back the test file.
- Interrupt native autosave before and after its guarded write. Verify journal recovery, uncertain-write readback, retry, and conflict review.
- Enroll two devices in one encrypted workspace. Verify recovery, manual pull and push, deletion tombstones, conflict review, one snapshot restart, recovery-credential rotation, staged iCloud recovery reconciliation, workspace-scoped hosted deletion, and lost-key behavior. Confirm a stale snapshot blocks both rotation and deletion. Confirm hosted deletion retains local Files and iCloud documents.
- Reject traversal, encoded separators, symlink escapes, invalid JSON, unknown tools, missing hashes, stale hashes, and ambiguous patch matches.
- Cancel during model generation; verify no later tool side effect.
- Interrupt before and after a file write. Inspect the checkpoint and pending journal before recovery.
- Exercise the registered `BGProcessingTask` on a physical device. Verify safe `planning`/`ready` resume, `executing` review-only behavior, expiration cancellation, locked-device deferral, exactly-once completion, and the recorded Settings status.
- Check resource admission at battery reserve and thermal pressure. Record that app memory excludes other processes.
- Test Apple Intelligence unavailable, cloud disabled, app handoff failure, and missing external local app.
- Test notification denial, Files revocation, offline iCloud file availability, and storage pressure.
- Verify VoiceOver, Dynamic Type, landscape, iPad layouts, and touch targets.
- Use the same held-out task suite for each model and report failures as part of the denominator.

## Required hosted and static acceptance

- Configure the production Apple Services ID, native client ID, redirect URI, signing key, storage key, and D1 migrations. Before any live auth, read the target D1 migration and table provenance. Accept a pristine 0000 target only when it receives the complete 0001–0014 chain. You may also apply 0014 to a target already proved complete through 0013, or use a target already proved complete through 0014. Stop for manual review if auth tables or partial auth migrations exist without a complete 0013. The release precondition is that no auth-capable 0011 or 0012 worker was ever live. Never roll back to one.
- After applying through 0014, read `apple_auth_admission_cutover` directly from D1 and wait until wall-clock time is strictly greater than its server-created five-minute future cutoff. Only then deploy and read back the first auth-capable, 0014-aware worker. Confirm that migration 0014 copied legacy native sessions as `active` and that an omitted activation state defaults to `pending`. Confirm that pre-cutover web and native sessions and grants require reauthentication, then run the live web and native flows in `APPLE-AUTH.md`.
- Read back the deployed `17 * * * *` Cloudflare Cron Trigger and observe a real scheduled firing against disposable lifecycle rows. Confirm that pending sessions never authorize sync or refresh and that the provider-backed retention path keeps failed grant revocations for another run. Source, Miniflare, and built-worker tests do not satisfy this production gate.
- Test the dashboard with both ChatGPT and standalone Apple identity. Confirm that a mismatched pair fails instead of merging owners.
- Test dashboard GitHub polling only while its page is visible. Test that the local app performs only user-initiated direct GitHub requests.
- Configure a production Cursor Origin App. Verify owner binding, opaque-path repository discovery, manual mirror refresh, disconnect, exact manual-cleanup acknowledgement, delayed-callback rejection across the 60-second receipt-skew fence, later re-consent, and that no installation credential reaches the browser.
- In a disposable migrated D1 database, delete and re-enroll the same sync workspace. Confirm that the old epoch is rejected, a fresh epoch receives a new incarnation, and account deletion removes the retained history. Set disposable file and sync revisions to `9007199254740991`. Confirm that the next write fails without changing storage. Corrupt one active history tuple and one stored envelope, then confirm that the API returns `SYNC_STORAGE_INTEGRITY` without returning ciphertext metadata.
- Run `scripts/release/selfhost.py`, deploy the generated ZIP, and test it as a separate HTTPS origin. Confirm that direct GitHub remains available while Cursor Origin and encrypted server sync remain disabled.
- Test Safari storage persistence, multi-tab autosave conflicts, suspend and resume, offline launch, update, encrypted export and restore, quota failure, and clearing website data.

## Authorize the Apple release action

Keep the `apple-release` GitHub environment approval enabled. Add `APPLE_ACTION_READINESS_JSON` as a secret in that environment. The workflow reads this protected input in the **Validate protected Apple action readiness** step and again only in the final **Archive or upload** step. That final read prevents a locally forged receipt from replacing the protected record. The workflow does not expose the App Store Connect private key, key ID, issuer ID, team ID, or bundle ID until the first protected-record check passes.

The canonical tracker is `qualification/Local-Sandbox-0.3-Progress.xlsx`; its deterministic, privacy-bounded companion is `qualification/Local-Sandbox-0.3-Progress.snapshot.json`. Generate the snapshot only from the sanitized workbook, review and commit both files, then verify the exact committed pair:

```bash
python3 scripts/release/tracker.py snapshot \
  --tracker qualification/Local-Sandbox-0.3-Progress.xlsx \
  --output qualification/Local-Sandbox-0.3-Progress.snapshot.json
python3 scripts/release/tracker.py verify
```

The standard-library verifier rejects reordered or missing requirement rows, changed Evidence rows, stale snapshots, unsafe OOXML or formulas, stale formula results, machine-specific home paths, token-shaped secrets, generic PASS proof, an altered dependency graph, and any PASS gate with an open dependency. Its canonical-verifier stage proves workbook-to-snapshot integrity only; it does not claim Apple, GitHub, device, TestFlight, App Store, or final release readiness. The workbook and snapshot are release authorization evidence and are explicitly excluded from both distributable ZIPs.

On a successful full run, the `Release qualification tracker` check in `docs/validation.json` records the exact six-field workbook/snapshot binding returned by that verifier. The same record's `candidateDigest` hashes the sorted Git-tracked and nonignored untracked regular files by path, executable bit, size, and bytes. Only `docs/validation.json` and the canonical qualification XLSX/snapshot pair are excluded to break the validation/tracker generation cycle. Apple readiness, final Apple authorization, GitHub publication, and readiness export recompute the candidate digest and committed/current tracker pair and require both bindings byte-for-byte. Keep the flow noncircular: let the tracker cite the preceding validation evidence, commit the reviewed workbook and snapshot, rerun the full verifier so the refreshed validation binds that committed pair and current candidate, then commit the refreshed validation before exporting readiness.

Do not hand-author the protected value. Once the workbook has the exact noncircular Apple pre-action profile, export it deterministically with an explicit timestamp and commit. Replace the example timestamp with the current reviewed UTC time:

```bash
python3 scripts/release/tracker.py export-readiness \
  --profile apple \
  --tracker qualification/Local-Sandbox-0.3-Progress.xlsx \
  --expected-commit FULL_40_CHARACTER_COMMIT \
  --ready-at 2026-09-11T18:00:00Z \
  --output /absolute/path/to/apple-action-readiness.json
```

The JSON value has record type `local-sandbox-apple-action-readiness`, schema version 1, release state `READY`, and the selected version and full commit. Its exact `xcode` object is `{"version":"27.0","build":"27A266a"}`. It lists all 57 gate IDs with exactly 53 of 57 gates set to `PASS`. `REL-03` is `IN PROGRESS`; the exporter rejects a pre-passed `REL-03`. `REL-04`, `REL-06`, and `REL-07` are `IN PROGRESS` or `NOT STARTED`. Every gate carries the SHA-256 digest of its exact workbook evidence, never the evidence prose. `totalGates` is 57, `passedGates` is 53, and `completionPercent` is `92.98245614035088`.

Set `readyAt` after the timestamp in the committed `docs/validation.json` and no more than 24 hours before the run. The `tracker`, `verification`, and `artifacts` objects bind the committed workbook, snapshot, canonical table hashes, validation record, candidate digest, and three ZIP/PDF artifacts. The protected-readiness step and final authorizer independently recompute the candidate digest plus both committed and current workbook/snapshot bytes and require exact gate status and evidence-digest equality. A post-validation source change, refreshed working copy, stale snapshot, or edited protected record cannot replace the committed evidence.

After every check passes, the workflow writes `release-output/apple-action-readiness-receipt.json`. The retained workflow artifact includes this bounded receipt. It records the protected input's byte-for-byte SHA-256 digest, exact commit and version, freshness timestamps, Xcode 27.0 build `27A266a`, build number, archive/upload stage, 53-of-57 state with `REL-03` still `IN PROGRESS`, committed validation and artifact digests, and the digest of `apple-release-evidence.json`. At final action time, `apple.py` reads the actual `xcodebuild -version`, rejects every other build, and makes the authorizer parse and revalidate the protected JSON against Git and the receipt before any archive or export. It does not copy gate evidence or the protected JSON into retained files.

This record authorizes one causal Apple action. The receipt is not the final 57-of-57 qualification and neither file changes the tracker.

## Store submission

Choose your own app category, price, territory availability, support contact, and privacy-policy URL. Complete privacy disclosures for the released behavior, including optional cloud providers. Review required-reason API declarations against the exact SDK/build. Screenshots must show the actual running signed app. Resolve entitlements and signing warnings, archive, upload to App Store Connect, test with TestFlight, and submit to App Review.

The native privacy manifest is a starting declaration for this exact source. It is not a claim that a modified or cloud-enabled product collects no data. The source ships no advertising or analytics SDK. No App Store approval is claimed.

## Validation performed in the authoring environment

Run `pnpm verify` to execute the 41-stage canonical release verifier and generate `validation.json` from the checks that ran. The generated record includes the current candidate digest; promotion and release preflights recompute it and reject missing, malformed, or stale values. The 18-stage portable web roster uses the same tracker integrity stage but does not replace the macOS-native stages. The verifier never regenerates committed artifacts or tracker evidence: it independently builds the source ZIP, static self-host ZIP, and setup-guide PDF in a temporary directory and fails on any byte difference. Deliberately refresh all three with `scripts/release/regenerate.py` under Python 3.12 with Pillow 12.3.0, ReportLab 4.4.9, and pypdf 6.10.0. Set `LOCAL_SANDBOX_RELEASE_PYTHON` when that pinned environment is not the default `python3`. On Darwin, the full verifier parses all Swift sources and runs the native contract executables, including workspace preparation and bounded GitHub transport. Those checks are not a full Xcode app or simulator build. The generated record keeps the release state at `QUALIFYING` and lists live Apple, GitHub, Cursor Origin, browser, cross-device, physical-device, TestFlight, and App Store work as qualifications.

## Version 0.3 update boundary

The private website is updated in place. No new Site or empty database replaces it. Old API provider selection is normalized to ChatGPT, and its setup completion is cleared. Other resource authorization, text files, receipts, file versions, and settings revisions remain. The migrations add Apple ownership, native sessions, Cursor Origin installations, and encrypted sync state. Migration 0013 deliberately invalidates all pre-cutover Apple authorization ceremonies, sessions, and grants because erased alternate transfer aliases cannot be reconstructed safely; users reauthenticate after the five-minute rollout drain. Migration 0014 adds the pending-to-active native-session boundary while copying existing rows as active for upgrade continuity. Preserve the source-base data, but do not claim a partial-auth upgrade safe without the live D1 provenance preflight in `APPLE-AUTH.md`. Model API calls and key fields remain removed.

GitHub live writes are untested without a user-entered repository token. Transport contract checks and a real local worktree patch exercise were performed separately. They are not evidence of GitHub account authorization. The patch importer reads back actual file changes and rejects conflicts, wrong branches, tampered hashes, and symlinks.

## Bootstrap the GitHub repository before release gates

The source repository must exist before GitHub account, source-sync, Apple-workflow, and final-release gates can pass. After you choose the owner and either `private` or `public` visibility, authorize this bootstrap separately from the final release. The bootstrap does not create a tag or release.

For a new repository, run these commands with the chosen visibility. Do not run them against an existing repository.

```bash
gh repo create YOUR_GITHUB_OWNER/local-sandbox --private \
  --description 'Local-first iOS workspace with native Shortcuts and bounded agent execution'
git -c credential.helper= \
  -c credential.helper='!gh auth git-credential' \
  push --porcelain \
  https://github.com/YOUR_GITHUB_OWNER/local-sandbox.git \
  "$(git rev-parse HEAD):refs/heads/main"
gh repo edit YOUR_GITHUB_OWNER/local-sandbox --default-branch main
```

Replace `--private` with `--public` only when that is the chosen visibility. The push has no force flag and fails on a non-fast-forward update. If the repository already exists, inspect its visibility, default branch, and remote history before choosing a deliberate source-sync command. Do not use the final publisher to create or synchronize the repository.

## Publish the GitHub release

`scripts/publish-github.sh` is a dry run unless you pass `--execute`. It requires the repository to exist already. It reads back the exact visibility, `main` default branch, and selected commit before any release mutation. It also rejects a dirty worktree, a commit mismatch, changed artifacts, stale evidence, and an existing `v0.3.0` tag or release.

Generate the external JSON with `scripts/release/tracker.py export-readiness --profile github`, an explicit full commit, an explicit `readyAt`, the canonical `--tracker`, and an output path outside the repository. Replace the example timestamp below with the current reviewed UTC time. The exporter refuses until the exact noncircular profile exists: 56 of 57 gates are `PASS`, `REL-06` is `IN PROGRESS`, every gate has exact workbook evidence, and every PASS dependency is closed. The result binds the candidate digest, workbook, snapshot, Requirements and Evidence hashes, `docs/validation.json`, and the three canonical release artifacts to the exact release commit. Its 57 gate entries carry exact status and per-gate evidence SHA-256. The publisher recomputes and compares all of them and rejects post-validation source changes, a pre-passed `REL-06`, generic proof, reordered rows, altered evidence, stale or missing tracker data, or an open dependency. A nonempty signed Shortcut catalog and every cataloged package must match the bytes embedded in both release ZIPs.

```bash
python3 scripts/release/tracker.py export-readiness \
  --profile github \
  --tracker qualification/Local-Sandbox-0.3-Progress.xlsx \
  --expected-commit "$(git rev-parse HEAD)" \
  --ready-at 2026-09-11T18:00:00Z \
  --output /absolute/path/to/github-action-readiness.json
```

Run the preflight after the complete 0.3 change set is committed, synchronized to remote `main`, and the action-readiness record is less than 24 hours old:

```bash
scripts/publish-github.sh \
  --owner YOUR_GITHUB_OWNER \
  --repo local-sandbox \
  --visibility private \
  --expected-commit "$(git rev-parse HEAD)" \
  --tag v0.3.0 \
  --tracker qualification/Local-Sandbox-0.3-Progress.xlsx \
  --action-readiness /absolute/path/to/github-action-readiness.json
```

Choose `private` or `public` explicitly. The dry run writes deterministic copies, `SHA256SUMS`, release notes, and a JSON plan under `release-output/github-v0.3.0/`. Review those files, then rerun the same command with `--execute`.

With `--execute`, the script creates only the tag and release. It then reads back the repository visibility and default branch, the `main` and tag commits, the release tag, title, draft and prerelease state, and every uploaded asset's exact bytes and SHA-256 digest. Only successful readback writes `release-output/github-v0.3.0/REL-06-completion-receipt.json`. That local receipt marks only `REL-06`; it does not claim the final release is 57 of 57.

A network or service failure can leave a tag or release in an uncertain state. The script never creates or deletes a repository, updates `main`, rolls back a ref, overwrites a release, force-pushes, or retries an external mutation. After a failure, do not rerun `--execute`. Inspect the repository, `refs/heads/main`, `refs/tags/v0.3.0`, the release, and every asset against the reviewed commit and hashes. Then choose a manual recovery.

No pre-signed third-party Shortcut packages or fabricated iCloud install links are shipped. Local Sandbox's own App Shortcuts are included in the native project. Third-party action availability, one-tap shared-link installation, Apple login, and iOS 27 execution require the installed signed app and the device.

## 0.3 evidence and limits

The verifier covers release-version ownership, generated Xcode metadata, lint, TypeScript, protocol and storage contracts, portable Swift contracts on Darwin, the production web build, worker integration, source and static archives, capability manifests, and release-artifact inspection. `validation.json` owns the result of the current run. This document does not duplicate a test total or generated artifact page count.

Version 0.3 implements the standalone encrypted local vault, three journal-first autosave paths, standalone and linked Apple web identity, native bearer exchange, manual encrypted workspace sync with bounded snapshot pagination, direct and proxied GitHub clients, hosted Cursor Origin, bounded native Apple Intelligence continuation, protected native workspaces, and authenticated App Intents.

The release remains `QUALIFYING`. Xcode 27 generic iOS Release and simulator build-for-testing actions pass without warnings, but simulator runtime/test execution, signing, physical-device installation, production Apple web and native authentication, deployed Cloudflare Cron Trigger readback and firing, Face ID, iCloud Keychain and Files behavior, physical autosave recovery, `BGProcessingTask`, the iPhone 18 Pro Max on-device/offline model path, lower-device provider Shortcuts, live GitHub and Cursor Origin, Safari offline behavior, accessibility, iOS 27 device acceptance, TestFlight, App Store submission, and App Review remain unverified. Cursor Origin is a read-only repository installation, not a Local Sandbox login. The app does not claim an Apple passkey, a complete automatic repository mirror, automatic provider fallback, or a default Siri replacement. See `INSTALL-TODAY.md` for setup and constraints.
