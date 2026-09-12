# Local Sandbox 0.3: install and publish

The installer and automation suite are implemented in source. Apple signing, actual provider workflow exports, iPhone acceptance and App Store review have not been completed in this environment. The catalog deliberately contains zero packages until real signed workflows are published. This is not an App Store-approved release.

## 1. Use the Home Screen workspace now

Open the hosted `/local/index.html` in Safari. Create or unlock the encrypted local vault, then use Share → Add to Home Screen. Launch that icon. Settings detects standalone display mode and reports whether the page runs as a Home Screen app. Detection does not install the app or add permissions.

The offline shell stores application resources locally. Files, draft journals, and recorded session progress stay encrypted in IndexedDB. A 650 ms autosave journals before it changes the vault, serializes writes, detects multi-tab conflicts, and retains failed drafts for retry. Keep an encrypted backup.

The vault password is separate from web or native Apple authentication. In the hosted deployment, the local app can use the current Local Sandbox identity for manual encrypted workspace sync and a server-backed Cursor Origin connection. Direct GitHub requests come from the browser. The generated static self-host package keeps direct GitHub but has no Cursor Origin or encrypted sync service. None of these repository or sync features polls in the background.

## 2. Build and install the native app on your Mac

Prerequisites: Xcode with an SDK supporting your phone, a trusted connected iPhone, and an Apple Developer team with Sign in with Apple configured for your unique bundle ID. Run from the unzipped source root:

```sh
python3 scripts/release/apple.py check
xcrun devicectl list devices
python3 scripts/release/apple.py install --team YOURTEAMID --bundle-id com.yourcompany.LocalSandbox --device YOUR_DEVICE_ID
```

The install command builds the app, requests provisioning through your Xcode account, then uses Apple's `devicectl` to install it on the selected phone. It fails on signing or build errors. Apple login prepares an app-owned protected workspace. Optional Files or iCloud folder selection remains explicit.

To reopen an existing ChatGPT-owned workspace on native, link Apple from that signed-in web account before the first native sign-in. The first verified native sign-in for an unseen Apple subject creates a separate Apple-owned workspace. The native app binds a raw nonce to the Apple request and exchanges the identity token for a 15-minute bearer. The bearer authorizes only encrypted sync and native revocation, stays in the device-only Keychain, and clears on expiry, lock, background, or logout. A failed hosted exchange does not block local native files.

Encrypted sync is manual. It includes only non-private `workspace/` and `output/` descendants; reserved credential, profile, private-export, and signing-material paths; `.env` files; and `.cer`, `.key`, `.mobileprovision`, `.p12`, `.p8`, and `.pem` files are rejected. Choose either a random 256-bit recovery secret stored in synchronizable iCloud Keychain or a local-only passphrase. Back up the random secret if a browser must recover the workspace. Recovery rotation rewraps the same data key and uses the workspace snapshot revision as its compare-and-swap guard; it does not re-encrypt record ciphertext. iOS stages a replacement iCloud secret before the hosted update and reconciles it on the next unlock. Workspace deletion atomically removes one matching hosted recovery envelope and its ciphertext records after an explicit confirmation. It does not delete local Files or iCloud documents. Native autosave journals to the selected workspace before a 650 ms guarded write. The app requests a flush during close or scene transition, but the durable journal owns crash recovery.

To run native tests first:

```sh
xcrun simctl list devices available
python3 scripts/release/apple.py test --simulator YOUR_SIMULATOR_UDID
```

## 3. Create the real provider exports once

On an Apple device, create and test the named workflows in `release/shortcuts/recipe.json`. Use the actual actions exposed by your installed Locally, ChatGPT, Grok, Grokbot and Claude apps; keep account authentication inside those apps. Do not embed credentials, personal paths, private file contents, or prompts in distributable workflows. Export each workflow to an untracked `private-exports` directory on your Mac.

The publisher cannot invent vendor App Intent identifiers. For an app without a text-returning action, prepare a clearly labeled manual-transfer workflow instead of promising automatic tool chaining. A manual-return route may be used only in a deliberate attended flow and is never eligible for unattended Siri. Installing the native app registers Begin Oracle Task, Apply Validated Action, Begin Provider Check, Record Provider Check, Apply Oracle Recommendation, and the other declared App Shortcuts. A personal provider Shortcut still needs visible review and confirmation in Apple's Add Shortcut and permission screens. The runner's `requires` list must reflect the adapters it actually calls. Edit the recipe to match your tested stack; omit optional providers if you are not distributing them.

### Qualify each provider before applying a route

The device runs `strict-json`, `read-tool`, `list-tool`, `patch-tool`, and `bounded-context`. Use Begin Provider Check to create an external-provider challenge. Decode the result, send only `payload` to the user-reviewed provider action, then pass the provider, attempt ID, and raw response to Record Provider Check. Run the Apple suite from Apps & Shortcuts. Use Apply Oracle Recommendation only after the app reports qualified evidence. Capture live visual device evidence showing the provider app, selected action, personal Shortcut contents, and returned result; Local Sandbox cannot attest those facts itself.

The first comparable suite needs all five completed probe types. It needs at least four schema-valid responses, at least four passing exact assertions, and zero integrity faults. The protected ledger stores at most 240 attempts and admits at most one attempt for each provider, probe, and UTC day. Scores use only the 20 freshest attempts from the last seven days and require both pass rates to remain at or above 80%. Every task route, including direct Apple Intelligence, requires that full base qualification plus all three tool probes and enough tested context for that task. An external Siri route also requires an observed App Intent return for every probe. The observation records only that returned text reached Record Provider Check. It does not prove unattended end-to-end execution, the response source, the provider account, or the active model. Live physical-device evidence qualifies unattended operation. The device profile, full OS major, minor, and patch version, OS build descriptor, app version and build, provider, and adapter name and mode define the epoch.

The app ranks eligible providers by schema-validation rate and assertion pass rate. Equal external-provider scores then use lower observed App Intent round-trip time in 500 ms buckets. Apple records in-process model time, which is not compared with an external round trip. Remaining ties use Apple Intelligence, Locally, ChatGPT, Claude, Grok, and Grokbot. Neither timing is pure provider inference latency. Saved and explicit choices stay pinned. Best local considers only Apple Intelligence and Locally. Its cold start applies only while neither has comparable evidence: it targets available Apple, otherwise Locally, but blocks execution until that route has a current task-qualified suite. As soon as either has comparable evidence, it uses the measured rank and blocks if its selected route does not qualify. Each task fixes its route before the first action and cannot switch providers mid-run. Provider authentication remains inside the provider app. Local Sandbox validates only the user- or Shortcut-returned response against its local challenge and assertions; it does not prove provider login, response origin, or Shortcut contents. The native app gates new work using its own provider-qualification, native-run, pending-response, and applying-response state. After deliberate terminal-receipt import, the dashboard shows validated route and handoff evidence; it does not receive live native or provider activity. iOS does not expose another provider app's live model activity.

```sh
python3 scripts/release/shortcuts.py --exports private-exports --base-url https://YOUR_DOMAIN/shortcuts --check
python3 scripts/release/shortcuts.py --exports private-exports --base-url https://YOUR_DOMAIN/shortcuts
```

The first command checks inputs. The second uses Apple's `shortcuts sign --mode anyone`, stages signed `.shortcut` files in an immutable version directory, computes SHA-256 and byte counts, then atomically publishes the catalog. Apple receives the workflow for validation during signing. No private exports or signing credentials enter the source ZIP. A successful signing operation is not a successful device test.

Deploy the generated `public/shortcuts` directory to that same HTTPS base URL. In the website, open Install Shortcut packages. In the native app, open Set up Shortcuts → Install Shortcut packages and import `catalog.json`. Each Add Shortcut button opens the actual package URL. Apple presents its import and permission flow, and the user must confirm it. Complete the five-probe qualification in provider settings. Catalog hashes are release metadata; the current installer delegates signed-workflow validation to Apple, and does not claim a returned execution receipt from opening the link.

## 4. Self-host the local web application

```sh
python3 scripts/release/selfhost.py
```

Unzip `public/downloads/Local-Sandbox-Selfhost.zip` on your server. Set `LOCAL_SANDBOX_DOMAIN` to your own domain, point its DNS at the host, allow ports 80/443, and run:

```sh
export LOCAL_SANDBOX_DOMAIN=YOUR_DOMAIN
docker compose up -d
```

Caddy serves the static client and signed package catalog with HTTPS. There is no workspace database, identity service, or model API on that server. User content stays in each device's encrypted browser vault. Direct GitHub remains available because the browser calls `api.github.com`. The packaged capability manifest disables Cursor Origin and encrypted server sync. The package includes no Apple OAuth backend. Genuine Apple web identity requires a separate server deployment. Moving between origins requires encrypted export and restore. A Home Screen app cannot mount the native app's private directory.

The package pins the official multi-platform `caddy:2.11.4` image to OCI index digest `sha256:13ba145cba2f3e28fa801994876e4c086d1b95d5aa2a520a734765ffb6b12017`. Docker Hub reported active Linux images for amd64, arm64/v8, arm/v6, arm/v7, ppc64le, riscv64, and s390x under that index on 10 September 2026. Review the official tag record and update both the version and digest deliberately when upgrading. Preserve the previous static package and encrypted client backups when updating; rolling back the shell must not clear browser data.

## 5. Upload through Apple's distribution channel

Create the app record in App Store Connect, enable the bundle ID's required capabilities, and resolve agreements. Use the protected `Package native release` workflow for the normal archive or upload path. A direct local archive or upload is fail-closed: the canonical preflight must first write both `release-output/apple-release-evidence.json` and `release-output/apple-action-readiness-receipt.json` for the same clean commit, 0.3.0 version, Xcode 27.0 build `27A266a`, three-part build number, stage, validation record, artifact bytes, and the committed `qualification/Local-Sandbox-0.3-Progress.xlsx` plus deterministic snapshot. Create the protected value with `scripts/release/tracker.py export-readiness --profile apple`; the exporter and both Apple authorization checks recompute exact gate status and per-gate evidence digests and reject stale snapshots or open PASS dependencies. The same byte-for-byte `APPLE_ACTION_READINESS_JSON` value must remain in `LS_APPLE_ACTION_READINESS_JSON` for the final local command; a receipt alone cannot authorize it. The receipt expires after 24 hours. The local command uses your Xcode account, or an App Store Connect API key supplied through `LS_ASC_KEY_PATH`, `LS_ASC_KEY_ID`, and `LS_ASC_ISSUER_ID`. Keep the `.p8` outside the repository.

```sh
python3 scripts/release/apple.py archive --team YOURTEAMID --bundle-id com.yourcompany.LocalSandbox --build-number RUN.ATTEMPT.0 --release-commit FULL_40_CHARACTER_COMMIT --release-version 0.3.0
# For an upload, repeat the canonical preflight with a new unused three-part build number and stage=upload.
python3 scripts/release/apple.py upload --team YOURTEAMID --bundle-id com.yourcompany.LocalSandbox --build-number RUN.ATTEMPT.0 --release-commit FULL_40_CHARACTER_COMMIT --release-version 0.3.0
```

Upload builds and exports an archive with destination upload. `apple.py` first reads and records `xcodebuild -version`, then refuses anything other than Xcode 27.0 build `27A266a`. Before SDK inspection, archive, or export, it rechecks the protected readiness bytes and both preflight files against Git, the current validation file, and all three release artifacts. A missing, stale, forged, or mismatched authorization stops before build work. Upload does not submit metadata or assert approval. Check processing in App Store Connect and qualify the build with TestFlight. App Store Connect requires real screenshots, support and privacy URLs, an app description, an age rating, export-compliance answers, privacy declarations, pricing and availability, and review access instructions. These declarations must describe the actual app, including optional cloud-provider handoffs and GitHub sync. Portable Swift contract checks do not qualify the full Xcode app or its UI.

For repeatable GitHub automation, configure the `apple-release` environment with variables `APPLE_TEAM_ID` and `APPLE_BUNDLE_ID`. Add the `ASC_KEY_P8`, `ASC_KEY_ID`, and `ASC_ISSUER_ID` secrets. Keep required reviewers on that environment. Run `Package native release` from `main`, then enter the full 40-character commit SHA shown for that dispatch and the exact release version. The workflow refuses a different commit, a dirty checkout, or a version that differs from `package.json`.

The workflow uses the mutable `xcode-27` runner label but fails unless `xcodebuild` reports exactly Xcode 27.0 build `27A266a`, Apple's Xcode 27 RC. GitHub's underlying hosted image revision can change. A runner still carrying a beta build stops before release evidence or credentials. The evidence file, protected readiness record, final receipt, and local authorizer all bind that exact version and build. Read the logged Xcode version and SDK list for each release. The workflow pins every imported action to a full commit SHA.

The automated build string is `run_number.run_attempt.0`. The run number must be 1 through 9,999, and the attempt must be 1 through 99. The final component is zero. These limits keep all three components within Apple's conservative four-digit, two-digit, and two-digit bounds. GitHub assigns a new run number to each workflow run and increments the attempt for each rerun, so the pair is unique in this workflow. Do not assign the same three-component form to a manual build for the same release version.

Before signing, the job checks the exact Xcode RC, installs locked dependencies, runs `pnpm run verify`, runs the native simulator suite, and reads the generated passed validation record. The full verifier checks the committed source, self-host, and guide artifacts for byte-level freshness. The job stops if any source other than `docs/validation.json` changes during verification. Only then does it write the App Store Connect `.p8` to the temporary runner with mode `0600`. The cleanup step runs even after a signing failure. The retained release output includes the archive or export and an evidence file that binds its commit, version, Xcode version and build, build string, validation record, and artifact hashes. The workflow requires this source in your GitHub repository and a configured environment. Apple can require more provisioning or signing setup on the hosted runner.

App Review approval and timing are Apple's decision. No automation can promise approval today. A locally installed development build and a Home Screen web app do not wait for App Store review.

## 6. Background behavior and recovery

Use foreground execution for provider app switches and interactive Shortcuts. Native Apple Intelligence runs save a versioned continuation before planning and before any tool call. A `BGProcessingTask` may resume only a `planning` or `ready` checkpoint whose saved authorization still matches. Resume compares a canonical digest of the full checkpoint and rejects a replacement even when its run ID, step, and phase match. After every model return and before each dispatcher side effect, the runner revalidates saved authorization and current app-owned activity, device, configuration, qualification epoch, Oracle pin, and route evidence. A changed value stops the run. An `executing` checkpoint requires human review, so an interrupted side effect is never replayed automatically.

iOS decides whether and when a processing request runs and may end a grant after minutes. The expiration handler cancels model generation, records the result, completes the system task once, and submits one later request only when the saved checkpoint is safe. Complete file protection blocks workspace and Keychain access while the device is locked. External selected folders request network availability; provider-app handoffs never run unattended. No audio, location, or other unrelated mode is used to keep the process alive. This is bounded recovery, not a continuously running daemon.

Autosave and encrypted workspace sync never run in `BGProcessingTask`. The native editor requests a foreground flush when the scene changes or closes, then relies on its journal if iOS suspends the app. Dashboard and local-web autosave also depend on their journals when the browser suspends a page.

## 7. LocalSend

LocalSend can transfer encrypted backups, catalogs, and signed Shortcut exports over a local network. It does not install Shortcuts, unlock another app's filesystem, provide Apple login, or grant background execution. Transfer encrypted backups rather than plaintext user data. This suite requires no LocalSend dependency.

## Release sequence and remaining gates

| Order | Deliverable | Evidence required |
|---|---|---|
| 1 | Hosted and static web clients | Build, capability contracts, Safari lifecycle, offline, autosave, and deployed static-package tests |
| 2 | Native development install | Successful signed build and actual device installation |
| 3 | Apple identity and local protection | Standalone/link/native login, revocation, lock/unlock, restart, and key-loss tests |
| 4 | Real Shortcut packages | Export, Apple signing, Apple-confirmed installation, five-probe qualification, text return, and file readback |
| 5 | Encrypted sync and iCloud recovery | Two-device enrollment, pagination, conflict, offline, revocation, and lost-secret tests |
| 6 | GitHub and Cursor Origin | Scoped live authorization, direct and proxied GitHub, Origin mirror, conflict, and disconnect tests |
| 7 | Apple production identity | Registered Services ID, domain, native client ID, server secrets, and live web and native qualification |
| 8 | TestFlight | Build processing and physical iOS 27 acceptance; unavailable-provider cases |
| 9 | App Store | Complete metadata, submitted review, Apple's decision |

## Primary sources checked 10 September 2026

- Apple Shortcuts for Mac, **Signing shortcuts from the command line**: https://support.apple.com/guide/shortcuts-mac/run-shortcuts-from-the-command-line-apd455c82f02/mac
- Apple App Store Connect Help, **Upload builds**: https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/
- Apple Developer, **CFBundleVersion**: https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleversion
- Apple Developer, **Choosing Background Strategies for Your App**: https://developer.apple.com/documentation/backgroundtasks/choosing-background-strategies-for-your-app
- Apple Account Help, **Associate your website to your app**: https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/
- Cursor, **Origin overview**: https://cursor.com/docs/origin
- GitHub, **GitHub-hosted runner images**: https://github.com/actions/runner-images
- LocalSend, **How It Works** and **Frequently Asked Questions**: https://localsend.org/
