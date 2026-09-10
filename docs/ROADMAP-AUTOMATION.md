# Local Sandbox 0.3: install and publish

The installer and automation suite are implemented in source. Apple signing, actual provider workflow exports, iPhone acceptance and App Store review have not been completed in this environment. The catalog deliberately contains zero packages until real signed workflows are published. This is not an App Store-approved release.

## 1. Use the Home Screen workspace now

Open `/local/index.html` in Safari. Create or unlock the encrypted local vault, then Share → Add to Home Screen. Launch that icon. Settings now detects standalone display mode and reports whether this instance is running as a Home Screen app. Detection does not install the app or elevate its permissions.

The offline shell stores application resources locally. Files and recorded session progress stay encrypted in IndexedDB. This build uses a vault password, not Apple web login. Keep an encrypted backup. The native Apple login has separate device Keychain credentials. Sign in with Apple proves identity; encryption needs its own key lifecycle. Never derive a secret encryption key from an Apple user identifier or OAuth token.

## 2. Build and install the native app on your Mac

Prerequisites: Xcode with an SDK supporting your phone, a trusted connected iPhone, and an Apple Developer team with Sign in with Apple configured for your unique bundle ID. Run from the unzipped source root:

```sh
python3 scripts/release/apple.py check
xcrun devicectl list devices
python3 scripts/release/apple.py install --team YOURTEAMID --bundle-id com.yourcompany.LocalSandbox --device YOUR_DEVICE_ID
```

The install command builds the actual app, requests provisioning through your Xcode account, then uses Apple's devicectl to install it on the selected phone. It fails on signing/build errors. It does not replace errors with success. Apple login then prepares the app-owned protected workspace; optional iCloud folder selection remains explicit.

To run native tests first:

```sh
xcrun simctl list devices available
python3 scripts/release/apple.py test --simulator YOUR_SIMULATOR_UDID
```

## 3. Create the real provider exports once

On an Apple device, create and test the named workflows in `release/shortcuts/recipe.json`. Use the actual actions exposed by your installed Locally, ChatGPT, Grok, Grokbot and Claude apps; keep account authentication inside those apps. Do not embed credentials, personal paths, private file contents, or prompts in distributable workflows. Export each workflow to an untracked `private-exports` directory on your Mac.

The publisher cannot invent vendor App Intent identifiers. For an app without a text-returning action, prepare a clearly labeled manual-transfer workflow instead of promising automatic tool chaining. The native Begin Oracle Task and Apply Reviewed Action actions are available only after the native app is installed. The runner's `requires` list must reflect the adapters it actually calls. Edit the recipe to match your tested stack; omit optional providers if you are not distributing them.

```sh
python3 scripts/release/shortcuts.py --exports private-exports --base-url https://YOUR_DOMAIN/shortcuts --check
python3 scripts/release/shortcuts.py --exports private-exports --base-url https://YOUR_DOMAIN/shortcuts
```

The first command checks inputs. The second uses Apple's `shortcuts sign --mode anyone`, stages signed `.shortcut` files in an immutable version directory, computes SHA-256 and byte counts, then atomically publishes the catalog. Apple receives the workflow for validation during signing. No private exports or signing credentials enter the source ZIP. A successful signing operation is not a successful device test.

Deploy the generated `public/shortcuts` directory to that same HTTPS base URL. In the website, open Install Shortcut packages. In the native app, open Set up Shortcuts → Install Shortcut packages and import `catalog.json`. Each Add Shortcut button opens the actual package URL; Apple presents its import and permission flow. Complete the harmless text test in provider settings. Catalog hashes are release metadata; the current installer delegates signed-workflow validation to Apple, and does not claim a returned execution receipt from opening the link.

## 4. Self-host the local web application

```sh
python3 scripts/release/selfhost.py
```

Unzip `public/downloads/Local-Sandbox-Selfhost.zip` on your server. Set `LOCAL_SANDBOX_DOMAIN` to your own domain, point its DNS at the host, allow ports 80/443, and run:

```sh
export LOCAL_SANDBOX_DOMAIN=YOUR_DOMAIN
docker compose up -d
```

Caddy serves the static client and signed package catalog with HTTPS. There is no workspace database or model API on that server. User content stays in each device's encrypted browser vault. The package includes no Apple OAuth backend: genuine Apple web identity remains a separate deployment requirement. Moving between origins requires encrypted export/restore; a Home Screen app cannot automatically mount the native app's private directory. The independent package does not expose the private hosted dashboard or its D1 data.

The Caddy major-version image should be resolved to a reviewed digest in your deployment environment before production rollout. Preserve the previous static package and encrypted client backups when updating; rolling back the shell must not clear browser data.

## 5. Upload through Apple's distribution channel

Create the app record in App Store Connect, enable the bundle ID's required capabilities, and resolve agreements. The local command uses your Xcode account, or an App Store Connect API key supplied through `LS_ASC_KEY_PATH`, `LS_ASC_KEY_ID`, and `LS_ASC_ISSUER_ID`. Keep the `.p8` outside the repository.

```sh
python3 scripts/release/apple.py archive --team YOURTEAMID --bundle-id com.yourcompany.LocalSandbox --build-number 4
# For an upload, choose a new unused build number:
python3 scripts/release/apple.py upload --team YOURTEAMID --bundle-id com.yourcompany.LocalSandbox --build-number 5
```

Upload builds and exports an archive with destination upload; it does not submit metadata or assert approval. Check processing in App Store Connect and qualify the build with TestFlight. App Store Connect requires real screenshots, support/privacy URLs, app description, age rating, export-compliance answers, privacy declarations, pricing/availability and review access instructions. These declarations must describe the actual app, including optional cloud-provider handoffs and GitHub sync. Do not auto-answer them falsely. Native UI here has not been compiled or tested, so do not submit it as qualified merely because source exists.

For repeatable GitHub automation, configure the `apple-release` environment with variables `APPLE_TEAM_ID`, `APPLE_BUNDLE_ID` and secrets `ASC_KEY_P8`, `ASC_KEY_ID`, `ASC_ISSUER_ID`. Run the `Package native release` workflow from main. It runs simulator tests before archiving/uploading, deletes its temporary API key, and retains artifacts for seven days. The target GitHub repository is not yet connected/published from this environment; the workflow will run only after source is placed in your GitHub repository. Apple may require additional provisioning/signing setup on the hosted runner.

App Review approval and timing are Apple's decision. No automation can promise approval today. A locally installed development build and a Home Screen web app do not wait for App Store review.

## 6. Background behavior and recovery

Use foreground execution for provider app switches and interactive Shortcuts. The existing native coordinator checkpoints between actions and resumes pending work; it is not a continuously running daemon. With complete file protection, locked-device file access is intentionally unavailable.

Future native background work must use the appropriate Apple BackgroundTasks APIs, accept system scheduling and expiration, checkpoint before suspension, and avoid launching arbitrary provider UIs while unattended. Do not use fake audio/location modes to keep the process alive. Service workers support event-driven web work and caching; they are not an always-on local model process. Background execution is not added or claimed in this patch.

## 7. LocalSend

LocalSend can transfer encrypted backups, catalogs, and signed Shortcut exports over a local network. It does not install Shortcuts, unlock another app's filesystem, provide Apple login, or grant background execution. Transfer encrypted backups rather than plaintext user data. This suite requires no LocalSend dependency.

## Release sequence and remaining gates

| Order | Deliverable | Evidence required |
|---|---|---|
| 1 | Current web/local client | Build, contract checks, standalone/offline test on the phone |
| 2 | Native development install | Successful signed build and actual device installation |
| 3 | Apple identity and local protection | Login/revocation, lock/unlock, restart and key-loss tests |
| 4 | Real Shortcut packages | Export, Apple signing, installation, text return and file readback |
| 5 | Optional GitHub/iCloud connections | Scoped authorization, conflict, offline and revocation tests |
| 6 | Apple web identity | Registered Services ID/domain, supported host, server token verification and secure key recovery design |
| 7 | TestFlight | Build processing and physical iOS 27 acceptance; unavailable-provider cases |
| 8 | App Store | Complete metadata, submitted review, Apple's decision |

## Primary sources checked 10 September 2026

- Apple Shortcuts for Mac, **Signing shortcuts from the command line**: https://support.apple.com/guide/shortcuts-mac/run-shortcuts-from-the-command-line-apd455c82f02/mac
- Apple App Store Connect Help, **Upload builds**: https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/
- Apple Developer, **Choosing Background Strategies for Your App**: https://developer.apple.com/documentation/backgroundtasks/choosing-background-strategies-for-your-app
- Apple Account Help, **Associate your website to your app**: https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/
- LocalSend, **How It Works** and **Frequently Asked Questions**: https://localsend.org/
