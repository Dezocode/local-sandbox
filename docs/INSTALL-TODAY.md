# Local Sandbox 0.3 — installation paths

This release is a working web implementation and uncompiled native source. It is not an App Store release. No signed provider Shortcut installers are bundled.

## On-device web workspace

Open `/local/index.html` from the Site, create a vault password of at least 12 characters, then in Safari use Share → Add to Home Screen and enable Open as Web App where offered. The page registers an offline shell; installation and offline behavior still need testing on your iPhone. This is separate from the online dashboard, which continues to use the private Sites account and server storage.

Files and manually transferred Oracle/Locally messages are encrypted with AES-GCM before IndexedDB storage. PBKDF2 derives the key from your vault password with a fresh salt and 600,000 iterations. The password stays in page memory until Lock or page closure. Export encrypted backups; clearing website data or losing the password can lose access. A second tab cannot overwrite a newer vault revision silently. This is password protection, not an Apple passkey or Face ID implementation.

For independent ownership, host the `public/local` folder on your own HTTPS origin. It contains only static files, needs no model API, and does not call the dashboard server. Changing origins does not move browser storage: export and restore an encrypted backup using the same password.

## Native Xcode source

1. Unzip the source. Open `ios/LocalSandbox.xcodeproj` in Xcode with the iOS 27 SDK for your reported iOS 27 phone.
2. Select your Apple Developer team and a unique bundle ID. Configure Sign in with Apple for that App ID. The identity entitlement requires valid provisioning; a downloadable ZIP does not supply it.
3. Build to your connected, trusted iPhone. Apple SDK compilation and device acceptance have not run in this environment; resolve any compiler or provisioning errors before distribution.
4. Sign in with Apple. The app prepares a protected Application Support workspace on this device. Settings can switch to a user-selected Files/iCloud folder; switching does not copy or erase the prior workspace.
5. Unlock through Face ID or the device passcode. App Intent operations request device authentication. Native credentials stay in this device’s Keychain. Native on-device files receive complete file protection.
6. Find Local Sandbox in Shortcuts → App Shortcuts. Prepare Workspace, Begin Oracle Task, Apply Reviewed Action, Run Bounded Task, and Open Local Sandbox are declared by the native app. Registration requires installing the app, and has not been tested on a device here.

## Fix “Agent Step - Local does not exist”

`shortcuts://run-shortcut` can only run an already-saved Shortcut. `shortcuts://create-shortcut` opens an empty editor. Neither creates the requested provider workflow automatically.

Create a Shortcut named **Agent Step - Local**. Pass Shortcut Input to the actual text-generating action offered by your installed Locally app; finish with Stop and Output. If Locally offers no such action, use the manual transfer path and return its response yourself. Do not invent a Locally, LM Link, Grokbot or other vendor action identifier.

Save the workflow, confirm the exact name in Settings, and run the read-only text test. Only mark the test passed after you receive the result. The app records your device report; it cannot inspect your Shortcut inventory. The same process applies to ChatGPT, Grok and Claude, using their own app accounts and exposed actions. Cloud handoff consent must also be enabled for cloud providers.

To distribute a one-tap installer, export the tested Shortcut through Apple's sharing flow, choose Anyone where appropriate, or copy its iCloud share link. Put that real link in the provider settings. This source does not bundle fabricated installer links. Apple still presents its Add Shortcut and permission UI.

## Siri and mirroring

Use Siri to invoke Local Sandbox's declared App Shortcuts. This build adds actions to Siri; it does not implement a default assistant replacement, a Cursor Origin OAuth connection, or access to private provider chat histories. Only prompts and responses explicitly transferred into the workspace can be mirrored.

GitHub settings connect a repository-scoped token, track the selected branch, and compare one selected file before commit/import. Visible web status polls every 30 seconds. Publishing uses expected remote commits and non-force updates. The worktree bridge applies reviewed exported patches to an existing worktree on its computer. Profile/config/state folders are excluded from the sync file picker. This is not an automatic bidirectional mirror of every repository file.

## Remaining release gates

Xcode compilation, Apple provisioning/sign-in, Face ID, actual Shortcuts installation and round-trip, iPhone offline behavior, live GitHub sync, iOS 27 acceptance and App Review remain unverified. The target GitHub repository returned 404 and repository creation is unavailable in this session. `scripts/publish-github.sh` is provided for an authenticated GitHub CLI on your computer. Never describe the managed Sites git remote as GitHub.
