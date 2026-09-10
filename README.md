# Local Sandbox

An iOS-style Oracle workspace with Shortcuts-based app providers, a versioned text sandbox, and GitHub worktree sync.

Live private dashboard: https://local-sandbox.ctyy4wd4c2.chatgpt.site

## Start on your phone

Open the dashboard, then Apps & Shortcuts. Configure Locally, ChatGPT, Grok, Grokbot, or Claude using the named action your installed app exposes. Sign in inside that app. No model API keys or model API billing are used. If an app offers no text-returning Shortcuts action, use the explicit manual return flow.

The native companion is in `ios/LocalSandbox.xcodeproj`. Choose your Apple Developer team and bundle ID, build and sign, then use the Apple login splash. Choose an iCloud LocalSandbox folder in Settings. Local Sandbox's own App Shortcuts register with installation; third-party app adapters must be configured and tested on device. A shared iCloud Shortcut link enables a one-tap Add Shortcut flow when supplied. Empty links open the actual Shortcuts editor and do not claim installation.

## GitHub and worktrees

Settings → GitHub authentication & sync accepts a repository-scoped fine-grained token with Contents read/write. Browser credentials last only for the current tab; native credentials use this device's Keychain. Select an existing branch and file, compare both versions, then commit or import. Branch changes block publishing.

To apply an exported worktree patch on a computer:

```bash
python3 scripts/worktree-sync.py Local-Sandbox-Worktree.patch.json --worktree /absolute/path/to/worktree
python3 scripts/worktree-sync.py Local-Sandbox-Worktree.patch.json --worktree /absolute/path/to/worktree --apply
```

The bridge verifies the exact repository, branch, base commit, safe paths, and file hashes. It does not commit, push, or create a worktree automatically.

## Development and updates

Use pnpm and the existing lockfile. `pnpm exec tsc --noEmit`, Node contract tests, Python storage/worktree checks, and the Sites build validate the web source. See `.github/workflows/verify.yml` for native CI instructions. `public/updates.json` is the versioned release manifest. Source changes preserve the app's identity, database, source history, and file-revision checks.

## Current evidence

Version 0.2 is an implementation preview. Apple SDKs, Xcode, real-device validation, vendor Shortcut action availability, GitHub live-account writes, and App Store submission have not been completed in this environment. iOS 26+ is the deployment target; iOS 27.0 is explicitly in the device acceptance matrix. See `docs/RELEASE.md` and the visual PDF for exact gates.

## 0.3 local workspace update

See [INSTALL-TODAY.md](docs/INSTALL-TODAY.md) for exact installation steps and remaining device gates. The independent `public/local` web app provides an encrypted local editor, session notebook, backup/restore and a scoped offline shell. It has its own vault password, not Sign in with Apple. The native source now prepares local protected files after Apple sign-in, supports device authentication, and retains optional selected-folder access. Missing provider Shortcuts are blocked until the user completes setup; no one-tap provider installers are claimed without genuine shared links.

## 0.3 installation automation

See [ROADMAP-AUTOMATION.md](docs/ROADMAP-AUTOMATION.md) for native installation, real Shortcut signing and catalog publishing, self-hosting, App Store Connect upload and remaining acceptance steps. The package installer is available at `/local/install.html` and in native Setup. No actual provider package is distributed until real exported workflows have been signed. The automation does not fabricate Apple approval.
