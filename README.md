# Local Sandbox

An iOS agent control room with an online source workspace and a SwiftUI companion. Oracle prepares bounded work; a model proposes one action; a dispatcher validates the action; readback evidence becomes a receipt.

## Status

This is an implementation preview, not an App Store release. The web application can persist settings, edit scoped text files, prepare task packets, run a deterministic file-tool check, and inspect receipts. Native source includes Apple sign-in, a folder picker, App Intents, Foundation Models and OpenAI providers, file coordination, resource checks, cancellation, and call journals.

Native compilation, real-device execution, Apple provisioning, external local-app integration, and store review have not passed in this environment. See [release evidence](docs/RELEASE.md).

## Open it

- Site: https://local-sandbox.candy-lyric-5390.chatgpt.site
- Native project: `ios/LocalSandbox.xcodeproj`
- Visual guide: `public/downloads/Local-Sandbox-Setup-Guide.pdf`

The web dashboard uses the hosting platform's authenticated user. The native app uses local Apple authentication. These identities are not silently joined. Selecting an iCloud folder is a separate user action.

## Web development

Node 22.13 or newer and the package manager pinned in package.json are required. Install from the lockfile, run the contract tests, then use the package build command. The managed Sites runtime supplies its normal installation and build helpers.

```sh
pnpm install --frozen-lockfile
node --experimental-strip-types --test tests/contracts.test.ts
pnpm build
```

Declare `DB` through `.openai/hosting.json`. Drizzle migrations in `drizzle/` own the schema. Real hosted secrets are set through host environment configuration. `.env` is ignored. `OPENAI_API_KEY` and `OPENAI_MODEL` are both required for `/api/step`. No API request is made when cloud consent is off. API costs are separate from a ChatGPT subscription.

The Sites platform performs authentication and forwarding. Do not expose the worker directly to the internet while trusting arbitrary `oai-authenticated-*` request headers. A different hosting platform needs its own authenticated gateway.

## Native development

Open the Xcode project using Xcode with an iOS 26 SDK or later. Select your Apple Developer team and a unique bundle ID. Enable Sign in with Apple for that App ID. Build and run on your iPhone, select the LocalSandbox folder, save the resource policy, and choose an available provider.

The on-device runtime measures this app process memory footprint. It cannot measure memory owned by a separate model service or another app. Battery policy measures observed level drop, not consumed watt-hours. Missing resource telemetry blocks a native run. This intentionally means the resource admission path cannot pass on a simulator with no battery readings.

Locally AI and LM Link remain named Shortcuts adapters. The app does not invent undocumented external-app APIs. Shortcuts need installation and device permission approval. The bundled App Intents appear after the native app is installed; they are not signed `.shortcut` files.

```sh
xcodebuild -project ios/LocalSandbox.xcodeproj -scheme LocalSandbox \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

Run the test scheme on an installed simulator. Then perform the real-device acceptance in the release checklist. The Xcode project can be regenerated with `python3 scripts/generate-xcode-project.py`.

## Publication

The Site source is stored with the Site. `scripts/publish-github.sh` creates a private `Dezocode/local-sandbox` repository using an authenticated GitHub CLI. It refuses to overwrite an existing remote. The connected GitHub tools in the authoring session could inspect and update repositories but did not expose repository creation, and the requested repository was not accessible.

Apple distribution requires your team, signing, store metadata, privacy declarations, screenshots, support contact, TestFlight qualification, and App Review. No purchase, signing identity, store submission, or public source release is implied by generating this project.
