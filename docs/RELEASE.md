# Release evidence and remaining gates

Version 0.2 implementation preview, 10 September 2026.

## Evidence categories

| Goal | Current artifact | Remaining gate |
|---|---|---|
| Oracle guidance | Built-in task packet compiler and compact policy | Live frontier model qualification |
| Dashboard | Nested iOS-style views, durable state, file edits, receipts | User acceptance on target phone |
| Shortcuts | Eleven visual recipes and App Intents source | Device construction/install and testing |
| File sandbox | D1 owner-scoped text workspace; native scoped folder implementation | Real iCloud conflict and revocation tests |
| Resource consent | Saved sliders and portable policy; native admission/monitor | Device memory, battery, and thermal validation |
| Retry behavior | Exact patches, version/hash checks, pending call journal | Crash injection on device |
| Micro-model workflow | One-action contract, bounded inputs, compact state | Locally AI / LM Link benchmark |
| Subscription apps | ChatGPT/Grok/Grokbot/Claude named Shortcuts, no model APIs | Verify actual installed app actions and text return |
| Apple Intelligence | Availability-aware provider | Supported device and enabled model |
| Siri | App Intents and named Shortcut handoff | Voice and Share Sheet acceptance |
| Apple sign-in | AuthenticationServices UI and credential-state check | Developer App ID capability, signing, live login |
| iCloud | Folder picker, bookmark, coordinated reads/writes | User folder selection and device validation |
| Native app | Xcode project, source, icons, privacy manifest, unit tests | Compile, TestFlight, regression and accessibility testing |
| GitHub sync | Repository authentication, conflict-checked branch commits, real worktree patch importer | Live account test and source repository publication |
| App Store | Submission checklist | Metadata, privacy review, signed archive, review approval |

## Required Apple acceptance

- Build and run on the actual iPhone with your developer team. Test iOS 27.0 on iPhone 14 Pro and an Apple Intelligence capable iPhone; preserve iOS 26 compatibility.
- Sign in with Apple and verify revoked-credential behavior.
- Select only the intended LocalSandbox folder and verify access after relaunch.
- Create, read, append, patch, and read back the test file.
- Reject traversal, encoded separators, symlink escapes, invalid JSON, unknown tools, missing hashes, stale hashes, and ambiguous patch matches.
- Cancel during model generation; verify no later tool side effect.
- Interrupt before and after a file write. Inspect the checkpoint and pending journal before recovery.
- Check resource admission at battery reserve and thermal pressure. Record that app memory excludes other processes.
- Test Apple Intelligence unavailable, cloud disabled, app handoff failure, and missing external local app.
- Test notification denial, Files revocation, offline iCloud file availability, and storage pressure.
- Verify VoiceOver, Dynamic Type, landscape, iPad layouts, and touch targets.
- Use the same held-out task suite for each model and report failures as part of the denominator.

## Store submission

Choose your own app category, price, territory availability, support contact, and privacy-policy URL. Complete privacy disclosures for the released behavior, including optional cloud providers. Review required-reason API declarations against the exact SDK/build. Screenshots must show the actual running signed app. Resolve entitlements and signing warnings, archive, upload to App Store Connect, test with TestFlight, and submit to App Review.

The native privacy manifest is a starting declaration for this exact source. It is not a claim that a modified or cloud-enabled product collects no data. The source ships no advertising or analytics SDK. No App Store approval is claimed.

## Validation performed in the authoring environment

See `validation.json` for the exact automated checks and their results. Native compilation, simulator tests, physical device runs, WebMCP browser execution, Apple login, local-model tool calling, iCloud access, and App Store review are not marked as passed without actual execution.

## Version 0.2 update boundary

The private website is updated in place; no new Site or empty database is substituted. Old API provider selection is normalized to ChatGPT and its setup completion is cleared. Other resource authorization, text files, and receipts are retained. Existing file versions and settings revision checks remain active. Model API calls and key fields are intentionally removed per the requested subscription-app design.

GitHub live writes are untested without a user-entered repository token. Transport contract checks and a real local worktree patch exercise were performed separately. They are not evidence of GitHub account authorization. The patch importer reads back actual file changes and rejects conflicts, wrong branches, tampered hashes, and symlinks.

No pre-signed third-party Shortcut packages or fabricated iCloud install links are shipped. Local Sandbox's own App Shortcuts are included in the native project. Third-party action availability, one-tap shared-link installation, Apple login, and iOS 27 execution require the installed signed app and the device.
