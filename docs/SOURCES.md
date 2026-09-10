# Primary sources checked 10 September 2026

| Source | Section used | Implementation consequence |
|---|---|---|
| [Apple Shortcuts URL scheme](https://support.apple.com/guide/shortcuts/run-a-shortcut-from-a-url-apd624386f42/ios) | Run a shortcut from a URL | Encoded named shortcut handoff; no invented installation URL |
| [WWDC26 Apple Intelligence Group Lab](https://developer.apple.com/videos/play/wwdc2026/8011/) | 00:08:18, cross-app intent routing | Siri/Shortcuts own system orchestration |
| Same session | 00:13:26, background work; 01:00:09, context | Bounded calls, availability handling, no always-on execution promise |
| [Sign in with Apple for the web](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/) | Associate your website to your app | A Services ID, primary App ID, and registered website are needed for web Apple OAuth; this Site uses its platform identity instead |
| [Foundation Models](https://developer.apple.com/documentation/foundationmodels) | Framework overview | Native model availability is checked |
| [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling) | Function calling | Strict tool schemas propose actions; the app executes and validates |
| User-supplied iOS_ChatGPT_Local_Agent_Setup_Guide.pdf | Pages 1–5 | Original build order, narrow tool set, capsule, retry budgets, Siri entry, and visual document structure |

The supplied guide's particular model names were not treated as evidence of current availability. A model ID must be chosen from the actual API project. The app makes no vendor benchmark claims.
