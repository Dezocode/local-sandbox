# Configure Cursor Origin

The hosted `/local` app can connect a Cursor Origin App, list the repositories that an installation permits, and request a manual mirror refresh. The static self-host package has no identity or API server, so it does not offer these controls.

Do not mark Cursor Origin as qualified until the live checks in this guide pass.

## Register the Origin App

1. Enable Origin for the Cursor namespace that owns the repositories.
2. Open the Origin App settings at `https://cursor.com/codebase/settings/apps`.
3. Create a private Origin App.
4. Create an Ed25519 signing key. Register only the public key with Cursor.
5. Store the PKCS#8 private key in the deployment's encrypted secret store.
6. Register this exact callback URL:

   ```text
   https://YOUR_DOMAIN/api/origin/callback
   ```

7. Grant `repository:contents:read`.

Local Sandbox accepts exactly `repository:contents:read`. Origin endpoints fail closed if `ORIGIN_INSTALL_SCOPES` contains another scope, including another read scope or any write scope. The install redirect does not retain previously granted scopes. Remove an older installation with broader grants before reconnecting it.

The server checks the current installation grant before it saves the callback and again before every short-lived credential mint. Any missing, additional, or write scope blocks the connection before a token is minted. Local Sandbox uses the read-only grant to list approved repositories and request `Sync Mirror` for the default branch. It does not clone, push, create a branch, or return an installation token to the browser.

## Set the server secrets

Set these values in the host's encrypted secret store:

| Name | Value |
| --- | --- |
| `ORIGIN_APP_ID` | The Origin App ID that starts with `app_` |
| `ORIGIN_APP_PRIVATE_KEY_PKCS8` | The complete Ed25519 PKCS#8 private key, including its header and footer |
| `ORIGIN_INSTALL_REDIRECT_URI` | The exact registered HTTPS callback URL |
| `ORIGIN_INSTALL_SCOPES` | `repository:contents:read` |
| `ORIGIN_INSTALL_SUMMARY` | A plain description of why Local Sandbox requests access |

Never put the private key in source control, the progress workbook, a log, or a client-side environment variable.

## Apply the D1 migration

Apply every migration through `drizzle/0013_general_external_operation_leases.sql` in filename order through the deployment's normal migration process. Migration 0003 adds these Origin tables:

- `origin_auth_flows` stores owner-bound, one-use installation state.
- `origin_auth_receipts` prevents installation receipt replay.
- `origin_installations` binds each approved installation to one hosted account.
- `origin_installation_receipt_fences` records the latest accepted or disconnected-through signed receipt time for each installation ID.

Migration 0012 adds `apple_owner_external_operation_leases` for Origin. Migration 0013 generalizes the table to provider-kind and resource identifiers while copying live Origin installation leases without changing their scope. Each authenticated dashboard Origin action claims one opaque, five-minute owner/installation lease before its first provider call and releases it only after the operation finishes. Apple deletion and server-notification cleanup atomically refuse a matching active lease; deletion that wins first prevents the provider callback from running. Lease claim and release are idempotent, expired leases cannot authorize successful completion, and bounded cleanup prevents an abandoned lease from blocking deletion indefinitely. A final owner check after release suppresses a staged provider response if deletion starts at that boundary.

The callback verifies Cursor's Ed25519-signed installation receipt against Cursor's discovery document and signing keys. Before provider inspection, it binds the flow lease to the signed installation ID under a global per-installation exclusion shared with disconnect and repository operations. The final save proves the same live lease and advances the installation's signed `issuedAt` high-water. If account deletion, lease contention, an owner conflict, a stale receipt, or another local gate prevents a confirmed save, the callback returns `ORIGIN_INSTALLATION_COMPENSATION_REQUIRED`, releases only its local operation authority, and leaves the durable possible-installation marker for deletion accounting. It never automatically uninstalls the provider installation: Origin re-consent may reuse an existing installation ID, and the receipt has no callback nonce proving that this flow owns a fresh installation. Review or remove the connection in Cursor Origin settings, then acknowledge only the exact warning currently shown by Local Sandbox.

Disconnect atomically advances the receipt fence to local time plus the same 60-second clock skew accepted by receipt verification before it removes the local owner binding. A callback with an older or equal signed issue time can never restore that installation, even after the disconnect lease expires or a newer consent succeeds. An intentional immediate re-consent may therefore need to wait until Cursor issues a receipt strictly after that safety boundary. A successful later re-consent advances, rather than removes, the high-water. The row is bounded to one per installation ID.

Installation receipts are deliberately one-use. If the browser loses the success response after the fenced D1 save committed, resubmitting the same signed callback is rejected by receipt replay protection and does not repeat provider or storage mutation. Reloading the dashboard reads the already committed installation, so the successful connection itself is not lost.

Repository clone URLs are treated as opaque Cursor Origin URLs. Local Sandbox requires absolute HTTPS on exactly `origin.cursor.com`, no credentials, nondefault port, query, fragment, backslash, control character, or oversized URL. It does not assume a `/git/`, owner/name, or other path shape.

Authenticated Origin commands accept only same-origin `application/json` requests and stream at most 20,000 UTF-8 bytes before strict command-schema validation. Malformed content lengths, invalid UTF-8, extra fields, and oversized chunked bodies fail before provider or D1 work.

Standalone Apple account deletion and Apple `account-deleted` or `consent-revoked` notifications attempt provider-side removal for at most eight saved installations concurrently. Exact success/failure counts are persisted with the deletion receipt. Destructive notification processing also stores only validated unresolved installation IDs in its time-bounded operational record. Linked Apple removal preserves Cursor Origin installations owned by the ChatGPT workspace.

## Qualify the live connection

Run these checks on the registered production HTTPS domain:

1. Sign in to the private hosted site.
2. Open `/local/index.html`, unlock the local vault, and select **Cursor Origin**.
3. Select **Connect Cursor Origin**.
4. Approve one installation with a limited repository selection and exactly `repository:contents:read`. Remove any older installation that shows another grant.
5. Confirm that Cursor returns to `/api/origin/callback` and the app shows the connected installation.
6. Load the permitted repositories. Confirm that the server first reads the installation metadata, rejects any scope other than `repository:contents:read`, and that the browser receives repository metadata but no `oit_` installation token.
7. Select a mirrored repository and request synchronization. Confirm that Local Sandbox sends `refs/heads/{defaultBranch}` with `wait: false` and accepts only a matching `synced` response.
8. After a successful callback, simulate a lost browser response, repeat the same signed callback, and confirm that replay is rejected without another provider call or D1 mutation. Reload the dashboard and confirm that the committed installation remains visible.
9. Sign in as another hosted user. Confirm that the other user cannot list or use the installation.
10. Disconnect the installation. Confirm that Cursor deletes it, Local Sandbox removes the owner binding, and a delayed older/equal callback cannot restore it. Wait past the documented 60-second receipt-skew boundary, perform an intentional re-consent, and confirm that a strictly newer signed receipt reconnects it.
11. Race a callback against standalone Apple deletion. Confirm the callback either saves before deletion and is included in bounded account cleanup, or fails closed with the explicit manual-review/removal error. Local Sandbox must not automatically delete an installation from a failed callback: Origin re-consent can reuse an existing installation ID, so the callback receipt does not prove that this flow owns a fresh installation. The durable possible-installation marker remains until a successful local save for that exact flow or account deletion consumes it into a `manualRevocationRequired` receipt.

Run the generated-key and D1 contract tests with:

```sh
node --experimental-strip-types --test tests/origin-auth.test.ts tests/origin-persistence.test.ts
```

These tests prove the local protocol code. They do not prove a production Origin App, a live Cursor account, or a real repository mirror.

## Cursor references

- [Origin overview](https://cursor.com/docs/origin)
- [Origin API](https://cursor.com/docs/api/origin)
- [Origin clone, push, and pull](https://cursor.com/docs/origin/git)
