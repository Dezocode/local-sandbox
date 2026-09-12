import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);

test('generated Xcode settings enforce Swift 6 complete concurrency only', async () => {
  const [generator, project] = await Promise.all([
    readFile(new URL('scripts/generate-xcode-project.py', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox.xcodeproj/project.pbxproj', root), 'utf8'),
  ]);

  assert.match(generator, /'SWIFT_VERSION':'6\.0'/);
  assert.match(generator, /'SWIFT_STRICT_CONCURRENCY':'complete'/);
  assert.match(project, /SWIFT_VERSION = "6\.0";/);
  assert.match(project, /SWIFT_STRICT_CONCURRENCY = "complete";/);

  for (const source of [generator, project]) {
    assert.doesNotMatch(source, /SWIFT_DEFAULT_ACTOR_ISOLATION/);
    assert.doesNotMatch(source, /SWIFT_APPROACHABLE_CONCURRENCY/);
    assert.doesNotMatch(source, /SWIFT_UPCOMING_FEATURE_/);
  }
});

test('iOS 27 release metadata keeps an App Store-compatible launch screen', async () => {
  const [generator, infoPlist] = await Promise.all([
    readFile(new URL('scripts/generate-xcode-project.py', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/Info.plist', root), 'utf8'),
  ]);

  assert.match(generator, /'UILaunchScreen':\{\}/);
  assert.match(infoPlist, /<key>UILaunchScreen<\/key>\s*<dict\/>/);
});

test('Xcode 27 sendability conformances stay on their owning declarations', async () => {
  const [routing, packages, accountSync, workspaceSync, app] = await Promise.all([
    readFile(new URL('ios/LocalSandbox/ProviderRoutingCore.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/ShortcutPackageCore.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/NativeAccountSync.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/NativeWorkspaceSyncView.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/LocalSandboxApp.swift', root), 'utf8'),
  ]);

  assert.match(routing, /enum ProviderSelection: String, CaseIterable, Codable, Identifiable, Sendable \{/);
  assert.match(packages, /class ShortcutPackageRedirectRejector: NSObject, URLSessionTaskDelegate, @unchecked Sendable \{/);
  assert.match(accountSync, /protocol NativeHTTPPerforming: Sendable \{/);
  assert.match(accountSync, /struct NativeAppleAuthAPI: Sendable \{/);
  assert.match(accountSync, /struct NativeWorkspaceSyncAPI: Sendable \{/);
  assert.match(workspaceSync, /isolated deinit \{/);
  assert.match(app, /isolated deinit \{/);
});

test('iOS 26 UI uses native tabs and receipt-bound trace identity', async () => {
  const app = await readFile(new URL('ios/LocalSandbox/LocalSandboxApp.swift', root), 'utf8');

  for (const title of ['Inbox', 'Sandbox', 'Activity', 'Settings']) {
    assert.match(app, new RegExp(`Tab\\("${title}", systemImage:`));
  }
  assert.doesNotMatch(app, /\.tabItem\s*\{/);
  assert.doesNotMatch(app, /id:\s*\\\.offset/);
  assert.doesNotMatch(app, /receipt\.trace\.enumerated\(\)/);
  assert.match(app, /private struct ReceiptTraceRow: Identifiable/);
  assert.match(app, /ForEach\(receiptTraceRows\(receipt\)\)/);
  assert.match(app, /NativeDigest\.sha256\([\s\S]*\[receipt\.id, entry\.tool, entry\.status, entry\.detail, evidenceIdentity\]/);
  assert.match(app, /id: "\\\(receipt\.id\):\\\(fingerprint\):\\\(occurrence\)"/);
});

test('native JSON contracts validate raw production boundaries before Foundation decoding', async () => {
  const [models, routing, qualification, store, catalog, contracts, server, dashboard, runtime, shortcut, intents] = await Promise.all([
    readFile(new URL('ios/LocalSandbox/Models.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/ProviderRoutingCore.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/ProviderQualification.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/SandboxStore.swift', root), 'utf8'),
    readFile(new URL('lib/catalog.ts', root), 'utf8'),
    readFile(new URL('lib/contracts.ts', root), 'utf8'),
    readFile(new URL('lib/server.ts', root), 'utf8'),
    readFile(new URL('app/dashboard.tsx', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/Runtime.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/ShortcutBridge.swift', root), 'utf8'),
    readFile(new URL('ios/LocalSandbox/AppIntents.swift', root), 'utf8'),
  ]);

  assert.match(models, /StrictJSON\.object\(bytes, limits: \.providerResponse\)/);
  assert.match(models, /StrictJSON\.object\(data, limits: \.traceDetail\)/);
  assert.match(models, /static func decodeStrict\(from data: Data\)/);
  assert.match(routing, /StrictJSON\.object\(bytes, limits: \.providerResponse\)/);
  assert.match(qualification, /StrictJSON\.decode\(SignedProviderQualificationLedger\.self, from: bytes, limits: \.qualificationLedger\)/);
  assert.match(store, /RunReceipt\.decodeStrict\(from: data\)/);
  assert.match(models, /maximumSerializedUTF8Bytes = 1_900_000/);
  assert.match(contracts, /maximumSerializedUTF8Bytes:1_900_000/);
  assert.match(contracts, /maximumJSONDepth:32/);
  assert.match(contracts, /Receipt JSON contains a duplicate object member/);
  assert.match(models, /value\.unicodeScalars\.count/);
  assert.match(contracts, /Array\.from\(value\)\.length/);
  assert.match(store, /func saveReceipt\(_ receipt: RunReceipt, path: String\)/);
  assert.match(store, /maximumReceiptCollectionBytes = 100 \* 64_000/);
  assert.match(runtime, /saveReceipt\(receipt, path:/);
  assert.match(shortcut, /saveReceipt\(receipt,path:/);
  assert.match(intents, /receipt\.encodedWireData\(\)/);
  assert.match(routing, /payload\.utf8\.count <= 128_000/);
  assert.match(server, /receiptRequestMaximumBytes=receiptWireContract\.maximumSerializedUTF8Bytes\+12/);
  assert.match(server, /TextEncoder\(\)\.encode\(payload\)\.byteLength>receiptWireContract\.maximumSerializedUTF8Bytes/);
  assert.match(server, /hostedReceiptPageMaximumUTF8Bytes=6_400_000/);
  assert.match(server, /length\(CAST\(payload AS BLOB\)\) AS payload_bytes/);
  assert.match(server, /db\.batch\(selected\.map/);
  assert.match(dashboard, /parseReceiptWireBytes\(new Uint8Array\(await file\.arrayBuffer\(\)\)\)/);
  assert.match(dashboard, /Load older receipts/);
  assert.match(catalog, /\{"kind":"final","summary":"\.\.\."\}/);
  assert.doesNotMatch(catalog, /\{"kind":"final","summary":"\.\.\.","verified":false\}/);
});
