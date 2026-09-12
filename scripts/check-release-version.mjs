import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const productVersion = '0.3.0';
const displayVersion = '0.3';

async function text(path) {
  return readFile(new URL(`../${path}`, import.meta.url), 'utf8');
}

const packageMetadata = JSON.parse(await text('package.json'));
const updateMetadata = JSON.parse(await text('public/updates.json'));
const shortcutCatalog = JSON.parse(await text('public/shortcuts/catalog.json'));
const project = await text('ios/LocalSandbox.xcodeproj/project.pbxproj');
const generatedProject = await text('scripts/generate-xcode-project.py');
const serviceWorker = await text('public/local/sw.js');

assert.equal(packageMetadata.version, productVersion, 'package.json version drifted');
assert.equal(updateMetadata.version, productVersion, 'public/updates.json version drifted');
assert.equal(shortcutCatalog.release, productVersion, 'Shortcut catalog release drifted');
assert.match(serviceWorker, new RegExp(`local-sandbox-shell-${productVersion.replaceAll('.', '\\.')}-build\\d+`));

const projectVersions = [...project.matchAll(/MARKETING_VERSION = "([^"]+)"/g)].map((match) => match[1]);
assert.equal(projectVersions.length, 2, 'Expected Debug and Release marketing versions');
assert.deepEqual(new Set(projectVersions), new Set([productVersion]), 'Xcode marketing versions drifted');
assert.match(generatedProject, new RegExp(`'MARKETING_VERSION':'${productVersion.replaceAll('.', '\\.')}'`));

const userVisibleSources = [
  'README.md',
  'app/dashboard.tsx',
  'app/globals.css',
  'docs/ARCHITECTURE.md',
  'docs/RELEASE.md',
  'docs/SOURCES.md',
];
const staleVersion = /(?:Local Sandbox |Version |v)0\.2\b/i;
for (const path of userVisibleSources) {
  const body = await text(path);
  assert.doesNotMatch(body, staleVersion, `${path} still identifies this release as 0.2`);
}

assert.match(await text('README.md'), new RegExp(`Version ${displayVersion.replace('.', '\\.')}`));
assert.match(await text('app/dashboard.tsx'), new RegExp(`v${displayVersion.replace('.', '\\.')} · QUALIFYING`));

console.log(`Release version sources agree on ${productVersion}; qualification remains explicit.`);
