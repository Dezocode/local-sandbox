import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

function uint32(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}

function box(name, payload = Buffer.alloc(0), size = payload.length + 8) {
  return Buffer.concat([uint32(size), Buffer.from(name, 'ascii'), payload]);
}

function fixtures() {
  const cases = [];
  const add = (name, type, bytes, dimensions = null) => cases.push({ name, type, bytes, dimensions });
  const icns = (length = 8) => Buffer.concat([
    Buffer.from('icns'), uint32(16), Buffer.from('icp4'), uint32(length),
  ]);
  const stream = Buffer.from([0xff, 0x0a, 1, 0]);
  const jxlHeader = Buffer.concat([
    box('JXL ', Buffer.from('0d0a870a', 'hex')),
    box('ftyp', Buffer.concat([Buffer.from('jxl '), uint32(0), Buffer.from('jxl ')])),
  ]);
  const jxl = (length = 16) => Buffer.concat([
    jxlHeader, box('jxlp', Buffer.concat([uint32(0x80000000), stream]), length),
  ]);
  const heifHeader = box('ftyp', Buffer.concat([Buffer.from('mif1'), uint32(0), Buffer.from('mif1')]));
  const heif = (length = 20, crop = null) => {
    const properties = [box('ispe', Buffer.concat([uint32(0), uint32(32), uint32(24)]), length)];
    if (crop) properties.push(crop);
    return Buffer.concat([
      heifHeader,
      box('meta', Buffer.concat([uint32(0), box('iprp', box('ipco', Buffer.concat(properties)))])),
    ]);
  };

  // A zero size previously kept the parser at the same offset indefinitely.
  for (const length of [0, 1, 4, 7]) add(`icns-size-${length}`, 'icns', icns(length));
  for (const length of [0, 1, 7, 8, 9, 11]) add(`jxl-size-${length}`, 'jxl', jxl(length));
  for (const length of [0, 1, 7, 8, 12, 19]) add(`heif-size-${length}`, 'heif', heif(length));
  add('icns-truncated', 'icns', icns().subarray(0, 14));
  add('icns-valid', 'icns', icns(), { width: 16, height: 16 });
  add('jxl-partial-valid', 'jxl', jxl(), { width: 8, height: 8 });
  add('jxl-whole-valid', 'jxl', Buffer.concat([jxlHeader, box('jxlc', stream)]), { width: 8, height: 8 });
  add('heif-valid', 'heif', heif(), { width: 32, height: 24 });
  add('heif-short-crop', 'heif', heif(20, box('clap')), { width: 32, height: 24 });
  add('heif-valid-crop', 'heif', heif(20, box('clap', Buffer.concat([uint32(0), uint32(4)]))), { width: 28, height: 24 });
  add('png-valid', 'png', Buffer.from('89504e470d0a1a0a0000000d4948445200000020000000180806000000', 'hex'), { width: 32, height: 24 });
  add('gif-valid', 'gif', Buffer.from('47494638396120001800800000', 'hex'), { width: 32, height: 24 });
  add('jpeg-valid', 'jpg', Buffer.from('ffd8ffe00002ffc00011080018002003011100021100031100ffd9', 'hex'), { width: 32, height: 24 });
  add('jp2-valid', 'jp2', Buffer.concat([
    box('jP  ', Buffer.from('0d0a870a', 'hex')),
    box('ftyp', Buffer.concat([Buffer.from('jp2 '), uint32(0), Buffer.from('jp2 ')])),
    box('jp2h', box('ihdr', Buffer.concat([uint32(24), uint32(32)]))),
  ]), { width: 32, height: 24 });
  return cases;
}

if (process.argv[2] === '--probe') {
  const [entry, kind] = process.argv.slice(3);
  const parser = await import(pathToFileURL(entry).href);
  const directory = process.argv[5] || null;
  try {
    const results = [];
    for (const fixture of fixtures()) {
      if (kind.startsWith('type:') && kind.slice(5) !== fixture.type) continue;
      try {
        let value;
        if (kind === 'file') {
          const filename = path.join(directory, fixture.name);
          writeFileSync(filename, fixture.bytes);
          value = await parser.imageSizeFromFile(filename);
        } else if (kind === 'types') {
          value = parser.typeHandlers.get(fixture.type).calculate(fixture.bytes);
        } else if (kind.startsWith('type:')) {
          value = parser[fixture.type.toUpperCase()].calculate(fixture.bytes);
        } else {
          value = parser.imageSize(fixture.bytes);
        }
        results.push({ name: fixture.name, value });
      } catch (error) {
        results.push({ name: fixture.name, error: error.name });
      }
    }
    process.stdout.write(JSON.stringify(results));
  } finally {
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
} else {
  // Resolve from vinext itself: a separate top-level copy would not prove its parser is fixed.
  const vinextEntry = import.meta.resolve('vinext');
  const imageEntry = createRequire(vinextEntry).resolve('image-size');
  const packageRoot = path.dirname(path.dirname(imageEntry));
  const metadata = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  assert.equal(metadata.name, 'image-size');
  assert.equal(metadata.version, '2.0.2', 'Review/remove the backport when changing the upstream version');

  for (const format of ['require', 'import']) {
    const typeExport = metadata.exports['./types/*'][format].default;
    const entries = [
      ['main', metadata.exports['.'][format].default],
      ['file', metadata.exports['./fromFile'][format].default],
      ['types', typeExport.replace('*', 'index')],
      ...['icns', 'jxl', 'heif', 'jp2'].map((type) => [`type:${type}`, typeExport.replace('*', type)]),
    ];
    for (const [kind, relativeEntry] of entries) {
      test(`vinext image-size ${format} ${kind} rejects malformed images and retains dimensions`, (t) => {
        const directory = kind === 'file' ? mkdtempSync(path.join(tmpdir(), 'local-sandbox-image-size-')) : null;
        if (directory) t.after(() => rmSync(directory, { recursive: true, force: true }));
        // Promise.race cannot interrupt a synchronous parser loop; the parent must kill the child.
        const result = spawnSync(process.execPath, [
          '--max-old-space-size=128', fileURLToPath(import.meta.url), '--probe',
          path.resolve(packageRoot, relativeEntry), kind, directory ?? '',
        ], { encoding: 'utf8', timeout: 3_000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 });
        assert.equal(result.error, undefined, `Parser probe failed or timed out: ${result.error?.message}`);
        assert.equal(result.status, 0, result.stderr || `Parser exited with ${result.signal}`);
        const actual = JSON.parse(result.stdout);
        const expected = fixtures().filter((fixture) => !kind.startsWith('type:') || kind.slice(5) === fixture.type);
        assert.deepEqual(actual.map(({ name }) => name), expected.map(({ name }) => name));
        for (let index = 0; index < expected.length; index += 1) {
          const fixture = expected[index];
          const outcome = actual[index];
          if (fixture.dimensions === null) {
            assert.equal(typeof outcome.error, 'string', `${fixture.name} must reject malformed input`);
          } else {
            assert.equal(outcome.error, undefined, fixture.name);
            assert.deepEqual({ width: outcome.value.width, height: outcome.value.height }, fixture.dimensions, fixture.name);
          }
        }
      });
    }
  }
}
