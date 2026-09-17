# image-size 2.0.2 parser safety backport

Vinext 1.0.0-beta.5 pins image-size 2.0.2. This patch backports the ICNS,
JXL and HEIF malformed-input safety checks from the maintainer-published
image-size 2.0.3 package, without changing 2.0.2's exports or package layout.
It also updates every bundled copy of the shared box reader, including JP2.
The patch is applied through pnpm's exact-version `patchedDependencies`.

The two source tarballs were verified against npm's SHA512 integrity:

- [2.0.2](https://registry.npmjs.org/image-size/-/image-size-2.0.2.tgz),
  SHA256 `7a47b434cf3c1d3f50dd23f6de2587c5cb0bd55bf044c2546cbb60d979f00d36`.
- [2.0.3](https://registry.npmjs.org/image-size/-/image-size-2.0.3.tgz),
  SHA256 `d69c04f1a100fc76ff8898cf76d448d311982710263ee7dc9117acf9836bee7f`.

The upstream safety changes are in `dist/esm/types/{utils,icns,jxl,heif}.js`
and the corresponding CJS files in 2.0.3. The patch preserves 2.0.2's existing
formatting and unrelated behavior, including its missing-codestream error.
It changes all 20 executable CJS/ESM copies, with no package metadata or
license changes. Upstream's MIT copyright and permission notice is in LICENSE.

The patch SHA256 is
`5008ebb67afca0fb4be0ebf8d6dfb2241fb2df95dfdee277c5c523821adc669f`.

`tests/image-size-backport.test.mjs` resolves the installed package from vinext
and checks malformed input and retained dimensions in bounded child processes.
It runs inside the existing Node contracts verification stage.

The project retains its seven-day dependency age policy. Version 2.0.3 was
published on September 14, 2026 at 15:57:47.615 UTC, and is too recent at this
backport's September 17 review. Replace this patch only after selecting and
verifying an age-eligible upstream release, including the same parser tests,
production build and extracted-source installation checks.

Dependency audits may continue reporting nominal version 2.0.2 for
[GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr) and
[GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq).
Keep those findings visible with the backport evidence; this patch does not
suppress advisories or establish a clean audit.
