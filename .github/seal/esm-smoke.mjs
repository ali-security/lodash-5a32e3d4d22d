// Post-pack smoke test of the packed lodash-es tarball. test/test.js only covers
// the monolithic lodash.js, so this loads the packed ES modules themselves.
//
// Usage: node .github/seal/esm-smoke.mjs <extracted package dir> <source lodash.js>
//
// 1. `template.js` and the `lodash.js` barrel must import and render a template.
//    lodash-cli builds each module's imports from its hard-coded `lib/mapping.js`,
//    so a stale mapping yields `ReferenceError: assignWith is not defined`
//    (lodash issue #6167).
// 2. The CVE-2026-4800 and CVE-2026-2950 repros run in fresh processes against the
//    source lodash.js and against the packed modules; the packed modules must
//    behave exactly like the source they were generated from (both vulnerable on
//    the unpatched base, both blocked once the fixes are applied).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [pkgDir, srcLodash] = process.argv.slice(2).map((p) => path.resolve(p));
const modUrl = (file) => pathToFileURL(path.join(pkgDir, file)).href;

const { default: template } = await import(modUrl('template.js'));
const { default: unset } = await import(modUrl('unset.js'));
const { default: _ } = await import(modUrl('lodash.js'));

assert.equal(template('hi <%= a %>')({ a: 1 }), 'hi 1');
assert.equal(template('<%= a %>', { imports: { a: 'ok' } })(), 'ok');
assert.equal(_.template('hi <%= a %>')({ a: 1 }), 'hi 1');
assert.equal(_.template('<%= a %>', { imports: { a: 'ok' } })(), 'ok');
const obj = { a: { b: 1 } };
assert.equal(unset(obj, 'a.b'), true);
assert.deepEqual(obj, { a: {} });
console.log('OK   packed template.js, unset.js and lodash.js import and work');

const loaders = [
  ['source lodash.js', (name) =>
    `(await import('node:module')).createRequire(${JSON.stringify(srcLodash)})(${JSON.stringify(srcLodash)}).${name}`],
  ['packed <method>.js', (name) => `(await import(${JSON.stringify(modUrl(name + '.js'))})).default`],
  ['packed lodash.js', (name) => `(await import(${JSON.stringify(modUrl('lodash.js'))})).default.${name}`],
];

const repros = {
  'CVE-2026-4800': {
    name: 'template',
    body: `
      let threw = false;
      try { fn('x', { imports: { 'a=(globalThis.P=1,1)': undefined } })(); } catch (e) { threw = true; }
      console.log(globalThis.P === 1 ? 'vulnerable' : threw ? 'blocked' : 'unexpected');`,
  },
  'CVE-2026-2950': {
    name: 'unset',
    body: `
      fn({}, [['constructor'], ['prototype'], ['toString']]);
      console.log(typeof ({}).toString === 'function' ? 'blocked' : 'vulnerable');`,
  },
};

let failed = false;
for (const [cve, { name, body }] of Object.entries(repros)) {
  const outcomes = loaders.map(([label, load]) => {
    const code = `const fn = ${load(name)};\n${body}`;
    const out = execFileSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' }).trim();
    console.log(`${cve}  ${label.replace('<method>', name).padEnd(18)} ${out}`);
    return out;
  });
  if (outcomes[0] === 'unexpected' || outcomes.some((o) => o !== outcomes[0])) {
    console.log(`FAIL ${cve}: packed modules do not match the source lodash.js`);
    failed = true;
  } else {
    console.log(`OK   ${cve}: packed modules match the source lodash.js (${outcomes[0]})`);
  }
}
if (failed) process.exit(1);
console.log('ESM smoke test passed');
