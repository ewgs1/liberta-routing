import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, readdir, symlink, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson, validateRegistry, normalizeDomain, render, sha256, json, atomicDirectory } from '../scripts/lib.mjs';
import { routeHash, compare, checkLock } from '../compare-lists.mjs';
import { canary, isPublicAddress } from '../service-canary.mjs';
import { integrate } from '../scripts/integrate.mjs';
import { scanContent } from '../scripts/audit-public.mjs';
import { verifyRelease } from '../scripts/verify-release.mjs';
import { manifest } from '../scripts/lib.mjs';

const registry = await readJson(new URL('../registry.json', import.meta.url));
const now = new Date('2026-11-13T12:00:00Z');
const fresh = () => structuredClone(registry);
const valid = value => validateRegistry(value, { now });
const outputs = () => render(fresh(), { now });
const xrayRoute = (routing, domain) => routing.rules.find(rule => rule.domain?.some(pattern => pattern.startsWith('full:') ? pattern.slice(5) === domain : domain === pattern.slice(7) || domain.endsWith('.' + pattern.slice(7))) || (!rule.domain && rule.network === 'tcp,udp'))?.outboundTag;
const singboxRoute = (source, domain) => source.rules.some(rule => rule.domain?.includes(domain) || rule.domain_suffix?.some(suffix => domain === suffix || domain.endsWith('.' + suffix))) ? 'direct' : 'proxy';

test('independent alpha registry validates without claiming regional measurement', () => {
  assert.equal(valid(fresh()).entries.length, 8);
  assert.ok(registry.entries.every(entry => entry.verification.reachability === 'not-measured'));
});
test('canonicalization handles IDNA and a root dot without silently accepting URLs or addresses', () => {
  assert.equal(normalizeDomain('ПРИМЕР.РФ.'), 'xn--e1afmkfd.xn--p1ai');
  for (const value of ['https://nalog.ru', 'nalog.ru/path', ' nalog.ru', '*.nalog.ru', 'nalog.ru:443', 'nalog..ru', '127.0.0.1', 'localhost', 'foo.internal', 'full:nalog.ru']) assert.throws(() => normalizeDomain(value));
});
for (const [label, mutate] of [
  ['unknown registry field', value => { value.outbounds = []; }],
  ['unknown entry field', value => { value.entries[0].token = 'should-never-publish'; }],
  ['duplicate ID', value => { value.entries[1].id = value.entries[0].id; }],
  ['duplicate domain', value => { value.entries[1].domain = value.entries[0].domain; }],
  ['unknown class', value => { value.entries[0].class = 'missing'; }],
  ['implicit direct', value => { value.entries[0].explicit = false; }],
  ['broad country route', value => { value.entries[0].domain = 'ru'; }],
  ['foreign-list syntax', value => { value.entries[0].domain = 'geosite:category-ru'; }],
  ['unapproved suffix expansion', value => { value.entries[0].match = 'suffix'; }],
  ['public suffix', value => { value.entries[0].domain = 'gov.ru'; value.entries[0].match = 'suffix'; }],
  ['future date', value => { value.entries[0].reviewedAt = '2026-11-14'; }],
  ['invalid date', value => { value.entries[0].addedAt = '2026-02-30'; }],
  ['unverified ownership', value => { value.entries[0].verification.ownership = 'pending'; }],
  ['claimed live result', value => { value.entries[0].verification.reachability = 'passed'; }],
  ['missing source', value => { value.entries[0].source = []; }],
  ['private source', value => { value.entries[0].source[0].url = 'https://localhost/'; }],
  ['secret-bearing source', value => { value.entries[0].source[0].url = 'https://www.nalog.gov.ru/?token=hidden'; }],
  ['noncanonical host', value => { value.entries[0].domain = 'WWW.GOSUSLUGI.RU'; }],
  ['unsafe default', value => { value.profile.defaultRoute = 'direct'; }],
  ['ambiguous tags', value => { value.profile.directTag = value.profile.proxyTag; }]
]) test(`rejects ${label}`, () => { const value = fresh(); mutate(value); assert.throws(() => valid(value)); });
test('stale review fails the whole build rather than silently changing the direct set', () => {
  assert.throws(() => render(fresh(), { now: new Date('2027-02-12T00:00:00Z') }), /stale/);
});
test('all three exports agree on exact hosts, suffix boundaries and proxy fallback', () => {
  const files = outputs(), xray = JSON.parse(files['smart.xray.json']), singbox = JSON.parse(files['smart.singbox.json']);
  const exact = new Set(registry.entries.map(entry => entry.domain));
  const cases = ['unlisted.ru', 'unlisted.com', 'api.gosuslugi.ru', 'www.gosuslugi.ru.evil.com', 'evilwww.gosuslugi.ru', ...exact, ...[...exact].map(host => 'unreviewed.' + host)];
  for (const host of cases) {
    const expected = exact.has(host) ? 'direct' : 'proxy';
    assert.equal(xrayRoute(xray, host), expected, host);
    assert.equal(singboxRoute(singbox, host), expected, host);
  }
  assert.deepEqual(files['smart.domains.txt'].trim().split('\n').sort(), [...exact].map(host => 'full:' + host).sort());
  assert.deepEqual(Object.keys(files).sort(), ['smart.domains.txt', 'smart.singbox.json', 'smart.xray.json']);
  assert.equal(singbox.version, 1);
});
test('entry order does not change the generated bytes or routing hash', () => {
  const reverse = fresh(); reverse.entries.reverse();
  assert.deepEqual(render(reverse, { now }), outputs());
  assert.equal(routeHash(reverse), routeHash(registry));
});
test('candidate/disabled records never reach exports and empty lists fail', () => {
  const value = fresh(); value.entries[0].status = 'candidate';
  assert.ok(!render(value, { now })['smart.domains.txt'].includes(value.entries[0].domain));
  value.entries.forEach(entry => { entry.status = 'disabled'; });
  assert.throws(() => render(value, { now }), /empty direct/);
});
test('semantic diff catches removals and outbound changes while ignoring documentation-only edits', () => {
  const value = fresh(); value.entries[0].source[0].evidence += ' Проверено вручную.';
  assert.equal(compare(registry, value).routeChanged, false);
  value.entries[0].status = 'disabled';
  assert.equal(compare(registry, value).removed.length, 1);
  value.profile.proxyTag = 'vpn';
  assert.equal(compare(registry, value).profileChanged, true);
});
test('route lock cannot be reused for a different allowlist', () => {
  const lock = { schemaVersion: 1, routeSha256: routeHash(registry), reviewedAt: '2026-11-13', reason: 'Initial exact-host alpha review; connectivity not measured.' };
  assert.equal(checkLock(registry, lock, now), true);
  const value = fresh(); value.entries[0].status = 'disabled';
  assert.throws(() => checkLock(value, lock, now), /routing changed/);
});
test('atomic output is complete, immutable, and cleans temporary state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'liberta-build-test-'));
  try {
    const target = join(root, 'release');
    await atomicDirectory(target, outputs());
    assert.equal((await readdir(target)).length, 3);
    await assert.rejects(atomicDirectory(target, outputs()), /already exists/);
    assert.deepEqual(await readdir(root), ['release']);
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('isolated integration preserves base profile, connection settings, DNS and user keys', () => {
  for (const format of ['xray', 'singbox']) {
    const base = { outbounds: [{ tag: 'proxy', custom: 'private-setting' }, { tag: 'direct' }], dns: { privateSetting: 'preserve' }, custom: { key: true }, routing: { rules: [{ outboundTag: 'old' }] }, route: { rules: [{ outbound: 'old' }], rule_set: [{ tag: 'old' }] } };
    const snapshot = json(base), result = integrate(base, registry, format);
    assert.equal(json(base), snapshot);
    assert.deepEqual(result.outbounds, base.outbounds);
    assert.deepEqual(result.dns, base.dns);
    assert.deepEqual(result.custom, base.custom);
    assert.notEqual(json(format === 'xray' ? result.routing : result.route), json(format === 'xray' ? base.routing : base.route));
  }
});
test('isolated integration refuses missing tags and active Xray scripts', () => {
  assert.throws(() => integrate({ outbounds: [] }, registry, 'xray'), /outbounds/);
  assert.throws(() => integrate({ outbounds: [{ tag: 'direct' }, { tag: 'proxy' }], routing: { script: 'existing' } }, registry, 'xray'), /script/);
});
test('SSRF guard rejects special IPv4/IPv6 ranges and accepts public resolver addresses', () => {
  for (const value of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '100.64.0.1', '192.168.1.1', '172.16.0.1', '198.18.0.1', '192.0.2.1', '198.51.100.2', '203.0.113.4', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:8.8.8.8', '2001:db8::1', '2001:0db8::1', '2002::1']) assert.equal(isPublicAddress(value), false, value);
  for (const value of ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888', '2606:4700:4700::1111']) assert.equal(isPublicAddress(value), true, value);
});
test('canary rejects a mixed public/private resolution without making a request', async () => {
  let calls = 0;
  const before = json(registry);
  const report = await canary(registry, { resolveHost: async () => ['8.8.8.8', '127.0.0.1'], probe: async () => { calls++; } });
  assert.equal(calls, 0);
  assert.ok(report.results.every(result => result.result === 'inconclusive'));
  assert.equal(json(registry), before);
  assert.ok(!json(report).includes('8.8.8.8'));
});
test('403 and TLS/network failures do not prove blocking or trigger route changes', async () => {
  const before = sha256(json(registry));
  const report = await canary(registry, { resolveHost: async () => ['8.8.8.8'], probe: async () => ({ tls: 'valid', httpStatus: 403, result: 'http-response' }) });
  assert.ok(report.results.every(result => result.result === 'http-response'));
  assert.equal(before, sha256(json(registry)));
  assert.equal(report.serviceFunctionality, 'not-tested');
});
test('public scanner reports categories without exposing matched values', () => {
  const uri = ['vless', '://', 'private-example'].join('');
  assert.ok(scanContent(uri).includes('connection-uri'));
  assert.ok(scanContent('address=' + ['203', '0', '113', '9'].join('.')).includes('ipv4-literal'));
  assert.ok(scanContent('"token": "' + 'a'.repeat(30) + '"').includes('credential-assignment'));
  assert.deepEqual(scanContent('https://www.nalog.gov.ru/'), []);
});
test('download integrity check detects tampering and extra files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'liberta-integrity-test-'));
  try {
    const target = join(root, 'release'), files = outputs();
    files['release.json'] = json(manifest(registry, json(registry), files));
    await atomicDirectory(target, files);
    const pinned = sha256(files['release.json']);
    assert.equal((await verifyRelease(target, pinned)).version, registry.version);
    await assert.rejects(verifyRelease(target, '0'.repeat(64)), /manifest hash/);
    await writeFile(join(target, 'smart.domains.txt'), 'tampered\n');
    await assert.rejects(verifyRelease(target, pinned), /integrity failure/);
    await writeFile(join(target, 'smart.domains.txt'), files['smart.domains.txt']);
    await writeFile(join(target, 'extra.txt'), 'unexpected');
    await assert.rejects(verifyRelease(target, pinned), /unexpected/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
