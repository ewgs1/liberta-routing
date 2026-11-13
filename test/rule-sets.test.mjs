import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { allEntries, json, readJson, sha256 } from '../scripts/lib.mjs';
import { independentFiles, matchesDomain, selectedDomains, selectiveTemplate } from '../scripts/rule-sets.mjs';
import { writeRules } from '../scripts/build-rules.mjs';

const registryBytes = await readFile('registry/registry.json', 'utf8');
const provenanceBytes = await readFile('registry/provenance.json', 'utf8');
const registry = JSON.parse(registryBytes), provenance = JSON.parse(provenanceBytes);
const compatible = await readJson('dist/smart.xray.json');
const files = independentFiles(registry, provenance, registryBytes, provenanceBytes);
const selected = selectedDomains(registry);
const route = (template, domain) => {
  for (const rule of template.routing.rules) {
    if (rule.domain?.some(value => value.startsWith('domain:') && matchesDomain(domain, value.slice(7)))) return rule.outboundTag;
    if (!rule.domain && !rule.ip && !rule.protocol && rule.network === 'tcp,udp') return rule.outboundTag;
  }
};

test('independent list includes all 111 original domains, including legacy explicit:false classes', () => {
  assert.equal(selected.length, 111);
  assert.deepEqual(selected, allEntries(registry).map(entry => entry.domain));
  for (const domain of ['ozon.ru', 'wildberries.ru', 'vk.com', 'rzd.ru', 'tbank.ru']) assert.ok(selected.includes(domain));
});
test('all three independent formats describe the same domain-and-subdomain set', () => {
  const xray = JSON.parse(files['liberta-direct.xray.json']);
  const singbox = JSON.parse(files['liberta-direct.singbox.json']);
  assert.deepEqual(xray.domain, selected.map(domain => `domain:${domain}`));
  assert.deepEqual(singbox.rules[0].domain_suffix, selected);
  assert.deepEqual(files['liberta-direct.domains.txt'].trim().split('\n'), xray.domain);
  assert.equal(xray.outboundTag, 'direct');
});
test('13 categories cover the whole registry and contain no added domains', () => {
  const union = new Set();
  for (const [name, group] of Object.entries(registry.classes)) {
    const rule = JSON.parse(files[`liberta-${name.replaceAll('_', '-')}.singbox.json`]);
    assert.deepEqual([...rule.rules[0].domain_suffix].sort(), [...group.domains].sort());
    for (const domain of rule.rules[0].domain_suffix) union.add(domain);
  }
  assert.deepEqual([...union].sort(), selected);
});
test('manifest verifies every generated file and the input evidence registry', () => {
  const manifest = JSON.parse(files['manifest.json']);
  assert.equal(manifest.domains, 111);
  assert.equal(manifest.categories, 13);
  assert.equal(manifest.registrySha256, sha256(registryBytes));
  assert.equal(manifest.provenanceSha256, sha256(provenanceBytes));
  assert.deepEqual(manifest.externalRoutingDatabases, []);
  for (const set of Object.values(manifest.sets)) for (const file of Object.values(set.files)) {
    assert.equal(sha256(files[file.name]), file.sha256);
    assert.equal(Buffer.byteLength(files[file.name]), file.bytes);
  }
});
test('missing provenance stops generation without silently dropping services', () => {
  const incomplete = structuredClone(provenance); incomplete.entries.pop();
  assert.throws(() => independentFiles(registry, incomplete, registryBytes, provenanceBytes), /every selected domain/);
});
test('generation order is stable and requires no network source', () => {
  const reverse = structuredClone(registry);
  for (const value of Object.values(reverse.classes)) value.domains.reverse();
  const first = independentFiles(reverse, provenance, registryBytes, provenanceBytes);
  for (const name of Object.keys(files)) assert.equal(first[name], files[name]);
  for (const [name, body] of Object.entries(files)) {
    assert.ok(!/(?:geosite:|geoip:|include:|ext:)/.test(body), name);
    assert.ok(!/"(?:url|server|address|outbounds|inbounds)"\s*:/.test(body), name);
  }
});
test('selective profile routes the whole own list and its subdomains directly', () => {
  const template = selectiveTemplate(registry, compatible);
  for (const domain of selected) {
    assert.equal(route(template, domain), 'direct', domain);
    assert.equal(route(template, `api.${domain}`), 'direct', domain);
    assert.equal(route(template, `${domain}.unrelated.invalid`), 'proxy', domain);
  }
});
test('unlisted Russian domains and all unclassified IPs fall back to proxy', () => {
  const template = selectiveTemplate(registry, compatible);
  for (const domain of ['petya.ru', 'unknown-service.su', 'unknown-service.xn--p1ai', 'google.com', 'github.com']) assert.equal(route(template, domain), 'proxy', domain);
  assert.equal(template.routing.rules.at(-1).outboundTag, 'proxy');
  assert.ok(!template.routing.rules.some(rule => rule.ip?.includes('geoip:ru')));
  assert.ok(!/(?:geosite:|geoip:|ext:)/.test(json(template)));
});
test('selective DNS rules contain the same 111 domains and no country-wide category', () => {
  const template = selectiveTemplate(registry, compatible);
  const serviceResolvers = template.dns.servers.filter(server => typeof server === 'object' && server.domains?.some(value => value === 'domain:tbank.ru'));
  assert.equal(serviceResolvers.length, 2);
  for (const resolver of serviceResolvers) assert.deepEqual(resolver.domains, selected.map(domain => `domain:${domain}`));
});
test('independent generation leaves the whole compatible working profile unchanged', () => {
  const before = json(compatible), dataBefore = json(registry);
  selectiveTemplate(registry, compatible);
  independentFiles(registry, provenance, registryBytes, provenanceBytes);
  assert.equal(json(compatible), before);
  assert.equal(json(registry), dataBefore);
});
test('atomic rule directory updates remove stale files and never merge old content', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'liberta-own-rules-'));
  try {
    const output = join(directory, 'rules');
    await writeRules(output, { 'old.txt': 'old\n' });
    await writeRules(output, { 'new.txt': 'new\n' });
    assert.deepEqual(await readdir(output), ['new.txt']);
    await assert.rejects(writeRules(output, { '../escape.txt': 'refused' }), /unsafe generated name/);
    assert.equal(await readFile(join(output, 'new.txt'), 'utf8'), 'new\n');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
