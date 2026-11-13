import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { allEntries, json, readJson, sha256, validateProvenance } from '../scripts/lib.mjs';
import { independentFiles, matchesDomain, selectedDomains, selectiveTemplate, PROXY_DOMAINS, happProfile } from '../scripts/rule-sets.mjs';
import { writeRules } from '../scripts/build-rules.mjs';

const registryBytes = await readFile('registry/registry.json', 'utf8');
const provenanceBytes = await readFile('registry/provenance.json', 'utf8');
const registry = JSON.parse(registryBytes), provenance = JSON.parse(provenanceBytes);
const compatible = await readJson('dist/smart.xray.json');
const files = independentFiles(registry, provenance, registryBytes, provenanceBytes);
const selected = selectedDomains(registry);
const original = await readJson('registry/compatibility-v1.json');
const route = (template, domain) => {
  for (const rule of template.routing.rules) {
    if (rule.domain?.some(value => value.startsWith('domain:') && matchesDomain(domain, value.slice(7)))) return rule.outboundTag;
    if (!rule.domain && !rule.ip && !rule.protocol && rule.network === 'tcp,udp') return rule.outboundTag;
  }
};

test('independent list preserves service coverage except documented exclusions', () => {
  assert.equal(selected.length, 173);
  assert.deepEqual(selected, allEntries(registry).map(entry => entry.domain));
  for (const [name, group] of Object.entries(original.classes)) {
    for (const domain of group.domains) {
      if (['tbank.com','online.sberbank.ru'].includes(domain)) continue;
      assert.ok(registry.classes[name].domains.includes(domain), domain);
    }
  }
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
  assert.equal(manifest.domains, selected.length);
  assert.equal(manifest.categories, 13);
  assert.equal(manifest.registrySha256, sha256(registryBytes));
  assert.equal(manifest.provenanceSha256, sha256(provenanceBytes));
  assert.deepEqual(manifest.externalRoutingDatabases, []);
  assert.deepEqual(manifest.sourceReview, {pending:98,firstPartyReference:72,operatorReportedBundle:3,applicationTests:'not-performed-for-this-rule-set'});
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
test('selective DNS rules contain the complete current domain set and no country-wide category', () => {
  const template = selectiveTemplate(registry, compatible);
  const serviceResolvers = template.dns.servers.filter(server => typeof server === 'object' && server.domains?.some(value => value === 'domain:tbank.ru'));
  assert.equal(serviceResolvers.length, 2);
  for (const resolver of serviceResolvers) assert.deepEqual(resolver.domains, selected.map(domain => `domain:${domain}`));
});
test('reviewed service references cover the reported domain gaps without suffix leakage', () => {
  const template = selectiveTemplate(registry, compatible);
  for (const domain of ['t-bank-app.ru','acdn.t-bank-app.ru','yandex.ru','ya.ru','yastatic.net','api.music.yandex.net','market.yandex.ru','music.yandex.ru','travel.yandex.ru','2gis.ru','account.2gis.com','ir.ozone.ru','static-basket-02.wbbasket.ru']) {
    assert.equal(route(template, domain), 'direct', domain);
    assert.equal(route(template, `${domain}.unrelated.invalid`), 'proxy', domain);
  }
  assert.equal(route(template, 'sbp.ru'), 'proxy', 'travel agency must not be added as a payment service');
});
test('new domain references require dated evidence, valid URLs and the correct category', () => {
  for (const mutate of [
    entry=>{entry.source[0].checkedAt=null;},
    entry=>{entry.source[0].reference='https://unrelated.invalid/';},
    entry=>{entry.source[0].url='https://example.com/?credential=bad';},
    entry=>{entry.class='payments';},
    entry=>{entry.source[0].result='verified-app';}
  ]) {
    const changed=structuredClone(provenance);
    mutate(changed.entries.find(entry=>entry.domain==='yandex.ru'));
    assert.throws(()=>validateProvenance(registry,changed));
  }
});
test('reviewing an original source does not require inventing an addition date', () => {
  const changed=structuredClone(provenance);
  const entry=changed.entries.find(entry=>entry.domain==='tbank.ru');
  entry.source=[{url:'https://www.tbank.ru/',checkedAt:'2026-11-13',result:'first-party-reference',reference:'https://www.tbank.ru/',note:'Synthetic validator fixture.'}];
  assert.equal(entry.addedAt,null);
  assert.doesNotThrow(()=>validateProvenance(registry,changed));
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

test('shared-cloud exceptions win over parent service suffixes', () => {
  const template=selectiveTemplate(registry,compatible);
  for(const domain of PROXY_DOMAINS) for(const host of [domain,`tenant.${domain}`]) assert.equal(route(template,host),'proxy');
  assert.equal(route(template,'api.vk.com'),'direct');
  assert.equal(route(template,'tbank.com'),'proxy');
  assert.equal(route(template,'online.sberbank.ru'),'direct');
  assert.equal(JSON.parse(files['liberta-proxy.xray.json']).outboundTag,'proxy');
});
test('Happ native routing and optional FakeDNS profile share the own registry', () => {
  const standard=happProfile(registry), experimental=happProfile(registry,{fakeDNS:true});
  assert.deepEqual(standard.DirectSites,selected.map(d=>`domain:${d}`));
  assert.deepEqual(standard.ProxySites,PROXY_DOMAINS.map(d=>`domain:${d}`));
  assert.equal(standard.GlobalProxy,true);
  assert.equal(standard.FakeDNS,false);
  assert.equal(experimental.FakeDNS,true);
  assert.deepEqual(experimental.DirectSites,standard.DirectSites);
  assert.equal(standard.Geoipurl,''); assert.equal(standard.Geositeurl,'');
});
