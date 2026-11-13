import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readJson,validateRegistry,allEntries,activeEntries,render,json,sha256,normalizeDomain } from '../scripts/lib.mjs';
import { isPublicAddress,canary } from '../service-canary.mjs';
import { integrate } from '../scripts/integrate.mjs';
const registry=await readJson('registry/compatibility-v1.json');
const lock=await readJson('test/fixtures/production-lock.json');
test('all 111 original hosts and 13 classes remain in the frozen compatibility registry',()=>{
 validateRegistry(registry);assert.equal(sha256(json({classes:registry.classes,measured:registry.measured_exceptions.map(x=>x.domain)})),lock.registryPolicySha256);assert.equal(allEntries(registry).length,lock.registryDomains);assert.equal(Object.keys(registry.classes).length,lock.classes);assert.equal(activeEntries(registry).length,lock.explicitDomains);assert.equal(registry.nodes,undefined);
});
test('complete Xray behavior and DNS are preserved; only remarks changed',async()=>{
 const full=await readJson('dist/smart.xray.json');assert.equal(full.remarks,'Liberta Routing v1');delete full.remarks;assert.equal(sha256(json(full)),lock.behaviorSha256);
});
test('TXT and sing-box preserve the existing 45 suffix-domain rules',async()=>{
 const files=render(registry);const domains=activeEntries(registry).map(x=>x.domain);
 assert.deepEqual(JSON.parse(files['smart.singbox.json']).rules[0].domain_suffix,domains);
 assert.deepEqual(files['smart.domains.txt'].trim().split('\n'),domains.map(x=>'domain:'+x));
 const full=await readJson('dist/smart.xray.json');const explicit=full.routing.rules.find(r=>r.domain?.length===45);assert.deepEqual(explicit.domain,domains.map(x=>'domain:'+x));
 for(const host of domains){assert.ok(domains.some(d=>host===d||host.endsWith('.'+d)));assert.ok(domains.some(d=>('api.'+host).endsWith('.'+d)));assert.ok(!domains.some(d=>(host+'.unrelated.invalid').endsWith('.'+d)));}
});
test('the two existing measured exceptions remain active',()=>{for(const item of registry.measured_exceptions)assert.ok(activeEntries(registry).some(e=>e.domain===item.domain));});
test('unreviewed legacy provenance does not silently remove working services',async()=>{const p=await readJson('registry/provenance.json');const original=p.entries.filter(e=>e.origin==='existing-liberta-registry');assert.equal(original.length,111);assert.ok(original.every(e=>e.addedAt===null));assert.equal(activeEntries(registry).length,45);});
test('public registry rejects infrastructure fields and invalid names',()=>{
 const extra=structuredClone(registry);extra.nodes=[];assert.throws(()=>validateRegistry(extra));
 for(const domain of ['https://example.com','geoip:ru','geosite:category-ru','*.example.com','127.0.0.1','foo.local',' example.com'])assert.throws(()=>normalizeDomain(domain));
});
test('local integration changes the name without changing routing, DNS or connections',()=>{
 const base={remarks:'old',routing:{rules:[{outboundTag:'keep'}]},dns:{preserve:true},outbounds:[{tag:'proxy'}]};const copy=integrate(base,registry,'xray');assert.equal(copy.remarks,'Liberta Routing v1');copy.remarks=base.remarks;assert.deepEqual(copy,base);
});
test('canary rejects private and mixed DNS answers without changing the registry',async()=>{
 const before=json(registry);let calls=0;const report=await canary(registry,{resolveHost:async()=>['8.8.8.8','127.0.0.1'],probe:async()=>{calls++;}});assert.equal(calls,0);assert.equal(report.results.length,111);assert.equal(json(registry),before);assert.ok(!json(report).includes('8.8.8.8'));
});
test('special IPv4 and IPv6 addresses are refused',()=>{
 for(const x of ['127.0.0.1','169.254.169.254','192.168.1.1','100.64.0.1','2001:0db8::1','::1','::ffff:8.8.8.8'])assert.equal(isPublicAddress(x),false,x);
 for(const x of ['8.8.8.8','2001:4860:4860::8888'])assert.equal(isPublicAddress(x),true,x);
});
