import test from 'node:test';
import assert from 'node:assert/strict';
import {readJson,json} from '../scripts/lib.mjs';
import {certificateHosts,declaredHosts,quotedAssetHosts,discover,extractAssets,publicSource,validateDiscovery} from '../scripts/discover-services.mjs';
const registry=await readJson('registry/registry.json');
const config={schemaVersion:1,services:[{id:'test',domains:['tbank.ru'],pages:['https://tbank.ru/'],ctRoots:['tbank.ru'],asns:[]}]};
const response=(body,extra={})=>({result:'observed',status:200,body,sha256:'fixture',csp:'',...extra});
const dns=async()=>({a:'not-observed',aaaa:'not-observed',cnames:[]});
test('discovery follows approved public scripts and records external dependencies without fetching them',async()=>{
  const called=[];const before=json(registry);
  const report=await discover(config,registry,{dns,fetch:async url=>{called.push(url);return url.endsWith('/main.js')?response('"https://api.new-bank-cdn.net/"'):response('<script src="/main.js"></script><script src="https://third-party.net/script.js"></script>',{csp:"connect-src https://*.other-bank-cdn.net"});}});
  assert.ok(called.includes('https://tbank.ru/main.js'));
  assert.ok(!called.some(url=>url.startsWith('https://third-party.net/')));
  assert.ok(report.candidates.some(c=>c.domain==='api.new-bank-cdn.net'&&c.route==='review-required'));
  assert.ok(report.candidates.some(c=>c.domain==='other-bank-cdn.net'&&c.evidence.some(e=>e.type==='csp-reference')));
  assert.equal(json(registry),before);assert.equal(report.routesModified,false);
  assert.ok(report.candidates.find(c=>c.domain==='tbank.ru'),'missing A/AAAA must not remove a suffix');
});
test('discovery distinguishes a public error response from an application test',async()=>{
  const report=await discover(config,registry,{dns,fetch:async()=>response('',{status:498,csp:'script-src https://wbcontent.net'})});
  assert.equal(report.observations[0].httpStatus,498);assert.equal(report.applicationTests,false);
  assert.ok(report.candidates.some(c=>c.domain==='wbcontent.net'));assert.ok(!JSON.stringify(report).includes('set-cookie'));
});
test('certificate names remain candidates and invalid/private names are discarded',()=>{
  assert.deepEqual(certificateHosts([{name_value:'*.cdn.tbank.ru\nunknown-bank.net\n127.0.0.1\nbad.local'}]),['cdn.tbank.ru','unknown-bank.net']);
  assert.deepEqual(extractAssets('<script src="/main.js?key=secret"></script><script src="/ok.js"></script>','https://tbank.ru/'),['https://tbank.ru/ok.js']);
  assert.equal(publicSource('https://tbank.ru/path?secret=value#fragment'),'https://tbank.ru/path');
  assert.throws(()=>publicSource('https://user:secret@tbank.ru/'));
});
test('literal domain declarations include alternatives without copying scripts or promoting candidates',()=>{
  const hosts=declaredHosts('<p>*.vkuseraudio.(com|net), *.userapi.com, tbank.ru</p><script>foo.bar.ru</script>');
  assert.ok(hosts.includes('vkuseraudio.com'));assert.ok(hosts.includes('vkuseraudio.net'));assert.ok(hosts.includes('userapi.com'));assert.ok(!hosts.includes('foo.bar.ru'));
  assert.deepEqual(quotedAssetHosts('a.ru;ft.ru;const x="api.tbrands.pro";const ext="script.js"'),['api.tbrands.pro']);
});
test('request limits and unavailable sources are explicit, never empty successful updates',async()=>{
  let calls=0;const report=await discover(config,registry,{dns,maxRequests:0,fetch:async()=>{calls++;throw Error('unavailable');}});
  assert.equal(calls,0);assert.equal(report.limits.requestBudgetReached,true);
  assert.equal(report.observations[0].result,'budget-exhausted');assert.equal(report.routesModified,false);
});
test('ASN ownership mismatch prevents prefix collection',async()=>{
  const sample=structuredClone(config);sample.services[0].asns=[{number:49053,holderIncludes:'wildberries',source:'https://wildberries.ru/'}];
  const called=[];const report=await discover(sample,registry,{dns,networks:true,fetch:async url=>{called.push(url);return url.includes('as-overview')?response(JSON.stringify({data:{resource:'AS49053',holder:'An unrelated company'}})):response('');}});
  assert.ok(!called.some(url=>url.includes('announced-prefixes')));
  assert.ok(report.observations.some(x=>x.result==='inconclusive-or-holder-mismatch'));
});
test('discovery config validates only reviewed public seed URLs and unique service IDs',()=>{
  assert.doesNotThrow(()=>validateDiscovery(config));
  const bad=structuredClone(config);bad.services[0].pages=['https://127.0.0.1/'];assert.throws(()=>validateDiscovery(bad));
  const duplicate=structuredClone(config);duplicate.services.push(duplicate.services[0]);assert.throws(()=>validateDiscovery(duplicate));
});
