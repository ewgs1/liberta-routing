import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateCatalog, shardServices } from '../scripts/catalog.mjs';
import { summarizeObservations } from '../scripts/import-observations.mjs';
import { makePlan, applyPlan } from '../scripts/remnawave-sync.mjs';
const registry=JSON.parse(await readFile('registry/registry.json','utf8'));
const catalog=JSON.parse(await readFile('registry/service-catalog.json','utf8'));
const generated=JSON.parse(await readFile('dist/liberta.xray.json','utf8'));
test('catalog shards cover every service once and active roots equal the routing registry',()=>{
  validateCatalog(catalog,registry);
  const ids=Array.from({length:10},(_,i)=>shardServices(catalog,i,10)).flat().map(s=>s.id);
  assert.equal(ids.length,catalog.services.length);assert.equal(new Set(ids).size,ids.length);
  const broken=structuredClone(catalog);broken.services[0].activeDomains.push('unreviewed.ru');assert.throws(()=>validateCatalog(broken,registry));
});
test('device observations drop source addresses, identities and paths; unclassified IPs remain explicit',()=>{
  const input='2026 from 192.168.2.7:123 accepted tcp:api.tbank.ru:443 [socks -> direct] email: private@invalid\n2026 accepted tcp:203.0.113.1:443\n2026 accepted udp:[2001:db8::1]:443\nraw credential';
  const result=summarizeObservations(input,registry,'xray');
  assert.equal(result.unidentifiedIpConnections,2);assert.equal(result.unparsed,1);assert.equal(result.destinations[0].route,'direct');
  assert.doesNotMatch(JSON.stringify(result),/192\.168|203\.0|2001:db8|private@|credential/);
});
test('Remnawave deployment preserves connections, rejects drift and supports a verified rollback',async()=>{
  const template={uuid:'11111111-1111-4111-8111-111111111111',templateType:'XRAY_JSON',templateJson:{...structuredClone(generated),outbounds:[...generated.outbounds,{tag:'proxy',protocol:'socks',settings:{servers:[{address:'unit.invalid',port:443}]}}]}};
  const plan=makePlan(template,generated,'a'.repeat(40));
  assert.deepEqual(plan.after.outbounds,template.templateJson.outbounds);
  let current=structuredClone(template),writes=0;
  const api=async(method,path,body)=>{if(method==='GET')return structuredClone(current);writes++;current.templateJson=structuredClone(body.templateJson);return current;};
  await applyPlan(plan,api);assert.equal(writes,1);
  await assert.rejects(()=>applyPlan(plan,api),/changed since plan/);assert.equal(writes,1);
  await applyPlan(plan,api,{rollback:true});assert.deepEqual(current,template);
  const tampered=structuredClone(plan);tampered.after.remarks='modified';await assert.rejects(()=>applyPlan(tampered,api),/modified deployment/);
});

import { reviewQueue } from '../scripts/prepare-review-queue.mjs';
import { apkLinks } from '../scripts/observe-apk.mjs';
test('incomplete daily observations cannot replace the complete review queue',()=>{
 assert.throws(()=>reviewQueue([],catalog),/incomplete/);
 const reports=[{checkedAt:'2026-11-14T00:00:00Z',services:catalog.services.map(s=>({candidates:[{service:s.id,domain:s.domains[0],route:'already-covered',evidence:[]}]}))}];
 assert.equal(reviewQueue(reports,catalog).services.length,catalog.services.length);
});
test('official APK discovery refuses third-party mirrors, credentials and query parameters',()=>{
 assert.deepEqual(apkLinks('<a href="https://download.2gis.ru/app.apk">ok</a><a href="https://unrelated.net/app.apk">mirror</a><a href="https://user:pass@apk.2gis.ru/app.apk">bad</a>','https://apk.2gis.ru/'),['https://download.2gis.ru/app.apk']);
});
