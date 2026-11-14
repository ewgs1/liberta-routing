import test from 'node:test';
import assert from 'node:assert/strict';
import { readJson } from '../scripts/lib.mjs';
import { integrate } from '../scripts/integrate.mjs';
import { referencedHosts } from '../scripts/observe-sources.mjs';
import { pinnedLookup } from '../service-canary.mjs';
const template=await readJson('dist/liberta-v1.xray.json');
const registry=await readJson('registry/registry.json');
test('selective integration preserves connection credentials and the original input',()=>{
  const base=structuredClone(template);
  base.outbounds.push({tag:'proxy',protocol:'socks',settings:{servers:[{address:'proxy.example',port:443,users:[{user:'fixture',pass:'fixture'}]}]}});
  const before=structuredClone(base);
  const result=integrate(base,registry,'xray',{mode:'selective',template});
  assert.deepEqual(base,before);
  assert.deepEqual(result.outbounds,base.outbounds);
  assert.deepEqual(result.inbounds.map(({sniffing,...rest})=>rest),base.inbounds.map(({sniffing,...rest})=>rest));
  assert.equal(result.routing.rules.at(-1).outboundTag,'proxy');
  assert.ok(!JSON.stringify(result).includes('geosite:'));
  assert.throws(()=>integrate({...base,fakedns:{}},registry,'xray',{mode:'selective',template}),/FakeDNS/);
  assert.throws(()=>integrate(template,registry,'xray',{mode:'selective',template}),/outbounds/);
});
test('candidate extraction strips paths and queries and refuses IPs/local names',()=>{
  assert.deepEqual(referencedHosts('https://*.wbcontent.net https:\\/\\/basket-01.wbbasket.ru/path?secret=x https://127.0.0.1/private https://bad.local/'),['basket-01.wbbasket.ru','wbcontent.net']);
});
test('pinned HTTPS lookup supports Node single and all-address callback forms',()=>{
  const lookup=pinnedLookup('8.8.8.8');
  lookup('irrelevant',{all:true},(error,records)=>{assert.equal(error,null);assert.deepEqual(records,[{address:'8.8.8.8',family:4}]);});
  lookup('irrelevant',{},(error,address,family)=>{assert.equal(error,null);assert.equal(address,'8.8.8.8');assert.equal(family,4);});
  assert.throws(()=>pinnedLookup('127.0.0.1'),/unsafe/);
});
