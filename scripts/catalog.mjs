import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensure, normalizeDomain, publicHttps, readJson } from './lib.mjs';
import { selectedDomains } from './rule-sets.mjs';
export function validateCatalog(catalog, registry) {
  ensure(catalog.schemaVersion === 1 && Array.isArray(catalog.services), 'invalid service catalog');
  const active = new Set(), ids = new Set();
  for (const service of catalog.services) {
    ensure(/^[a-z0-9][a-z0-9-]*$/.test(service.id) && !ids.has(service.id), 'duplicate service id'); ids.add(service.id);
    ensure(typeof service.name === 'string' && /^[a-z][a-z0-9_]*$/.test(service.category), 'invalid service metadata');
    for (const key of ['domains','activeDomains','candidateDomains','pages','ctRoots','asns','products']) ensure(Array.isArray(service[key]), 'missing catalog collection');
    ensure(service.domains.length && service.pages.length, 'missing service seeds');
    ensure(new Set(service.domains).size === service.domains.length, 'duplicate seed');
    ensure([...service.activeDomains,...service.candidateDomains].sort().join() === [...service.domains].sort().join(), 'catalog classification mismatch');
    for (const domain of [...service.domains,...service.ctRoots]) ensure(normalizeDomain(domain) === domain, 'invalid catalog domain');
    for (const domain of service.activeDomains) { ensure(!active.has(domain), 'active domain assigned twice'); active.add(domain); }
    for (const page of service.pages) publicHttps(page);
  }
  ensure([...active].sort().join() === selectedDomains(registry).sort().join(), 'catalog must cover the current routing registry exactly');
  return catalog;
}
export function shardServices(catalog, index, count) {
  ensure(Number.isInteger(count) && count > 0 && count <= 32 && Number.isInteger(index) && index >= 0 && index < count, 'invalid catalog shard');
  return [...catalog.services].sort((a,b)=>a.id.localeCompare(b.id)).filter((_,i)=>i%count===index);
}
if (process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const catalog=validateCatalog(await readJson('registry/service-catalog.json'),await readJson('registry/registry.json'));
  console.log(JSON.stringify({services:catalog.services.length,categories:new Set(catalog.services.map(s=>s.category)).size,activeDomains:catalog.services.reduce((n,s)=>n+s.activeDomains.length,0),candidateDomains:catalog.services.reduce((n,s)=>n+s.candidateDomains.length,0)}));
}
