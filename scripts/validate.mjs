import { readJson, validateRegistry, validateProvenance, allEntries, ensure } from './lib.mjs';
import { validateNetworks } from './network-data.mjs';
import { validateCatalog } from './catalog.mjs';
try{
 const registry=validateRegistry(await readJson('registry/registry.json'));
 validateNetworks(await readJson('registry/networks.json'));
 validateCatalog(await readJson('registry/service-catalog.json'),registry);
 const provenance=await readJson('registry/provenance.json');
 validateProvenance(registry,provenance);
 const evidence=await readJson('registry/evidence/tbank-user-report.json');
 const reported=provenance.entries.filter(entry=>entry.origin==='operator-service-report');
 ensure(reported.every(entry=>evidence.acceptedDomains.includes(entry.domain)),'operator source does not cover domain');
 ensure(evidence.acceptanceForCurrentBuild===false && evidence.individuallyIsolatedDomains.length===0,'do not promote a historical group observation to current acceptance');
 const domains=allEntries(registry).map(x=>x.domain).sort();
 ensure(provenance.entries.map(x=>x.domain).sort().join(',')===domains.join(','),'provenance does not cover the complete registry');
 ensure((await readJson('package.json')).releaseTag==='v1.0.0','unexpected test release tag');
 console.log(`Current own registry: ${Object.keys(registry.classes).length} classes, ${domains.length} hosts; provenance complete.`);
}catch(error){console.error(error.message);process.exitCode=1;}
