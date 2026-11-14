import { readFile, readdir } from 'node:fs/promises';
import { sha256, publicHttps, normalizeDomain, readJson, validateRegistry, validateProvenance, allEntries, ensure } from './lib.mjs';
import { validateNetworks } from './network-data.mjs';
import { validateCatalog } from './catalog.mjs';
try{
 const registry=validateRegistry(await readJson('registry/registry.json'));
 const networks=validateNetworks(await readJson('registry/networks.json'));
 const snapshots=await Promise.all((await readdir('registry/evidence')).filter(p=>p.includes('-networks-')&&p.endsWith('.json')).map(async p=>{const bytes=await readFile('registry/evidence/'+p);return {sha256:sha256(bytes),data:JSON.parse(bytes)};}));
 for(const entry of networks.entries)ensure(snapshots.some(s=>s.sha256===entry.snapshotSha256&&s.data.announcements.some(a=>(a.source??s.data.source)===entry.source&&a.asn===entry.asn&&a.holder===entry.holder&&a.currentPrefixes.includes(entry.prefix))),'network snapshot does not cover approved prefix');
 validateCatalog(await readJson('registry/service-catalog.json'),registry);
 const apps=await readJson('registry/application-sources.json');ensure(apps.schemaVersion===1&&Array.isArray(apps.services),'invalid APK source configuration');for(const app of apps.services){ensure(Array.isArray(app.pages)&&app.pages.length&&Array.isArray(app.downloadDomains)&&app.downloadDomains.length,'missing APK sources');for(const url of app.pages)publicHttps(url);for(const domain of app.downloadDomains)ensure(normalizeDomain(domain)===domain,'invalid APK origin');}
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
