import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, ensure, json, readJson, sha256 } from './lib.mjs';
import { currentAnnouncements } from './network-data.mjs';
import { reportFiles } from './prepare-review-queue.mjs';
export function refreshNetworks(reports, current, catalog, now=new Date()) {
 const results=reports.flatMap(r=>r.services??[r]),observations=results.flatMap(r=>r.observations??[]);
 const announcements=[];
 for(const entry of current.entries) {
  const declaration=catalog.services.find(s=>s.id===entry.service)?.asns.find(a=>a.number===entry.asn&&a.source===entry.source);
  ensure(declaration,'approved network has no current first-party ASN declaration');
  const record=observations.find(o=>o.service===entry.service&&o.asn===entry.asn&&o.result==='holder-matched'&&o.source===entry.source&&o.holder===entry.holder);
  ensure(record&&record.holder.toLowerCase().includes(declaration.holderIncludes.toLowerCase()),'network observation unavailable; previous registry retained');
  const prefixes=currentAnnouncements({query_endtime:record.window?.end,prefixes:record.prefixes},now);
  ensure(prefixes.includes(entry.prefix),'approved network withdrawn or absent; explicit route review required');
  if(!announcements.some(a=>a.asn===record.asn))announcements.push({source:record.source,asn:record.asn,holder:record.holder,window:record.window,currentPrefixes:[],historicalOnlyPrefixes:[]});
  announcements.find(a=>a.asn===record.asn).currentPrefixes.push(entry.prefix);
 }
 const checkedAt=now.toISOString().slice(0,10),validUntil=new Date(Date.parse(checkedAt+'T00:00:00Z')+7*86400000).toISOString().slice(0,10);
 const evidence={schemaVersion:1,checkedAt:now.toISOString(),source:current.entries[0]?.source??'https://stat.ripe.net/',announcements};
 const snapshotSha256=sha256(json(evidence));
 return {evidence,registry:{...structuredClone(current),entries:current.entries.map(e=>({...e,checkedAt,validUntil,snapshotSha256}))}};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 try {
  const options=args(process.argv.slice(2),['--input-dir']);ensure(options['--input-dir'],'input directory required');
  const reports=await Promise.all((await reportFiles(options['--input-dir'])).map(readJson));
  const current=await readJson('registry/networks.json');
  if(current.entries.length){const refreshed=refreshNetworks(reports,current,await readJson('registry/service-catalog.json'));
   await writeFile('registry/evidence/service-networks-latest.json',json(refreshed.evidence));await writeFile('registry/networks.json',json(refreshed.registry));console.log('Existing service networks refreshed for PR review; route selection unchanged');}
 } catch(error){console.error(error.message);process.exitCode=1;}
}
