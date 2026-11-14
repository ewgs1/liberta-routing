import { readdir, readFile, mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, ensure, json, normalizeDomain, publicHttps, readJson } from './lib.mjs';
import { privateOutput } from './integrate.mjs';
export function reviewQueue(reports, catalog) {
 const results=reports.flatMap(report=>report.services??[report]),byId=new Map();
 for(const report of results) {
  for(const entry of report.candidates??[]) {
   if(!byId.has(entry.service))byId.set(entry.service,[]);
   if(entry.route!=='review-required')continue;
   normalizeDomain(entry.domain);
   const evidence=entry.evidence.filter(e=>e.context!=='configured-seed').map(e=>{publicHttps(e.source);return {type:e.type,source:e.source,context:e.context};});
   if(evidence.length)byId.get(entry.service).push({domain:entry.domain,evidence});
  }
 }
 // Missing shards are failures, never a new empty candidate inventory.
 ensure(catalog.services.every(s=>byId.has(s.id)),'incomplete catalog observation; previous queue retained');
 return {schemaVersion:1,checkedAt:reports.map(r=>r.checkedAt).sort().at(-1),routesModified:false,
  services:catalog.services.map(s=>{const candidates=byId.get(s.id).sort((a,b)=>a.domain.localeCompare(b.domain));return {id:s.id,category:s.category,candidates:candidates.slice(0,20),candidateCount:candidates.length,truncated:candidates.length>20};})};
}
export async function reportFiles(directory) {const files=[];for(const entry of await readdir(directory,{withFileTypes:true})){const path=join(directory,entry.name);if(entry.isDirectory())files.push(...await reportFiles(path));else if(entry.name.endsWith('.json'))files.push(path);}return files;}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const options=args(process.argv.slice(2),['--input-dir','--out']);ensure(options['--input-dir']&&options['--out'],'input and output required');
  const paths=await reportFiles(options['--input-dir']);const queue=reviewQueue(await Promise.all(paths.map(readJson)),await readJson('registry/service-catalog.json'));
  await mkdir('.private',{recursive:true,mode:0o700});await writeFile(await privateOutput(options['--out'],''),json(queue),{mode:0o600,flag:'wx'});console.log(JSON.stringify({services:queue.services.length,candidates:queue.services.reduce((n,s)=>n+s.candidateCount,0),routesModified:false}));
 }catch(error){console.error(error.message);process.exitCode=1;}
}
