import { mkdir, writeFile } from 'node:fs/promises';
import { args, ensure, json, publicHttps, readJson, sha256 } from './lib.mjs';
import { cidr } from './network-data.mjs';
import { fetchPublic } from './discover-services.mjs';
import { privateOutput } from './integrate.mjs';
try {
 const options=args(process.argv.slice(2),['--out']);ensure(options['--out'],'--out required');
 const config=await readJson('registry/network-sources.json'),observations=[];
 for(const service of config.services) {
  publicHttps(service.source);ensure(service.holderIncludes.length>=4,'holder proof required');
  for(const prefix of service.prefixes) {
   cidr(prefix);const record={service:service.id,prefix,source:service.source,result:'inconclusive',automaticRoutePromotion:false};observations.push(record);
   try{
    const response=await fetchPublic('https://stat.ripe.net/data/prefix-overview/data.json?resource='+encodeURIComponent(prefix),{api:true});
    ensure(response.status===200,'no network snapshot');const data=JSON.parse(response.body).data;
    record.snapshotSha256=response.sha256;record.announced=data.announced;record.resource=data.resource;
    record.origins=data.asns?.map(a=>({asn:a.asn,holder:a.holder}));
    record.result=data.announced&&data.resource===prefix&&data.asns?.length&&data.asns.every(a=>String(a.holder).toLowerCase().includes(service.holderIncludes))?'current-holder-matched':'review-required';
   }catch{}
  }
 }
 await mkdir('.private',{recursive:true,mode:0o700});await writeFile(await privateOutput(options['--out'],''),json({schemaVersion:1,checkedAt:new Date().toISOString(),routesModified:false,observations}),{mode:0o600,flag:'wx'});
 console.log(json({observations,routesModified:false}));
}catch(error){console.error(error.message);process.exitCode=1;}
