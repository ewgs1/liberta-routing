import { mkdir, writeFile } from 'node:fs/promises';
import { args, ensure, json, readJson } from './lib.mjs';
import { validateCatalog, shardServices } from './catalog.mjs';
import { discover } from './discover-services.mjs';
import { privateOutput } from './integrate.mjs';
try {
  const options=args(process.argv.slice(2),['--shard','--shards','--out']);
  ensure(options['--out'],'--out required');
  const registry=await readJson('registry/registry.json');
  const catalog=validateCatalog(await readJson('registry/service-catalog.json'),registry);
  const services=shardServices(catalog,Number(options['--shard']??0),Number(options['--shards']??1));
  const results=[];
  // A separate bounded request budget for every service prevents early services starving the rest.
  for (const service of services) {
    const report=await discover({...catalog,services:[service]},registry,{maxRequests:4,maxDns:8,networks:service.asns.length>0});
    results.push(report);
    console.log(JSON.stringify({service:service.id,candidates:report.candidates.length,responses:report.observations.filter(o=>o.result==='observed').length,routesModified:false}));
  }
  await mkdir('.private',{recursive:true,mode:0o700});
  await writeFile(await privateOutput(options['--out'],''),json({schemaVersion:1,checkedAt:new Date().toISOString(),routesModified:false,services:results}),{mode:0o600,flag:'wx'});
} catch(error) {console.error(error.message);process.exitCode=1;}
