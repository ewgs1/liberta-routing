import { readJson, validateRegistry, allEntries, activeEntries, json, sha256, args, ensure } from './scripts/lib.mjs';
const state=r=>{validateRegistry(r);return allEntries(r).map(entry=>({domain:entry.domain,class:entry.class,route:entry.route}));};
const compatibleState=r=>({explicit:activeEntries(r).map(x=>x.domain),classes:Object.fromEntries(Object.entries(r.classes).map(([k,v])=>[k,{policy:v.policy,explicit:v.explicit}]))});
const options=args(process.argv.slice(2),['--base']);
try{
 const registry=await readJson('registry/registry.json');
 const digest=sha256(json(state(registry)));
 const lock=await readJson('route-lock.json');ensure(lock.schemaVersion===2 && lock.routeSha256===digest,'route-lock differs from independent route selection');
 const compatible=validateRegistry(await readJson('registry/compatibility-v1.json'));
 ensure(sha256(json(compatibleState(compatible)))===lock.compatibilityRouteSha256,'compatible route selection changed');
 if(options['--base']){const previous=state(await readJson(options['--base']));const current=state(registry);console.log(json({changed:json(previous)!==json(current),added:current.filter(x=>!previous.some(p=>p.domain===x.domain)),removed:previous.filter(x=>!current.some(p=>p.domain===x.domain))}));}
 else console.log('Independent route selection and frozen compatible profile match their locks.');
}catch(error){console.error(error.message);process.exitCode=1;}
