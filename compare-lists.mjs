import { readJson, validateRegistry, activeEntries, json, sha256, args, ensure } from './scripts/lib.mjs';
const state=r=>{validateRegistry(r);return {explicit:activeEntries(r).map(x=>x.domain),classes:Object.fromEntries(Object.entries(r.classes).map(([k,v])=>[k,{policy:v.policy,explicit:v.explicit}]))};};
const options=args(process.argv.slice(2),['--base']);
try{
 const registry=await readJson('registry/registry.json');
 const digest=sha256(json(state(registry)));
 const lock=await readJson('route-lock.json');ensure(lock.routeSha256===digest,'route-lock differs from existing route selection');
 if(options['--base']){const previous=state(await readJson(options['--base']));const current=state(registry);console.log(json({changed:json(previous)!==json(current),added:current.explicit.filter(x=>!previous.explicit.includes(x)),removed:previous.explicit.filter(x=>!current.explicit.includes(x))}));}
 else console.log('Existing route selection matches lock: '+digest);
}catch(error){console.error(error.message);process.exitCode=1;}
