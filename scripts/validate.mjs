import { readJson, validateRegistry, validateProvenance, allEntries, ensure } from './lib.mjs';
try{
 const registry=validateRegistry(await readJson('registry/registry.json'));
 const provenance=await readJson('registry/provenance.json');
 validateProvenance(registry,provenance);
 const domains=allEntries(registry).map(x=>x.domain).sort();
 ensure(provenance.entries.map(x=>x.domain).sort().join(',')===domains.join(','),'provenance does not cover the complete registry');
 ensure((await readJson('package.json')).releaseTag==='v1.0.0','unexpected test release tag');
 console.log(`Current own registry: ${Object.keys(registry.classes).length} classes, ${domains.length} hosts; provenance complete.`);
}catch(error){console.error(error.message);process.exitCode=1;}
