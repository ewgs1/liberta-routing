import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdtemp, rm, mkdir, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { args, readJson, validateRegistry, render, activeEntries, allEntries, json, sha256, ensure, atomicDirectory } from './scripts/lib.mjs';

const options=args(process.argv.slice(2),['--check','--out']);
let temp;
try {
  const registry=validateRegistry(await readJson('registry/registry.json'));
  const meta=await readJson('package.json');
  temp=await mkdtemp(join(tmpdir(),'liberta-compatible-build-'));
  const target=join(temp,'config.json');
  const result=spawnSync(process.execPath,['scripts/build.mjs','--out',target],{encoding:'utf8',timeout:15000});
  ensure(!result.error && result.status===0,'existing builder failed');
  const files={...render(registry),'smart.xray.json':await readFile(target,'utf8')};
  const xray=JSON.parse(files['smart.xray.json']);
  const behavior=structuredClone(xray);delete behavior.remarks;
  files['release.json']=json({schemaVersion:2,version:meta.version,releaseTag:meta.releaseTag,name:'Liberta Routing v1',registryDomains:allEntries(registry).length,explicitDomains:activeEntries(registry).length,behaviorSha256:sha256(json(behavior)),singboxScope:'explicit-domain-rules-only',files:Object.fromEntries(Object.entries(files).map(([name,body])=>[name,{sha256:sha256(body),bytes:Buffer.byteLength(body)}]))});
  const output=options['--out']??`releases/${meta.releaseTag}`;
  if(options['--check']) {
    ensure((await readdir(output)).sort().join(',')===Object.keys(files).sort().join(','),'unexpected release files');
    for(const [name,body] of Object.entries(files)) ensure(await readFile(join(output,name),'utf8')===body,`release differs: ${name}`);
    for(const name of ['smart.xray.json','smart.singbox.json','smart.domains.txt']) ensure(await readFile(join('dist',name),'utf8')===files[name],`dist differs: ${name}`);
  } else {
    await atomicDirectory(output,files);
    if(!options['--out']) {
      await mkdir('dist',{recursive:true});
      for(const name of ['smart.xray.json','smart.singbox.json','smart.domains.txt']) await writeFile(join('dist',name),files[name]);
    }
  }
  console.log(`Liberta Routing v1: ${allEntries(registry).length} registry hosts, ${activeEntries(registry).length} explicit domains; existing Xray routing and DNS preserved.`);
} catch(error){console.error(error.message);process.exitCode=1;}
finally{if(temp)await rm(temp,{recursive:true,force:true});}
