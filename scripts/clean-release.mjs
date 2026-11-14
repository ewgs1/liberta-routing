import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensure, json } from './lib.mjs';
let temporary;
try {
 ensure(process.env.GH_REPO==='ewgs1/liberta-routing'&&process.env.GITHUB_REF==='refs/heads/main','main publication required');
 temporary=await mkdtemp(join(tmpdir(),'liberta-release-'));
 let sequence=0;
 const api=async(method,path,body)=>{
  const argv=['api','--method',method,`repos/${process.env.GH_REPO}/${path}`];
  if(body){const file=join(temporary,`${sequence++}.json`);await writeFile(file,json(body));argv.push('--input',file);}
  const result=spawnSync('gh',argv,{encoding:'utf8',timeout:30000});ensure(result.status===0,'release housekeeping API failed');return result.stdout.trim()?JSON.parse(result.stdout):null;
 };
 const release=await api('GET','releases/tags/v1.0.0');
 const manifest=JSON.parse(await readFile('releases/v1.0.0/release.json','utf8'));
 for(const [name,info] of Object.entries(manifest.files)) {
  const extension=name.slice('liberta-v1'.length);
  const matches=release.assets.filter(a=>a.name.endsWith(extension)&&a.size===info.bytes);
  ensure(matches.length===1,'release asset identity ambiguous');const asset=matches[0];
  ensure(asset.digest===`sha256:${info.sha256}`,'release asset digest differs');
  if(asset.name!==name)await api('PATCH',`releases/assets/${asset.id}`,{name});
 }
 const body='Первая тестовая версия Liberta Routing. Совместимый профиль сохраняет прежнее поведение. Новые независимые наборы и клиентский шаблон публикуются в ветке release; актуальные инструкции — в README. Испытания приложений на устройствах отмечаются отдельно в матрице совместимости.';
 await api('PATCH',`releases/${release.id}`,{name:'Liberta Routing v1.0.0',body});
 // Replace only the filename manifest. The three routing payloads remain byte-identical.
 const oldManifest=release.assets.find(a=>a.name==='release.json');
 if(oldManifest)await api('DELETE',`releases/assets/${oldManifest.id}`);
 const result=spawnSync('gh',['release','upload','v1.0.0','releases/v1.0.0/release.json','--repo',process.env.GH_REPO],{encoding:'utf8',timeout:30000});
 ensure(result.status===0,'release manifest upload failed');console.log('v1.0.0 names and notes updated; routing payload bytes preserved');
} catch(error){console.error(error.message);process.exitCode=1;}finally{if(temporary)await rm(temporary,{recursive:true,force:true});}
