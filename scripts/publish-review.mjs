import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensure, json, readJson } from './lib.mjs';
let temporary;
try {
 const repository=process.env.GH_REPO,source=process.env.GITHUB_SHA,branch='automation/service-review';
 ensure(repository==='ewgs1/liberta-routing'&&process.env.GITHUB_REF==='refs/heads/main','review publication requires main');
 const queue=await readJson('.private/review-queue.json');ensure(queue.routesModified===false&&queue.services.length>0,'invalid candidate queue');
 temporary=await mkdtemp(join(tmpdir(),'liberta-review-'));let sequence=0;
 const api=async(method,path,body)=>{
  const argv=['api','--method',method,`repos/${repository}/${path}`];
  if(body){const input=join(temporary,`${sequence++}.json`);await writeFile(input,json(body));argv.push('--input',input);}
  const result=spawnSync('gh',argv,{encoding:'utf8',timeout:30000});ensure(result.status===0,'candidate PR API failed');return result.stdout.trim()?JSON.parse(result.stdout):null;
 };
 const main=await api('GET','git/ref/heads/main');ensure(main.object.sha===source,'main advanced during collection; collect again');
 const base=await api('GET',`git/commits/${source}`);
 const changes=[{path:'registry/review-queue.json',mode:'100644',type:'blob',content:json(queue)}];
 for(const path of ['registry/networks.json','registry/evidence/service-networks-latest.json','rules/manifest.json']) {
  try{changes.push({path,mode:'100644',type:'blob',content:await readFile(path,'utf8')});}catch(error){if(error.code!=='ENOENT')throw error;}
 }
 const tree=await api('POST','git/trees',{base_tree:base.tree.sha,tree:changes});
 const refs=await api('GET','git/matching-refs/heads/automation/service-review'),existing=refs.find(r=>r.ref===`refs/heads/${branch}`);
 if(existing){const old=await api('GET',`git/commits/${existing.object.sha}`);ensure(old.message.startsWith('Review service candidates from '),'review branch contains a manual commit; update refused');}
 const commit=await api('POST','git/commits',{message:`Review service candidates from ${source}`,tree:tree.sha,parents:[source]});
 if(existing)await api('PATCH',`git/refs/heads/${branch}`,{sha:commit.sha,force:true});else await api('POST','git/refs',{ref:`refs/heads/${branch}`,sha:commit.sha});
 const pulls=await api('GET',`pulls?state=open&head=ewgs1:${branch}`);
 const body='Автоматически собранные кандидаты из первичных источников. Доменные и IP-маршруты не изменены; обновляется очередь и актуальность уже одобренных сетей. Проверьте принадлежность и общие CDN перед переносом адресов в действующий реестр. Неполные или недоступные наблюдения не считаются успешными испытаниями приложений.';
 const pr=pulls[0]??await api('POST','pulls',{head:branch,base:'main',title:'Обзор новых доменных зависимостей',body});
 // workflow_dispatch explicitly triggers validation for a PR created by GITHUB_TOKEN.
 await api('POST','actions/workflows/ci.yml/dispatches',{ref:branch});
 console.log(`Candidate review PR: ${pr.html_url}`);
}catch(error){console.error(error.message);process.exitCode=1;}finally{if(temporary)await rm(temporary,{recursive:true,force:true});}
