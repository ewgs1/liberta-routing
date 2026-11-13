import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { ensure } from './lib.mjs';
try{
 const base=process.env.BASE_SHA;
 if(base&&!/^0+$/.test(base)){
  ensure(/^[a-f0-9]{40}$/.test(base),'invalid base SHA');
  let hasOriginalRegistry=false;
  try{execFileSync('git',['cat-file','-e',`${base}:registry/registry.json`],{stdio:'ignore'});hasOriginalRegistry=true;}catch{}
  if(hasOriginalRegistry){
   const diff=execFileSync('git',['diff','--name-status','--no-renames',base,'HEAD','--','releases/'],{encoding:'utf8'}).trim().split('\n').filter(Boolean);ensure(diff.every(line=>line.startsWith('A\t')),'published release changed');
   const previous=JSON.parse(execFileSync('git',['show',`${base}:registry/registry.json`],{encoding:'utf8'}));
   const current=JSON.parse(readFileSync('registry/registry.json','utf8'));
   const domains=r=>new Set(Object.values(r.classes).flatMap(group=>group.domains));
   const before=domains(previous),after=domains(current);
   console.log(JSON.stringify({independentRouteChanges:{added:[...after].filter(domain=>!before.has(domain)).sort(),removed:[...before].filter(domain=>!after.has(domain)).sort()}}));
   let hadSnapshot=false;
   try{execFileSync('git',['cat-file','-e',`${base}:registry/compatibility-v1.json`],{stdio:'ignore'});hadSnapshot=true;}catch{}
   if(hadSnapshot) ensure(execFileSync('git',['diff',base,'HEAD','--','registry/compatibility-v1.json'],{encoding:'utf8'}).length===0,'frozen compatible registry changed');
  }
  else console.log('Restoration of the original full registry; mistaken eight-host experiment removed from current tree.');
 }
}catch(error){console.error(error.message);process.exitCode=1;}
