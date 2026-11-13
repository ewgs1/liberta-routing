import { execFileSync } from 'node:child_process';
import { ensure } from './lib.mjs';
try{
 const base=process.env.BASE_SHA;
 if(base&&!/^0+$/.test(base)){
  ensure(/^[a-f0-9]{40}$/.test(base),'invalid base SHA');
  let hasOriginalRegistry=false;
  try{execFileSync('git',['cat-file','-e',`${base}:registry/registry.json`],{stdio:'ignore'});hasOriginalRegistry=true;}catch{}
  if(hasOriginalRegistry){const diff=execFileSync('git',['diff','--name-status','--no-renames',base,'HEAD','--','releases/'],{encoding:'utf8'}).trim().split('\n').filter(Boolean);ensure(diff.every(line=>line.startsWith('A\t')),'published release changed');}
  else console.log('Restoration of the original full registry; mistaken eight-host experiment removed from current tree.');
 }
}catch(error){console.error(error.message);process.exitCode=1;}
