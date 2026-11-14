import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ensure } from './lib.mjs';
try{
 const base=process.env.BASE_SHA||execFileSync('git',['merge-base','HEAD','origin/main'],{encoding:'utf8'}).trim();
 if(base&&!/^0+$/.test(base)){
  ensure(/^[a-f0-9]{40}$/.test(base),'invalid base SHA');
  let hasOriginalRegistry=false;
  try{execFileSync('git',['cat-file','-e',`${base}:registry/registry.json`],{stdio:'ignore'});hasOriginalRegistry=true;}catch{}
  if(hasOriginalRegistry){
   const diff=execFileSync('git',['diff','--name-status','--no-renames',base,'HEAD','--','releases/'],{encoding:'utf8'}).trim().split('\n').filter(Boolean);if(!diff.every(line=>line.startsWith('A\t'))) {
    // A filename-only migration is accepted only when every published payload is byte-identical.
    const old=JSON.parse(execFileSync('git',['show',`${base}:releases/v1.0.0/release.json`],{encoding:'utf8'}));
    const currentRelease=JSON.parse(readFileSync('releases/v1.0.0/release.json','utf8'));
    const metadata=({files,...rest})=>rest;
    ensure(JSON.stringify(metadata(old))===JSON.stringify(metadata(currentRelease)),'published release metadata changed');
    ensure(Object.keys(old.files).length===Object.keys(currentRelease.files).length,'published payload count changed');
    const allowed=new Set(['releases/v1.0.0/release.json']);
    for(const [oldName,info] of Object.entries(old.files)) {
      const matches=Object.entries(currentRelease.files).filter(([,x])=>JSON.stringify(x)===JSON.stringify(info));
      ensure(matches.length===1,'published payload identity changed');
      const newName=matches[0][0];ensure(!newName.includes('/'),'unsafe release name');
      const previousBytes=execFileSync('git',['show',`${base}:releases/v1.0.0/${oldName}`]);
      const currentBytes=readFileSync(`releases/v1.0.0/${newName}`);
      ensure(previousBytes.equals(currentBytes)&&createHash('sha256').update(currentBytes).digest('hex')===info.sha256,'published payload bytes changed');
      allowed.add(`releases/v1.0.0/${oldName}`);allowed.add(`releases/v1.0.0/${newName}`);
    }
    ensure(diff.every(line=>allowed.has(line.slice(2))),'unrelated published release changed');
   }
   const previous=JSON.parse(execFileSync('git',['show',`${base}:registry/registry.json`],{encoding:'utf8'}));
   const current=JSON.parse(readFileSync('registry/registry.json','utf8'));
   const domains=r=>new Set(Object.values(r.classes).flatMap(group=>group.domains));
   const before=domains(previous),after=domains(current);
   console.log(JSON.stringify({independentRouteChanges:{added:[...after].filter(domain=>!before.has(domain)).sort(),removed:[...before].filter(domain=>!after.has(domain)).sort()}}));
   try {
    const beforeIp=JSON.parse(execFileSync('git',['show',`${base}:registry/networks.json`],{encoding:'utf8'})).entries.map(e=>e.prefix);
    const afterIp=JSON.parse(readFileSync('registry/networks.json','utf8')).entries.map(e=>e.prefix);
    console.log(JSON.stringify({serviceIpChanges:{added:afterIp.filter(p=>!beforeIp.includes(p)),removed:beforeIp.filter(p=>!afterIp.includes(p))}}));
   }catch(error){if(!String(error.message).includes('does not exist'))console.log('Previous source has no service-IP registry; new routes require review.');}
   let hadSnapshot=false;
   try{execFileSync('git',['cat-file','-e',`${base}:registry/compatibility-v1.json`],{stdio:'ignore'});hadSnapshot=true;}catch{}
   if(hadSnapshot) ensure(execFileSync('git',['diff',base,'HEAD','--','registry/compatibility-v1.json'],{encoding:'utf8'}).length===0,'frozen compatible registry changed');
  }
  else console.log('Restoration of the original full registry; mistaken eight-host experiment removed from current tree.');
 }
}catch(error){console.error(error.message);process.exitCode=1;}
