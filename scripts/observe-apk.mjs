import { request } from 'node:https';
import { isIP } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, ensure, json, publicHttps, sha256, readJson } from './lib.mjs';
import { dnsAddresses, pinnedLookup } from '../service-canary.mjs';
import { fetchPublic, extractAssets } from './discover-services.mjs';
import { privateOutput } from './integrate.mjs';
const defaults=['2gis.ru','2gis.com'];
const allowed=(host,roots=defaults)=>roots.some(root=>host===root||host.endsWith('.'+root));
export function apkLinks(body,base,roots=defaults) {
 const urls=new Set();
 for(const match of body.replace(/\\u([a-f0-9]{4})/gi,(_,hex)=>String.fromCharCode(parseInt(hex,16))).replaceAll('\\/','/').matchAll(/["']([^"'<>\s]+\.apk(?:\?[^"'<>\s]*)?)["']/gi)) {
  try{const url=new URL(match[1],base);publicHttps(url.href);if(allowed(url.hostname,roots))urls.add(url.href);}catch{}
 }
 return [...urls].sort();
}
async function download(url,roots,redirects=0) {
 const target=publicHttps(url);ensure(allowed(target.hostname,roots)&&redirects<4,'unapproved APK origin/redirect');
 const addresses=await dnsAddresses(target.hostname),address=addresses.find(a=>isIP(a)===4)??addresses[0];
 return new Promise((resolve,reject)=>{
  let size=0;const chunks=[];const req=request(target,{agent:false,lookup:pinnedLookup(address),headers:{'User-Agent':'LibertaRouting-APK/1.0'}},res=>{
   if([301,302,303,307,308].includes(res.statusCode)){res.resume();clearTimeout(timer);download(new URL(res.headers.location,target).href,roots,redirects+1).then(resolve,reject);return;}
   if(res.statusCode!==200){res.resume();clearTimeout(timer);reject(Error('APK not available'));return;}
   res.on('data',chunk=>{size+=chunk.length;if(size>350_000_000)req.destroy(Error('APK too large'));else chunks.push(chunk);});
   res.on('error',error=>{clearTimeout(timer);reject(error);});res.on('end',()=>{clearTimeout(timer);resolve(Buffer.concat(chunks));});
  });const timer=setTimeout(()=>req.destroy(Error('APK download timed out')),60000);
  req.on('error',error=>{clearTimeout(timer);reject(error);});req.end();
 });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try {
 const options=args(process.argv.slice(2),['--out','--download','--service']);ensure(options['--out'],'--out required');
 const config=await readJson('registry/application-sources.json'),service=config.services.find(s=>s.id===(options['--service']??'2gis'));
 ensure(service,'unknown APK service');const roots=service.downloadDomains;
 const sources=[],found=new Set();let scripts=0,metadata=0;
 for(const page of service.pages){
  const response=await fetchPublic(page);if(response.status!==200){sources.push({url:page,result:'inconclusive',httpStatus:response.status});continue;}
  sources.push({url:page,sha256:response.sha256});for(const url of apkLinks(response.body,page,roots))found.add(url);
  for(const match of response.body.matchAll(/\bdata-url=["']([^"']+\.json)["']/gi)){
   if(metadata>=3)break;
   try{const target=publicHttps(new URL(match[1],page).href);if(!allowed(target.hostname,roots))continue;metadata++;
    const data=await fetchPublic(target.href);if(data.status===200){sources.push({url:target.href,sha256:data.sha256});for(const url of apkLinks(data.body,page,roots))found.add(url);}
   }catch{}
  }
  for(const script of extractAssets(response.body,page).filter(url=>allowed(new URL(url).hostname,roots))){
   if(scripts>=3)break;scripts++;const asset=await fetchPublic(script);if(asset.status===200){sources.push({url:script,sha256:asset.sha256});for(const url of apkLinks(asset.body,page,roots))found.add(url);}
  }
 }
 const links=[...found].sort();
 const report={schemaVersion:1,service:service.id,checkedAt:new Date().toISOString(),apkUrls:links,sources,routesModified:false};
 await mkdir('.private',{recursive:true,mode:0o700});
 await writeFile(await privateOutput(options['--out'],''),json(report),{flag:'wx',mode:0o600});
 if(options['--download']){ensure(links.length,'no approved APK link in official page');const bytes=await download(links[0],roots);ensure(bytes.subarray(0,2).toString()==='PK','APK is not a ZIP');await writeFile(await privateOutput(options['--download'],''),bytes,{flag:'wx',mode:0o600});report.downloadSha256=sha256(bytes);report.downloadedFrom=links[0];}
 await writeFile(await privateOutput(options['--out'],''),json(report),{mode:0o600});console.log(json(report));
}catch(error){console.error(error.message);process.exitCode=1;}
