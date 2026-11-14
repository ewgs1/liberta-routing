import { request } from 'node:https';
import { isIP } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, ensure, json, publicHttps, sha256 } from './lib.mjs';
import { dnsAddresses, pinnedLookup } from '../service-canary.mjs';
import { fetchPublic, extractAssets } from './discover-services.mjs';
import { privateOutput } from './integrate.mjs';
const allowed=host=>['2gis.ru','2gis.com'].some(root=>host===root||host.endsWith('.'+root));
export function apkLinks(body,base) {
 const urls=new Set();
 for(const match of body.replaceAll('\\/','/').matchAll(/["']([^"'<>\s]+\.apk(?:\?[^"'<>\s]*)?)["']/gi)) {
  try{const url=new URL(match[1],base);publicHttps(url.href);if(allowed(url.hostname))urls.add(url.href);}catch{}
 }
 return [...urls].sort();
}
async function download(url,redirects=0) {
 const target=publicHttps(url);ensure(allowed(target.hostname)&&redirects<4,'unapproved APK origin/redirect');
 const addresses=await dnsAddresses(target.hostname),address=addresses.find(a=>isIP(a)===4)??addresses[0];
 return new Promise((resolve,reject)=>{
  let size=0;const chunks=[];const req=request(target,{agent:false,lookup:pinnedLookup(address),headers:{'User-Agent':'LibertaRouting-APK/1.0'}},res=>{
   if([301,302,303,307,308].includes(res.statusCode)){res.resume();clearTimeout(timer);download(new URL(res.headers.location,target).href,redirects+1).then(resolve,reject);return;}
   if(res.statusCode!==200){res.resume();reject(Error('APK not available'));return;}
   res.on('data',chunk=>{size+=chunk.length;if(size>350_000_000)req.destroy(Error('APK too large'));else chunks.push(chunk);});
   res.on('error',reject);res.on('end',()=>{clearTimeout(timer);resolve(Buffer.concat(chunks));});
  });const timer=setTimeout(()=>req.destroy(Error('APK download timed out')),60000);
  req.on('error',error=>{clearTimeout(timer);reject(error);});req.end();
 });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try {
 const options=args(process.argv.slice(2),['--out','--download']);ensure(options['--out'],'--out required');
 const page='https://apk.2gis.ru/',response=await fetchPublic(page);ensure(response.status===200,'official APK page unavailable');
 const sources=[{url:page,sha256:response.sha256}];
 const found=new Set(apkLinks(response.body,page));
 for(const script of extractAssets(response.body,page).filter(url=>allowed(new URL(url).hostname)).slice(0,3)){
  const asset=await fetchPublic(script);if(asset.status===200){sources.push({url:script,sha256:asset.sha256});for(const url of apkLinks(asset.body,page))found.add(url);}
 }
 const links=[...found].sort();
 const report={schemaVersion:1,source:page,checkedAt:new Date().toISOString(),bodySha256:response.sha256,apkUrls:links,sources,routesModified:false};
 await mkdir('.private',{recursive:true,mode:0o700});
 await writeFile(await privateOutput(options['--out'],''),json(report),{flag:'wx',mode:0o600});
 if(options['--download']){ensure(links.length,'no approved APK link in official page');const bytes=await download(links[0]);ensure(bytes.subarray(0,2).toString()==='PK','APK is not a ZIP');await writeFile(await privateOutput(options['--download'],''),bytes,{flag:'wx',mode:0o600});report.downloadSha256=sha256(bytes);report.downloadedFrom=links[0];}
 await writeFile(await privateOutput(options['--out'],''),json(report),{mode:0o600});console.log(json(report));
}catch(error){console.error(error.message);process.exitCode=1;}
