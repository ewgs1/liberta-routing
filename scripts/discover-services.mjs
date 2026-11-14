import { request } from 'node:https';
import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dnsAddresses, pinnedLookup } from '../service-canary.mjs';
import { privateOutput } from './integrate.mjs';
import { args, ensure, json, normalizeDomain, publicHttps, readJson, sha256 } from './lib.mjs';
import { referencedHosts } from './observe-sources.mjs';
import { matchesDomain, PROXY_DOMAINS, selectedDomains } from './rule-sets.mjs';

export function validateDiscovery(config) {
  ensure(config.schemaVersion === 1 && Array.isArray(config.services) && config.services.length > 0, 'invalid discovery configuration');
  const ids = new Set();
  for (const service of config.services) {
    ensure(/^[a-z0-9][a-z0-9-]*$/.test(service.id) && !ids.has(service.id), 'duplicate/invalid discovery service'); ids.add(service.id);
    for (const key of ['domains','pages','ctRoots','asns']) ensure(Array.isArray(service[key]), 'missing discovery collection');
    ensure(service.domains.length && service.pages.length, 'service requires seed domains and pages');
    for (const domain of [...service.domains,...service.ctRoots]) ensure(normalizeDomain(domain) === domain, 'invalid discovery domain');
    for (const url of service.pages) publicHttps(url);
    for (const asn of service.asns) {
      ensure(Number.isSafeInteger(asn.number) && asn.number > 0 && asn.number < 4294967295 && typeof asn.holderIncludes === 'string' && asn.holderIncludes.length >= 4, 'ASN requires number and owner check'); publicHttps(asn.source);
    }
  }
  return config;
}
export function publicSource(value) {
  const url = new URL(value); url.search = ''; url.hash = '';
  return publicHttps(url.href).href;
}
export function extractAssets(body, base) {
  const urls = new Set();
  for (const match of body.matchAll(/<(?:script|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    try { const url = new URL(match[1],base); if (/\.(?:js|mjs|css)$/i.test(url.pathname) && !url.search && !url.hash) urls.add(publicHttps(url.href).href); } catch {}
  }
  return [...urls].sort();
}
export function certificateHosts(records) {
  ensure(Array.isArray(records), 'invalid certificate response');
  const names = new Set();
  for (const record of records) for (const name of String(record.name_value ?? '').split(/\s+/)) {
    try { names.add(normalizeDomain(name.replace(/^\*\./,''))); } catch {}
  }
  return [...names].sort();
}
export function declaredHosts(body) {
  // Extract literal hostnames from a document, not arbitrary JavaScript identifiers.
  const text=body.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi,' ').replace(/<[^>]*>/g,' ');
  const variants=[text];
  for(const value of text.matchAll(/([a-z0-9.-]+)\.\((com|net|ru)(?:\|(com|net|ru))+\)/gi)) {
    const parts=value[0].match(/\(([^)]+)\)/)[1].split('|');for(const suffix of parts)variants.push(value[1]+'.'+suffix);
  }
  const names=new Set();
  for(const value of variants)for(const match of value.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:ru|su|com|net|org|io|app|tech|cloud|online|me|cc|link|by|kz|yandex|dev|pro|tv|one|aero)(?![a-z0-9.-])/gi)) {
    try{names.add(normalizeDomain(match[0]));}catch{}
  }
  return [...names].sort();
}
export function quotedAssetHosts(body) {
  const names=new Set();
  for(const match of body.matchAll(/["'`]([a-z0-9*.-]+)["'`]/gi))for(const host of declaredHosts(match[1]))if(match[1].replace(/^\*\./,'')===host)names.add(host);
  return [...names].sort();
}
export async function fetchPublic(url, { api = false } = {}) {
  const target = new URL(url);
  ensure(!target.username && !target.password && (!target.port || target.port === '443') && target.protocol === 'https:', 'unsafe source URL');
  normalizeDomain(target.hostname);
  if (!api) publicHttps(target.href);
  else ensure(['crt.sh','stat.ripe.net'].includes(target.hostname), 'unknown discovery API');
  const addresses = await dnsAddresses(target.hostname);
  const address = addresses.find(value => isIP(value) === 4) ?? addresses[0];
  return new Promise(resolveResult => {
    let settled = false, size = 0;
    const done = value => { if (!settled) { settled = true; clearTimeout(timer); resolveResult(value); } };
    const req = request(target, { method:'GET', agent:false, rejectUnauthorized:true, lookup:pinnedLookup(address), headers:{'User-Agent':'LibertaRouting-Discovery/1.0',Accept:'text/html,application/json,text/javascript','Accept-Encoding':'identity'} }, res => {
      const chunks = [];
      res.on('data',chunk => {size += chunk.length; if(size > 8_000_000) req.destroy(); else chunks.push(chunk);});
      res.on('error',()=>done({result:'inconclusive'}));
      res.on('end',()=>{
        const body = Buffer.concat(chunks);
        done({result:'observed',status:res.statusCode,body:body.toString('utf8'),sha256:sha256(body),csp:[res.headers['content-security-policy'],res.headers['content-security-policy-report-only']].filter(Boolean).join('\n'),location:res.headers.location});
      });
    });
    const timer = setTimeout(()=>req.destroy(),10000);
    req.on('error',()=>done({result:'inconclusive'})); req.on('close',()=>done({result:'inconclusive'})); req.end();
  });
}
export async function dnsObservation(domain) {
  const resolver = new Resolver({timeout:1500,tries:1}); const timer = setTimeout(()=>resolver.cancel(),2000);
  try {
    const results = await Promise.allSettled([resolver.resolve4(domain),resolver.resolve6(domain),resolver.resolveCname(domain)]);
    const values = index => results[index].status === 'fulfilled' ? results[index].value : [];
    return {a:values(0).length?'observed':'not-observed',aaaa:values(1).length?'observed':'not-observed',cnames:values(2).flatMap(name=>{try{return [normalizeDomain(name)];}catch{return [];}})};
  } finally {clearTimeout(timer);}
}
export async function discover(config, registry, {fetch=fetchPublic, dns=dnsObservation, ct=false, networks=false, maxRequests=32, maxDns=32, now=new Date()}={}) {
  validateDiscovery(config); const known=selectedDomains(registry);
  const reports=[], candidates=new Map(); let requests=0, dnsChecks=0;
  const add=(service,domain,type,source,context='service-response')=>{
    try {domain=normalizeDomain(domain);} catch {return;}
    const key=service.id+'|'+domain;
    if(!candidates.has(key)) candidates.set(key,{service:service.id,domain,route:PROXY_DOMAINS.some(suffix=>matchesDomain(domain,suffix))?'proxy-exception':known.some(suffix=>matchesDomain(domain,suffix))?'already-covered':'review-required',evidence:[]});
    const entry=candidates.get(key), proof={type,source,context};
    if(!entry.evidence.some(p=>p.type===type&&p.source===source&&p.context===context)) entry.evidence.push(proof);
  };
  const get=async(url,api=false)=>{
    if(requests>=maxRequests)return {result:'budget-exhausted'};
    requests++;try{return await fetch(url,{api});}catch{return {result:'inconclusive'};}
  };
  for(const service of config.services) {
    for(const domain of service.domains)add(service,domain,'configured-seed','registry/discovery-sources.json','configured-seed');
    const pages=[...service.pages], visited=new Set(); let assets=0;
    while(pages.length) {
      const url=pages.shift();if(visited.has(url))continue;visited.add(url);
      const response=await get(url);
      const record={service:service.id,source:publicSource(url),result:response.result,...response.status?{httpStatus:response.status,bodySha256:response.sha256}: {}};reports.push(record);
      if(response.result!=='observed')continue;
      const ownedPage=service.domains.some(suffix=>matchesDomain(new URL(url).hostname,suffix));
      const context=ownedPage?'service-response':'reference-document';
      for(const name of referencedHosts(response.body??''))add(service,name,'page-reference',record.source,context);
      if(ownedPage)for(const name of referencedHosts(response.csp??''))add(service,name,'csp-reference',record.source,context);
      const asset=/\.(?:js|mjs|css)$/i.test(new URL(url).pathname);
      for(const name of asset?quotedAssetHosts(response.body??''):declaredHosts(response.body??''))add(service,name,asset?'asset-host-literal':'document-literal',record.source,context);
      const follow=[];
      if(response.location){try{const target=new URL(response.location,url);add(service,target.hostname,'redirect-reference',record.source);follow.push(publicHttps(target.href).href);}catch{}}
      if(ownedPage&&assets<3)for(const asset of extractAssets(response.body??'',url)) {if(assets>=3)break;if(service.domains.some(suffix=>matchesDomain(new URL(asset).hostname,suffix))){follow.push(asset);assets++;}}
      for(const next of follow)if(service.domains.some(suffix=>matchesDomain(new URL(next).hostname,suffix))&&!visited.has(next))pages.push(next);
      if(visited.size>=8)break;
    }
    if(ct)for(const root of service.ctRoots){
      const response=await get('https://crt.sh/?q='+encodeURIComponent('%.'+root)+'&output=json',true);
      const source='https://crt.sh/';reports.push({service:service.id,source,root,result:response.result,httpStatus:response.status});
      if(response.status===200)try{for(const domain of certificateHosts(JSON.parse(response.body)))add(service,domain,'certificate-name',source,'certificate-record');}catch{reports.at(-1).result='parse-failed';}
    }
    if(networks)for(const asn of service.asns){
      const response=await get(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn.number}`,true);
      const record={service:service.id,asn:asn.number,source:asn.source,result:'inconclusive',automaticRoutePromotion:false};reports.push(record);
      try{
        ensure(response.status===200,'no ASN result');const overview=JSON.parse(response.body).data;
        ensure(overview.resource===`AS${asn.number}`||Number(overview.resource)===asn.number,'ASN mismatch');
        ensure(String(overview.holder).toLowerCase().includes(asn.holderIncludes.toLowerCase()),'holder mismatch');
        record.holder=overview.holder;record.result='holder-matched';
        const result=await get(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn.number}`,true);
        if(result.status===200){const data=JSON.parse(result.body).data;record.prefixes=(data.prefixes??[]).map(p=>({prefix:p.prefix,timelines:p.timelines}));record.window={start:data.query_starttime,end:data.query_endtime};}
      }catch{record.result='inconclusive-or-holder-mismatch';}
    }
  }
  // Each DNS observation records names/counts, never collector or endpoint IPs.
  const groups=config.services.map(service=>[...candidates.values()].filter(entry=>entry.service===service.id).sort((a,b)=>Number(service.domains.some(s=>matchesDomain(b.domain,s)))-Number(service.domains.some(s=>matchesDomain(a.domain,s)))));
  const queue=[];
  while(queue.length<maxDns&&groups.some(group=>group.length))for(const group of groups)if(group.length&&queue.length<maxDns)queue.push(group.shift());
  let next=0;
  await Promise.all(Array.from({length:Math.min(4,queue.length)},async()=>{while(next<queue.length){const entry=queue[next++];dnsChecks++;try{entry.dns=await dns(entry.domain);const service=config.services.find(s=>s.id===entry.service);const context=entry.evidence.some(e=>e.context==='service-response'||e.context==='configured-seed')?'service-response':'reference-document';for(const name of entry.dns.cnames??[])add(service,name,'dns-cname','https://'+entry.domain+'/',context);}catch{entry.dns={result:'inconclusive'};}}}));
  return {schemaVersion:1,checkedAt:now.toISOString(),purpose:'service dependency candidates; no ownership or completeness guarantee',routesModified:false,applicationTests:false,limits:{maxRequests,maxDns,requests,dnsChecks,requestBudgetReached:requests>=maxRequests,dnsTruncated:candidates.size>queue.length},observations:reports,candidates:[...candidates.values()].sort((a,b)=>(a.service+'|'+a.domain).localeCompare(b.service+'|'+b.domain))};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const options=args(process.argv.slice(2),['--service','--out','--ct','--networks']);
    for(const key of ['--ct','--networks'])ensure(!options[key]||['true','false'].includes(options[key]),'expected true or false');
    const config=await readJson('registry/discovery-sources.json');
    if(options['--service']){config.services=config.services.filter(s=>s.id===options['--service']);ensure(config.services.length,'unknown service');}
    const report=await discover(config,await readJson('registry/registry.json'),{ct:options['--ct']==='true',networks:options['--networks']==='true'});
    if(options['--out']){await mkdir('.private',{recursive:true,mode:0o700});await writeFile(await privateOutput(options['--out'],''),json(report),{mode:0o600,flag:'wx'});}
    else console.log(json(report));
    console.log(json({candidates:report.candidates.length,reviewRequired:report.candidates.filter(c=>c.route==='review-required').length,publicResponses:report.observations.filter(o=>o.result==='observed').length,limits:report.limits,routesModified:false,reviewSample:report.candidates.filter(c=>c.route==='review-required').sort((a,b)=>Number(b.evidence.some(e=>e.context==='service-response'))-Number(a.evidence.some(e=>e.context==='service-response'))).slice(0,50),certificateObservations:report.observations.filter(o=>o.root),networkObservations:report.observations.filter(o=>o.asn).map(({prefixes,...observation})=>({...observation,prefixCount:prefixes?.length}))}));
  }catch(error){console.error(error.message);process.exitCode=1;}
}
