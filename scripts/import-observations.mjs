import { isIP } from 'node:net';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, ensure, json, normalizeDomain, readJson } from './lib.mjs';
import { privateOutput } from './integrate.mjs';
import { matchesDomain, PROXY_DOMAINS, selectedDomains } from './rule-sets.mjs';
export function summarizeObservations(content, registry, format) {
  ensure(Buffer.byteLength(content)<20_000_000,'observation input too large');
  const hosts=new Set();let unidentifiedIpConnections=0,unparsed=0;
  const add=value=>{try{if(isIP(value)){unidentifiedIpConnections++;return;}hosts.add(normalizeDomain(value));}catch{unparsed++;}};
  if(format==='json') {
    const rows=JSON.parse(content);ensure(Array.isArray(rows)&&rows.length<=100000,'expected array of destination observations');
    for(const row of rows){ensure(row&&typeof row.host==='string','observation requires host');add(row.host);}
  } else {
    ensure(format==='xray','supported formats: json, xray');
    for(const line of content.split('\n').filter(Boolean)) {
      // Only the accepted destination is parsed. Source address, user/email, URL and credentials are discarded.
      const match=line.match(/\baccepted\s+(?:tcp|udp):(?:\[([^\]]+)\]|([^\s:]+)):\d+\b/);
      if(match)add(match[1]??match[2]);else unparsed++;
    }
  }
  const known=selectedDomains(registry);
  return {schemaVersion:1,routesModified:false,unidentifiedIpConnections,unparsed,
    destinations:[...hosts].sort().map(domain=>({domain,route:PROXY_DOMAINS.some(s=>matchesDomain(domain,s))?'proxy-exception':known.some(s=>matchesDomain(domain,s))?'direct':'review-required'}))};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try{const options=args(process.argv.slice(2),['--input','--format','--out']);ensure(options['--input']&&options['--out'],'--input and --out required');
    const report=summarizeObservations(await readFile(options['--input'],'utf8'),await readJson('registry/registry.json'),options['--format']??'json');
    await mkdir('.private',{recursive:true,mode:0o700});await writeFile(await privateOutput(options['--out'],options['--input']),json(report),{mode:0o600,flag:'wx'});
    console.log(JSON.stringify({destinations:report.destinations.length,unidentifiedIpConnections:report.unidentifiedIpConnections,unparsed:report.unparsed,routesModified:false}));
  }catch{console.error('Observation import failed; raw input was not printed');process.exitCode=1;}
}
