import { isIP } from 'node:net';
import { isPublicAddress } from '../service-canary.mjs';
import { date, ensure, exactKeys, publicHttps } from './lib.mjs';
export function cidr(value) {
  ensure(typeof value==='string' && value.split('/').length===2,'CIDR required');
  const [address,bits]=value.split('/'),family=isIP(address),length=family===4?32:128;
  ensure(family && /^(0|[1-9][0-9]*)$/.test(bits) && Number(bits)>0 && Number(bits)<=length && isPublicAddress(address),'public canonical CIDR required');
  let parts;
  if(family===4)parts=address.split('.').map(Number).map(x=>[x,8]);
  else {
    ensure(!address.includes('.'),'mapped IPv6 is not accepted');
    const [left,right]=address.split('::'),a=left?left.split(':'):[],b=right?right.split(':'):[];
    const groups=address.includes('::')?[...a,...Array(8-a.length-b.length).fill('0'),...b]:a;
    ensure(groups.length===8,'invalid IPv6');parts=groups.map(x=>[parseInt(x,16),16]);
  }
  const number=parts.reduce((n,[part,width])=>(n<<BigInt(width))+BigInt(part),0n),hostBits=BigInt(length-Number(bits));
  ensure((number>>hostBits)<<hostBits===number,'CIDR contains host bits');
  ensure(Number(bits)>=(family===4?16:32),'service prefix is unexpectedly broad');
  return {family,bits:Number(bits)};
}
const timestamp=value=>Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value)?value:value+'Z');
export function currentAnnouncements(data, now=new Date()) {
  const end=timestamp(data.query_endtime??'');
  ensure(Number.isFinite(end)&&Math.abs(now.getTime()-end)<=36*3600000,'BGP snapshot is stale or in the future');
  return (data.prefixes??[]).filter(p=>{
    try{cidr(p.prefix);return p.timelines?.some(t=>timestamp(t.starttime)<=end&&timestamp(t.endtime)>=end);}catch{return false;}
  }).map(p=>p.prefix).sort();
}
export function validateNetworks(registry, now=new Date()) {
  exactKeys(registry,['schemaVersion','policy','entries'],'network registry');ensure(registry.schemaVersion===1 && Array.isArray(registry.entries),'invalid network registry');
  const seen=new Set();
  for(const entry of registry.entries) {
    exactKeys(entry,['service','prefix','source','checkedAt','validUntil','asn','holder','snapshotSha256','status'],'network entry');
    cidr(entry.prefix);ensure(!seen.has(entry.prefix),'duplicate service prefix');seen.add(entry.prefix);
    ensure(/^[a-z0-9][a-z0-9-]*$/.test(entry.service) && entry.status==='reviewed-service-network','network requires ownership review');
    publicHttps(entry.source);date(entry.checkedAt,now,'network checkedAt');
    const expires=Date.parse(entry.validUntil+'T00:00:00Z');
    ensure(Number.isFinite(expires)&&expires>now.getTime()&&expires-Date.parse(entry.checkedAt+'T00:00:00Z')<=8*86400000,'network review expired or validity too long');
    ensure(Number.isInteger(entry.asn)&&entry.asn>0&&typeof entry.holder==='string'&&entry.holder.length>3&&/^[a-f0-9]{64}$/.test(entry.snapshotSha256),'network snapshot provenance required');
  }
  return registry;
}
