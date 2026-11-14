import test from 'node:test';
import assert from 'node:assert/strict';
import { cidr, currentAnnouncements, validateNetworks } from '../scripts/network-data.mjs';
test('current network selection excludes withdrawn history, stale snapshots and unsafe CIDRs',()=>{
 const now=new Date('2026-11-14T01:00:00Z');
 const data={query_endtime:'2026-11-14T00:00:00',prefixes:[
  {prefix:'185.62.203.0/24',timelines:[{starttime:'2026-10-31T00:00:00',endtime:'2026-11-09T00:00:00'}]},
  {prefix:'185.62.204.0/24',timelines:[{starttime:'2026-10-31T00:00:00',endtime:'2026-11-14T00:00:00'}]}]};
 assert.deepEqual(currentAnnouncements(data,now),['185.62.204.0/24']);
 assert.throws(()=>currentAnnouncements(data,new Date('2026-11-20T00:00:00Z')),/stale/);
 for(const value of ['10.0.0.0/8','127.0.0.0/8','185.62.204.1/24','2001:db8::/32','0.0.0.0/0','::/0'])assert.throws(()=>cidr(value));
});
test('network publication refuses expired evidence and arbitrary DNS-derived prefixes',()=>{
 const entry={service:'test',prefix:'185.62.204.0/24',source:'https://kontur.ru/bugbounty',checkedAt:'2026-11-13',validUntil:'2026-11-20',asn:123,holder:'Test service',snapshotSha256:'a'.repeat(64),status:'reviewed-service-network'};
 const registry={schemaVersion:1,policy:'own',entries:[entry]};
 assert.doesNotThrow(()=>validateNetworks(registry,new Date('2026-11-14T00:00:00Z')));
 assert.throws(()=>validateNetworks(registry,new Date('2026-11-21T00:00:00Z')),/expired/);
 entry.status='dns-derived';assert.throws(()=>validateNetworks(registry,new Date('2026-11-14T00:00:00Z')),/review/);
});

import { refreshNetworks } from '../scripts/refresh-networks.mjs';
test('automatic network refresh only renews reviewed prefixes; withdrawal stops the update',()=>{
 const prefix='185.62.204.0/24',source='https://wildberries.ru/';
 const current={schemaVersion:1,policy:'test',entries:[{service:'wildberries',prefix,source,asn:57073,holder:'Wildberries',checkedAt:'2026-11-13',validUntil:'2026-11-20',snapshotSha256:'a'.repeat(64),status:'reviewed-service-network'}]};
 const catalog={services:[{id:'wildberries',asns:[{number:57073,holderIncludes:'wildberries',source}]}]};
 const reports=[{observations:[{service:'wildberries',asn:57073,source,result:'holder-matched',holder:'Wildberries',window:{end:'2026-11-14T00:00:00'},prefixes:[{prefix,timelines:[{starttime:'2026-11-01T00:00:00',endtime:'2026-11-14T00:00:00'}]},{prefix:'185.62.205.0/24',timelines:[{starttime:'2026-11-01T00:00:00',endtime:'2026-11-14T00:00:00'}]}]}]}];
 const result=refreshNetworks(reports,current,catalog,new Date('2026-11-14T01:00:00Z'));assert.deepEqual(result.registry.entries.map(e=>e.prefix),[prefix]);assert.equal(result.registry.entries[0].validUntil,'2026-11-21');
 reports[0].observations[0].prefixes.shift();assert.throws(()=>refreshNetworks(reports,current,catalog,new Date('2026-11-14T01:00:00Z')),/withdrawn/);
});
