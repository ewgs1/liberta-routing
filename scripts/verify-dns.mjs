import { createSocket } from 'node:dgram';
import { createServer, connect } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson, json, ensure } from './lib.mjs';

// Exercise Xray's actual DNS server selection with local mock resolvers only.
const host = '127.0.0.1', sockets = [], queries = [];
let child, directory, spawnError;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function questionEnd(message) {
  let offset = 12;
  while (offset < message.length && message[offset]) offset += message[offset] + 1;
  return offset + 5;
}
function questionName(message) {
  const labels = []; let offset = 12;
  while (message[offset]) { const size = message[offset++]; labels.push(message.subarray(offset,offset+size).toString()); offset += size; }
  return labels.join('.');
}
async function resolver(label) {
  const socket = createSocket('udp4'); sockets.push(socket);
  socket.on('message', (message, peer) => {
    const end = questionEnd(message);
    if (end > message.length) return;
    queries.push({label,domain:questionName(message)});
    const header = Buffer.from(message.subarray(0,12));
    header.writeUInt16BE(0x8180,2); header.writeUInt16BE(1,4); header.writeUInt16BE(1,6); header.writeUInt32BE(0,8);
    const answer = Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,192,0,2,1]);
    socket.send(Buffer.concat([header,message.subarray(12,end),answer]),peer.port,peer.address);
  });
  await new Promise(resolve => socket.bind(0,host,resolve));
  return socket.address().port;
}
function query(port, domain) {
  return new Promise((resolve, reject) => {
    const socket = connect({host,port}); let data=Buffer.alloc(0);
    socket.setTimeout(6000,()=>socket.destroy(new Error('local DNS query timeout')));
    socket.on('error',reject);
    socket.on('connect',()=>{
      const header=Buffer.from([0x12,0x34,1,0,0,1,0,0,0,0,0,0]);
      const name=Buffer.concat(domain.split('.').flatMap(label=>[Buffer.from([label.length]),Buffer.from(label)]));
      const message=Buffer.concat([header,name,Buffer.from([0,0,1,0,1])]);
      const size=Buffer.alloc(2);size.writeUInt16BE(message.length);
      socket.write(Buffer.concat([size,message]));
    });
    socket.on('data',chunk=>{
      data=Buffer.concat([data,chunk]);
      if(data.length>=2 && data.length>=data.readUInt16BE(0)+2) {
        socket.destroy();
        if(data.length<14 || (data[5]&15)!==0 || data.readUInt16BE(8)!==1) reject(new Error('unexpected local DNS response'));
        else resolve();
      }
    });
  });
}
try {
  const template = await readJson('examples/remnawave/liberta-selective.xray.json');
  const dns = structuredClone(template.dns); dns.hosts={}; dns.disableCache=true;
  for(let index=0;index<dns.servers.length;index++) {
    const server=typeof dns.servers[index]==='string'?{address:dns.servers[index]}:dns.servers[index];
    const label=server.domains?.includes('domain:tbank.ru')?'domestic':server.domains?.includes('domain:mcs.mail.ru')?'proxy-override':'fallback';
    const port=await resolver(label);
    dns.servers[index]={...server,address:host,port,timeoutMs:1000};
  }
  const reservation=createServer(); await new Promise(resolve=>reservation.listen(0,host,resolve));
  const port=reservation.address().port;await new Promise(resolve=>reservation.close(resolve));
  const config={log:{loglevel:'none'},dns,inbounds:[{tag:'dns-test',listen:host,port,protocol:'dokodemo-door',settings:{address:host,port:53,network:'tcp'}}],outbounds:[{tag:'local',protocol:'freedom'},{tag:'dns',protocol:'dns'}],routing:{domainStrategy:'AsIs',rules:[{type:'field',inboundTag:['dns-test'],outboundTag:'dns'}]}};
  directory=await mkdtemp(join(tmpdir(),'liberta-dns-')); const path=join(directory,'config.json'); await writeFile(path,json(config));
  child=spawn('xray',['run','-config',path],{stdio:'ignore'});child.on('error',error=>{spawnError=error;});
  let ready=false;
  for(let attempt=0;attempt<100;attempt++) {
    ensure(!spawnError && child.exitCode===null,'Xray DNS exercise could not start');
    ready=await new Promise(resolve=>{const s=connect({host,port});s.once('connect',()=>{s.destroy();resolve(true);});s.once('error',()=>resolve(false));});
    if(ready)break;await pause(50);
  }
  ensure(ready,'Xray DNS exercise not ready');
  for(const [domain,wanted] of [['api.tbank.ru','domestic'],['api.vk.com','domestic'],['tenant.mcs.mail.ru','proxy-override'],['tenant.cloud.vk.com','proxy-override'],['github.com','fallback']]) {
    await query(port,domain); await pause(50);
    const observed=queries.filter(q=>q.domain===domain);
    ensure(observed.length>0 && observed.every(q=>q.label===wanted),`DNS server selection mismatch: ${domain}; observed ${[...new Set(observed.map(q=>q.label))].join(',')}`);
  }
  console.log('Actual Xray DNS selection passed: selected services, shared-cloud overrides and unknown domain; all DNS servers were local mocks. No public DNS or application tested.');
} catch(error) {console.error(error.message);process.exitCode=1;}
finally {
  if(child && child.exitCode===null && !spawnError){child.kill('SIGTERM');for(let n=0;n<50&&child.exitCode===null;n++)await pause(20);if(child.exitCode===null)child.kill('SIGKILL');}
  for(const socket of sockets)socket.close();
  if(directory)await rm(directory,{recursive:true,force:true});
}
