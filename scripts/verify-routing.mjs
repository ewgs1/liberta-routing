import { createServer, connect } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson, json, ensure } from './lib.mjs';
import { selectedDomains } from './rule-sets.mjs';

// Exercise the real routing core. Both observed exits terminate on loopback;
// no request reaches a service, DNS resolver, VPN node or the public Internet.
const loopback = '127.0.0.1';
const sockets = new Set();
const servers = [];
let child, directory, spawnError;
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, loopback, resolve);
  });
  servers.push(server);
  return server.address().port;
}
async function observedExit(label) {
  const targets = [];
  const server = createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.setTimeout(5000, () => socket.destroy());
    let header = '', tunnel = false;
    socket.on('data', chunk => {
      if (tunnel) { socket.end(`LIBERTA_${label}\n`); return; }
      header += chunk.toString('utf8');
      if (header.length > 16384) { socket.destroy(); return; }
      const end = header.indexOf('\r\n\r\n');
      if (end < 0) return;
      const match = /^CONNECT (\S+) HTTP\/1\.[01]\r\n/.exec(header);
      if (!match) { socket.destroy(); return; }
      targets.push(match[1]);
      tunnel = true;
      socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
      if (header.length > end + 4) socket.end(`LIBERTA_${label}\n`);
    });
  });
  return { port: await listen(server), targets };
}
async function ready(port) {
  for (let attempt = 0; attempt < 160; attempt++) {
    ensure(!spawnError && child.exitCode === null, 'Xray could not start the routing exercise');
    const available = await new Promise(resolve => {
      const socket = connect({host:loopback,port});
      socket.setTimeout(100, () => { socket.destroy(); resolve(false); });
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => resolve(false));
    });
    if (available) return;
    await pause(50);
  }
  throw new Error('Xray routing listener did not become ready');
}
async function probe(port, host, payloadHost = host) {
  return new Promise((resolve, reject) => {
    const socket = connect({host:loopback,port});
    let response = '';
    socket.setTimeout(5000, () => socket.destroy(new Error('routing probe timeout')));
    socket.once('connect', () => {
      const authority = host.includes(':') ? `[${host}]:443` : `${host}:443`;
      const payload = payloadHost ? `GET / HTTP/1.1\r\nHost: ${payloadHost}\r\nConnection: close\r\n\r\n` : 'opaque application payload\r\n';
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n${payload}`);
    });
    socket.on('data', chunk => {
      response += chunk.toString('utf8');
      if (response.length > 16384) { socket.destroy(new Error('unexpected routing response')); return; }
      const result = /LIBERTA_(direct|proxy)/.exec(response);
      if (result) { socket.destroy(); resolve(result[1]); }
    });
    socket.once('error', reject);
    socket.once('close', () => reject(new Error('routing exercise closed without an observed exit')));
  });
}

try {
  const [direct, proxy] = [await observedExit('direct'), await observedExit('proxy')];
  const reservation = createServer();
  const inboundPort = await listen(reservation);
  await new Promise(resolve => reservation.close(resolve));
  const template = await readJson('examples/remnawave/liberta-selective.xray.json');
  const sniffing = structuredClone(template.inbounds.find(inbound => inbound.sniffing?.enabled).sniffing);
  template.log = {loglevel:'none'};
  template.inbounds = [{tag:'routing-exercise',listen:loopback,port:inboundPort,protocol:'http',settings:{},sniffing}];
  template.outbounds = [
    ...[direct, proxy].map((exit, index) => ({tag:index===0?'direct':'proxy',protocol:'http',settings:{servers:[{address:loopback,port:exit.port}]}})),
    {tag:'block',protocol:'blackhole',settings:{}}
  ];
  directory = await mkdtemp(join(tmpdir(), 'liberta-routing-exercise-'));
  const path = join(directory, 'config.json');
  await writeFile(path, json(template));
  child = spawn('xray', ['run','-config',path], {stdio:'ignore'});
  child.once('error', error => { spawnError = error; });
  await ready(inboundPort);
  const domains = selectedDomains(await readJson('registry/registry.json'));
  let checked = 0;
  for (const domain of domains) {
    for (const host of [domain,`api.${domain}`]) {
      ensure(await probe(inboundPort,host)==='direct', `actual Xray route is not direct: ${host}`);
      checked++;
    }
  }
  for (const host of ['unlisted-liberta-service.ru','github.com','not-tbank-app.ru','yastatic.net.unrelated.invalid','sbp.ru']) {
    ensure(await probe(inboundPort,host)==='proxy', `unexpected direct route: ${host}`);
    checked++;
  }
  ensure(await probe(inboundPort,'1.1.1.1',null)==='proxy','unclassified IPv4 must use proxy'); checked++;
  ensure(await probe(inboundPort,'2001:4860:4860::8888',null)==='proxy','unclassified IPv6 must use proxy'); checked++;
  ensure(await probe(inboundPort,'1.1.1.1','api.t-bank-app.ru')==='direct','HTTP sniffed service name must select direct'); checked++;
  ensure(direct.targets.at(-1)==='1.1.1.1:443','routeOnly must preserve the original IP destination');
  console.log(`Actual Xray routing passed: ${checked} loopback-only connections; domains, subdomains, negatives, raw IPv4/IPv6 and HTTP sniffing. This is not a device/application acceptance test.`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  if (child && child.exitCode === null && !spawnError) {
    child.kill('SIGTERM');
    for (let attempt=0;attempt<50 && child.exitCode===null;attempt++) await pause(20);
    if (child.exitCode===null) child.kill('SIGKILL');
  }
  for (const socket of sockets) socket.destroy();
  for (const server of servers) if (server.listening) await new Promise(resolve => server.close(resolve));
  if (directory) await rm(directory,{recursive:true,force:true});
}
