import { Resolver } from 'node:dns/promises';
import { request } from 'node:https';
import { isIP } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative, isAbsolute, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, readJson, validateRegistry, activeEntries, json, ensure } from './scripts/lib.mjs';
import { privateOutput } from './scripts/integrate.mjs';

export function isPublicAddress(address) {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  // Only currently allocated global-unicast space; mapped IPv4, ULA, link-local and documentation are rejected.
  if (isIP(address) === 6) {
    const canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1).toLowerCase();
    const [first, second] = canonical.split(':').map(part => parseInt(part || '0', 16));
    return first >= 0x2000 && first < 0x4000 && first !== 0x2002 && first !== 0x3fff &&
      !(first === 0x2001 && (second < 0x200 || second === 0xdb8));
  }
  return false;
}
export async function dnsAddresses(host, { timeoutMs = 4000 } = {}) {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 1 });
  const timer = setTimeout(() => resolver.cancel(), timeoutMs);
  try {
    const results = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
    const addresses = results.filter(item => item.status === 'fulfilled').flatMap(item => item.value);
    ensure(addresses.length > 0, 'dns-failed');
    ensure(addresses.every(isPublicAddress), 'non-public-resolution');
    return addresses;
  } finally { clearTimeout(timer); }
}
export function probeHttps(host, address, { timeoutMs = 6000 } = {}) {
  return new Promise(resolveResult => {
    let settled = false;
    const finish = value => { if (!settled) { settled = true; clearTimeout(timer); resolveResult(value); } };
    const req = request({
      hostname: host, servername: host, port: 443, path: '/', method: 'HEAD',
      rejectUnauthorized: true, agent: false,
      lookup: (_host, _options, callback) => callback(null, address, isIP(address)),
      headers: { 'User-Agent': 'LibertaRouting-Canary/0.1', 'Accept': '*/*' }
    }, response => {
      const status = response.statusCode;
      response.destroy();
      finish({ tls: 'valid', httpStatus: status, result: status >= 200 && status < 400 ? 'reachable' : 'http-response' });
    });
    const timer = setTimeout(() => req.destroy(new Error('timeout')), timeoutMs);
    req.on('error', error => finish({ result: 'inconclusive', error: ['ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'CERT_HAS_EXPIRED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(error.code) ? error.code : 'network-or-tls-error' }));
    req.end();
  });
}
export async function canary(registry, { resolveHost = dnsAddresses, probe = probeHttps, concurrency = 2 } = {}) {
  validateRegistry(registry);
  ensure(Number.isInteger(concurrency) && concurrency >= 1 && concurrency <= 4, 'invalid concurrency');
  const entries = activeEntries(registry), results = new Array(entries.length);
  let next = 0;
  const worker = async () => {
    while (next < entries.length) {
      const index = next++, entry = entries[index];
      try {
        const addresses = await resolveHost(entry.domain);
        ensure(Array.isArray(addresses) && addresses.length > 0 && addresses.every(isPublicAddress), 'unsafe-dns');
        const result = await probe(entry.domain, addresses[0]);
        // No IPs, redirect targets, certificates, headers, collector identities or raw errors in output.
        results[index] = { id: entry.id, domain: entry.domain, result: result.result, ...(result.tls ? { tls: result.tls } : {}), ...(Number.isInteger(result.httpStatus) ? { httpStatus: result.httpStatus } : {}), ...(result.error ? { error: result.error } : {}) };
      } catch { results[index] = { id: entry.id, domain: entry.domain, result: 'inconclusive', error: 'dns-failed-or-unsafe' }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, entries.length) }, worker));
  return { schemaVersion: 1, checkedAt: new Date().toISOString(), scope: 'current-runner-only', serviceFunctionality: 'not-tested', results };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = args(process.argv.slice(2), ['--registry', '--out', '--strict']);
    const target = resolve(options['--out'] ?? '.private/canary.json');
    const rel = relative(resolve('.private'), target);
    ensure(rel && !rel.startsWith('..') && !isAbsolute(rel), 'canary reports must stay under .private/');
    const report = await canary(await readJson(options['--registry'] ?? 'registry.json'));
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(await privateOutput(target, ''), json(report), { mode: 0o600, flag: 'wx' });
    const counts = Object.fromEntries(['reachable', 'http-response', 'inconclusive'].map(result => [result, report.results.filter(item => item.result === result).length]));
    console.log(json({ scope: report.scope, ...counts, routesModified: false }));
    if (options['--strict'] && report.results.some(item => item.result !== 'reachable')) process.exitCode = 2;
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
