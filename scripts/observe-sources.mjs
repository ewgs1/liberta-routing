import { request } from 'node:https';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dnsAddresses } from '../service-canary.mjs';
import { normalizeDomain, sha256, json } from './lib.mjs';

// Fixed public first-party pages only. No accounts, API calls, crawling or route updates.
export const SOURCES = ['https://www.wildberries.ru/', 'https://wb.ru/', 'https://www.tbank.ru/', 'https://status.tbank-online.com/', 'https://www.ozon.ru/', 'https://vk.com/'];
export function referencedHosts(text) {
  const hosts = new Set();
  const input = text.replaceAll('\\/', '/');
  for (const match of input.matchAll(/https?:\/\/(?:\*\.)?([a-z0-9.-]+)(?=[:/\s"'<>;,]|$)/gi)) {
    try { hosts.add(normalizeDomain(match[1])); } catch {}
  }
  return [...hosts].sort();
}
async function readPage(url) {
  const host = new URL(url).hostname;
  const addresses = await dnsAddresses(host);
  const address = addresses.find(value => isIP(value) === 4) ?? addresses[0];
  return new Promise(resolveResult => {
    let done = false, bytes = 0;
    const finish = value => { if (!done) { done = true; clearTimeout(timer); resolveResult(value); } };
    const req = request(url, {
      method: 'GET', agent: false, rejectUnauthorized: true,
      lookup: (_host, _options, callback) => callback(null, address, isIP(address)),
      headers: { 'User-Agent': 'LibertaRouting-SourceReview/1.0', Accept: 'text/html', 'Accept-Encoding': 'identity' }
    }, response => {
      const chunks = [];
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 2_000_000) req.destroy();
        else chunks.push(chunk);
      });
      response.on('error', () => finish({source:url,result:'inconclusive'}));
      response.on('end', () => {
        const body = Buffer.concat(chunks);
        // Do not publish headers, cookies, paths, IPs, body or redirect targets.
        const csp = [response.headers['content-security-policy'], response.headers['content-security-policy-report-only']].filter(Boolean).join('\n');
        finish({source:url,checkedAt:new Date().toISOString(),result:'observed-public-response',httpStatus:response.statusCode,bodySha256:sha256(body),bodyHosts:referencedHosts(body.toString('utf8')),cspSha256:sha256(csp),cspHosts:referencedHosts(csp)});
      });
    });
    const timer = setTimeout(() => req.destroy(), 10000);
    req.on('error', () => finish({source:url,result:'inconclusive'}));
    req.on('close', () => finish({source:url,result:'inconclusive'}));
    req.end();
  });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const results = [];
  for (const source of SOURCES) {
    try { results.push(await readPage(source)); }
    catch { results.push({source,result:'inconclusive'}); }
  }
  console.log(json({schemaVersion:1,purpose:'candidate discovery only',routesModified:false,applicationTests:false,results}));
}
