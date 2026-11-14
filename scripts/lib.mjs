import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
import { readFile, lstat, mkdtemp, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

export const ARTIFACTS = ['liberta-v1.domains.txt', 'liberta-v1.singbox.json', 'liberta-v1.xray.json'];
export const json = value => JSON.stringify(value, null, 2) + '\n';
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const releaseTag = registry => registry.releaseTag ?? `v${registry.version}`;
export const readJson = async path => JSON.parse(await readFile(path, 'utf8'));
export function ensure(condition, message) { if (!condition) throw new Error(message); }
export function exactKeys(value, keys, label) {
  ensure(value !== null && typeof value === 'object' && !Array.isArray(value), `${label}: expected object`);
  const actual = Object.keys(value).sort();
  ensure(actual.join(',') === [...keys].sort().join(','), `${label}: unexpected or missing fields`);
}
export function normalizeDomain(value) {
  ensure(typeof value === 'string' && value === value.trim(), 'domain: invalid whitespace');
  ensure(!/[\s/:@?#*\\]/u.test(value), 'domain: URL, pattern or address not allowed');
  const host = domainToASCII(value.replace(/\.$/, '').toLowerCase());
  ensure(host && host.length <= 253 && !isIP(host) && !/^[\d.]+$/.test(host), 'domain: invalid hostname');
  const labels = host.split('.');
  ensure(labels.length >= 2 && labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)), 'domain: invalid labels');
  ensure(!['localhost', 'local', 'internal', 'lan', 'invalid', 'test', 'example'].includes(labels.at(-1)), 'domain: non-public hostname');
  return host;
}
export function date(value, now, label) {
  ensure(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value), `${label}: expected ISO date`);
  const stamp = Date.parse(value + 'T00:00:00Z');
  ensure(Number.isFinite(stamp) && new Date(stamp).toISOString().slice(0, 10) === value, `${label}: invalid date`);
  ensure(stamp <= now.getTime(), `${label}: future date`);
  return stamp;
}
const broadSuffixes = new Set(['co.uk', 'com.au', 'com.ru', 'net.ru', 'org.ru', 'gov.ru', 'ac.uk']);
export function publicHttps(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('source: invalid URL'); }
  ensure(url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.search && !url.hash, 'source: public HTTPS URL without credentials/query required');
  ensure(normalizeDomain(url.hostname) === url.hostname, 'source: noncanonical hostname');
  return url;
}
export function validateRegistry(registry) {
  exactKeys(registry, ['version', 'updated', 'note', 'classes', 'measured_exceptions'], 'registry');
  ensure(registry.version === 3, 'unsupported existing registry schema');
  ensure(typeof registry.note === 'string' && typeof registry.updated === 'string', 'registry metadata missing');
  ensure(registry.classes && typeof registry.classes === 'object' && !Array.isArray(registry.classes), 'classes must be an object');
  const seen = new Set();
  for (const [name, cls] of Object.entries(registry.classes)) {
    ensure(/^[a-z][a-z0-9_]*$/.test(name), 'invalid class');
    exactKeys(cls, ['policy', 'explicit', 'why', 'domains'], 'class');
    ensure(cls.policy === 'direct' && typeof cls.explicit === 'boolean' && typeof cls.why === 'string', 'invalid legacy policy');
    ensure(Array.isArray(cls.domains) && cls.domains.length > 0, 'empty class');
    for (const domain of cls.domains) {
      ensure(normalizeDomain(domain) === domain && !seen.has(domain), 'duplicate or invalid registry domain');
      seen.add(domain);
    }
  }
  ensure(Object.keys(registry.classes).length > 0 && Array.isArray(registry.measured_exceptions), 'empty registry');
  for (const item of registry.measured_exceptions) {
    exactKeys(item, ['domain', 'why'], 'measured exception');
    ensure(normalizeDomain(item.domain) === item.domain && seen.has(item.domain) && typeof item.why === 'string', 'invalid measured exception');
  }
  return registry;
}
export function allEntries(registry) {
  return Object.entries(registry.classes).flatMap(([name, cls]) => cls.domains.map(domain => ({id:domain,class:name,domain,match:'suffix',route:'direct',explicit:cls.explicit}))).sort((a,b)=>a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0);
}
export function validateProvenance(registry, provenance, now = new Date()) {
  validateRegistry(registry);
  ensure(provenance.schemaVersion === 1 && Array.isArray(provenance.entries), 'invalid provenance registry');
  const expected = new Map(allEntries(registry).map(entry => [entry.domain, entry.class]));
  const seen = new Set();
  for (const entry of provenance.entries) {
    exactKeys(entry, ['domain', 'class', 'origin', 'addedAt', 'source'], 'provenance entry');
    ensure(expected.get(entry.domain) === entry.class && !seen.has(entry.domain), 'provenance domain/class missing, duplicate or mismatched');
    seen.add(entry.domain);
    ensure(Array.isArray(entry.source) && entry.source.length > 0, 'provenance source required');
    if (entry.origin === 'existing-liberta-registry') ensure(entry.addedAt === null, 'do not invent original addition dates');
    else {
      ensure(['first-party-document-review', 'operator-service-report'].includes(entry.origin), 'unknown provenance origin');
      date(entry.addedAt, now, 'addedAt');
    }
    for (const source of entry.source) {
      if (source.result === 'operator-reported-bundle') {
        exactKeys(source, ['record', 'checkedAt', 'result', 'note'], 'operator source');
        ensure(entry.origin === 'operator-service-report' && source.record === 'registry/evidence/tbank-user-report.json', 'invalid operator evidence');
        date(source.checkedAt, now, 'checkedAt');
        ensure(typeof source.note === 'string' && source.note.length > 0, 'operator evidence note required');
        continue;
      }
      publicHttps(source.url);
      if (source.result === 'pending-review') {
        exactKeys(source, ['url', 'checkedAt', 'result'], 'pending source');
        ensure(entry.origin === 'existing-liberta-registry' && source.checkedAt === null, 'new domains require a checked first-party reference');
      } else {
        exactKeys(source, ['url', 'checkedAt', 'result', 'reference', 'note'], 'reviewed source');
        ensure(source.result === 'first-party-reference', 'unknown source result');
        date(source.checkedAt, now, 'checkedAt');
        const host = publicHttps(source.reference).hostname;
        ensure(host === entry.domain || host.endsWith(`.${entry.domain}`), 'source reference does not identify this domain');
        ensure(typeof source.note === 'string' && source.note.length > 0, 'source review note required');
      }
    }
  }
  ensure(seen.size === expected.size, 'provenance must cover every selected domain exactly once');
  return provenance;
}
export function activeEntries(registry) {
  const measured = new Set(registry.measured_exceptions.map(entry => entry.domain));
  return allEntries(registry).filter(entry => entry.explicit || measured.has(entry.domain));
}
export function render(registry) {
  validateRegistry(registry);
  const domains=activeEntries(registry).map(entry=>entry.domain);
  ensure(domains.length > 0, 'empty explicit list');
  return {
    'liberta-v1.domains.txt': domains.map(domain=>'domain:'+domain).join('\n')+'\n',
    'liberta-v1.singbox.json':json({version:1,rules:[{domain_suffix:domains}]})
  };
}
export async function atomicDirectory(target, files) {
  const output = resolve(target);
  await mkdir(dirname(output), { recursive: true });
  let exists = false;
  try { await lstat(output); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
  ensure(!exists, 'immutable output already exists; choose another directory or use --check');
  const temp = await mkdtemp(join(dirname(output), '.liberta-build-'));
  try {
    for (const [name, content] of Object.entries(files)) await writeFile(join(temp, name), content, { flag: 'wx' });
    // A completed directory becomes visible in one rename, never a half-written release.
    await rename(temp, output);
  } finally { await rm(temp, { recursive: true, force: true }); }
}
export function args(argv, allowed = []) {
  const output = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    ensure(allowed.includes(key) && !Object.hasOwn(output, key), `unknown/duplicate option: ${key}`);
    if (['--check', '--strict', '--bootstrap', '--help'].includes(key)) output[key] = true;
    else { ensure(argv[i + 1] && !argv[i + 1].startsWith('--'), `missing value: ${key}`); output[key] = argv[++i]; }
  }
  return output;
}
