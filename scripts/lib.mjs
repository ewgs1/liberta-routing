import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
import { readFile, lstat, mkdtemp, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

export const ARTIFACTS = ['smart.domains.txt', 'smart.singbox.json', 'smart.xray.json'];
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
export function validateRegistry(registry, { now = new Date(), freshness = true } = {}) {
  exactKeys(registry, ['schemaVersion', 'project', 'version', ...(Object.hasOwn(registry, 'releaseTag') ? ['releaseTag'] : []), 'profile', 'maxReviewAgeDays', 'classes', 'entries'], 'registry');
  ensure(registry.schemaVersion === 1 && registry.project === 'liberta-routing', 'registry: unsupported schema/project');
  ensure(/^\d+\.\d+\.\d+-(?:alpha|beta)(?:\.\d+)?$/.test(registry.version), 'version: prerelease version required');
  if (Object.hasOwn(registry, 'releaseTag')) ensure(typeof registry.releaseTag === 'string' && /^v[1-9]\d*$/.test(registry.releaseTag), 'releaseTag: expected v1, v2, ...');
  exactKeys(registry.profile, ['id', 'defaultRoute', 'directTag', 'proxyTag'], 'profile');
  ensure(registry.profile.id === 'smart-alpha' && registry.profile.defaultRoute === 'proxy', 'profile: Smart must default to proxy');
  const tags = [registry.profile.directTag, registry.profile.proxyTag];
  ensure(tags.every(tag => typeof tag === 'string' && /^[a-zA-Z][a-zA-Z0-9_-]{0,31}$/.test(tag)) && tags[0] !== tags[1], 'profile: distinct safe outbound tags required');
  ensure(Number.isInteger(registry.maxReviewAgeDays) && registry.maxReviewAgeDays >= 1 && registry.maxReviewAgeDays <= 90, 'review window: expected 1..90 days');
  ensure(Array.isArray(registry.classes) && registry.classes.length > 0, 'classes: empty');
  const classes = new Set();
  for (const item of registry.classes) {
    exactKeys(item, ['id', 'label'], 'class');
    ensure(/^[a-z][a-z0-9-]{1,63}$/.test(item.id) && typeof item.label === 'string' && item.label.length > 0 && item.label.length <= 120 && !classes.has(item.id), 'class: invalid or duplicate');
    classes.add(item.id);
  }
  ensure(Array.isArray(registry.entries), 'entries: expected array');
  const ids = new Set(), domains = new Set();
  for (const entry of registry.entries) {
    exactKeys(entry, ['id', 'class', 'domain', 'match', 'route', 'explicit', 'status', 'source', 'addedAt', 'reviewedAt', 'verification'], 'entry');
    ensure(typeof entry.id === 'string' && /^[a-z][a-z0-9-]{1,79}$/.test(entry.id) && !ids.has(entry.id), 'entry: invalid/duplicate ID');
    ids.add(entry.id);
    ensure(classes.has(entry.class), `${entry.id}: unknown class`);
    ensure(normalizeDomain(entry.domain) === entry.domain && !domains.has(entry.domain), `${entry.id}: noncanonical/duplicate domain`);
    domains.add(entry.domain);
    ensure(['full', 'suffix'].includes(entry.match), `${entry.id}: unsupported match`);
    ensure(entry.match !== 'suffix' || !broadSuffixes.has(entry.domain), `${entry.id}: public suffix forbidden`);
    ensure(entry.route === 'direct' && entry.explicit === true, `${entry.id}: explicit direct rule required`);
    ensure(['approved', 'candidate', 'disabled'].includes(entry.status), `${entry.id}: unsupported status`);
    const added = date(entry.addedAt, now, `${entry.id}.addedAt`);
    const reviewed = date(entry.reviewedAt, now, `${entry.id}.reviewedAt`);
    ensure(added <= reviewed, `${entry.id}: review predates addition`);
    ensure(Array.isArray(entry.source) && entry.source.length >= 1, `${entry.id}: missing provenance`);
    for (const source of entry.source) {
      exactKeys(source, ['url', 'kind', 'checkedAt', 'evidence'], 'source');
      publicHttps(source.url);
      ensure(source.kind === 'official-site' && typeof source.evidence === 'string' && source.evidence.length >= 15 && source.evidence.length <= 500, `${entry.id}: first-party factual evidence required`);
      const checked = date(source.checkedAt, now, `${entry.id}.source.checkedAt`);
      ensure(checked >= added && checked <= reviewed, `${entry.id}: source check outside review interval`);
      if (entry.status === 'approved' && freshness) ensure(now.getTime() - checked < registry.maxReviewAgeDays * 86400000, `${entry.id}: stale source review`);
    }
    exactKeys(entry.verification, ['ownership', 'reachability'], 'verification');
    ensure(['verified', 'pending'].includes(entry.verification.ownership) && entry.verification.reachability === 'not-measured', `${entry.id}: invalid verification; live results belong in private reports`);
    if (entry.status === 'approved') {
      ensure(entry.verification.ownership === 'verified', `${entry.id}: ownership not verified`);
      // Alpha deliberately permits only individually reviewed hosts. Suffix support is reserved.
      ensure(entry.match === 'full', `${entry.id}: suffix approval is disabled in alpha`);
      if (freshness) ensure(now.getTime() - reviewed < registry.maxReviewAgeDays * 86400000, `${entry.id}: stale review`);
    }
  }
  return registry;
}
export const activeEntries = registry => registry.entries.filter(entry => entry.status === 'approved').sort((a, b) => a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0);
export function render(registry, options) {
  validateRegistry(registry, options);
  const entries = activeEntries(registry);
  ensure(entries.length > 0, 'refusing empty direct list (use a new explicit profile for this change)');
  const domains = entries.map(entry => `${entry.match === 'full' ? 'full' : 'domain'}:${entry.domain}`);
  const singbox = { version: 1, rules: [{ domain: entries.map(entry => entry.domain) }] };
  const xray = {
    domainStrategy: 'AsIs',
    rules: [
      { type: 'field', domain: domains, outboundTag: registry.profile.directTag },
      { type: 'field', network: 'tcp,udp', outboundTag: registry.profile.proxyTag }
    ]
  };
  return { 'smart.domains.txt': domains.join('\n') + '\n', 'smart.singbox.json': json(singbox), 'smart.xray.json': json(xray) };
}
export function manifest(registry, registryBytes, files) {
  return {
    schemaVersion: 1, version: registry.version, releaseTag: releaseTag(registry), profile: registry.profile.id,
    registrySha256: sha256(registryBytes), directHostCount: activeEntries(registry).length,
    verification: { ownership: 'first-party-source-review', regionalReachability: 'not-measured', legacySmartV5: 'not-tested' },
    files: Object.fromEntries(ARTIFACTS.map(name => [name, { sha256: sha256(files[name]), bytes: Buffer.byteLength(files[name]) }]))
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
