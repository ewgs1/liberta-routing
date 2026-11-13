import { allEntries, ensure, json, sha256, validateRegistry } from './lib.mjs';

export const DIRECT_TAG = 'direct';
export const PROXY_TAG = 'proxy';
export const LOCAL_NETWORKS = ['10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10'];
const lexical = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function selectedDomains(registry) {
  validateRegistry(registry);
  // explicit is a legacy optimisation for the old geodata-based template.
  // Every class already has policy: direct; the independent list includes all of them.
  return [...new Set(allEntries(registry).map(entry => entry.domain))].sort(lexical);
}

export function domainRule(domains) {
  ensure(domains.length > 0, 'empty independent rule set');
  return { type: 'field', domain: domains.map(domain => `domain:${domain}`), outboundTag: DIRECT_TAG };
}

export function renderSet(domains) {
  const sorted = [...new Set(domains)].sort(lexical);
  return {
    'domains.txt': sorted.map(domain => `domain:${domain}`).join('\n') + '\n',
    'singbox.json': json({ version: 1, rules: [{ domain_suffix: sorted }] }),
    'xray.json': json(domainRule(sorted))
  };
}

export function independentFiles(registry, provenance, registryBytes, provenanceBytes) {
  const domains = selectedDomains(registry);
  ensure(provenance.schemaVersion === 1 && Array.isArray(provenance.entries), 'invalid provenance registry');
  const sourceDomains = provenance.entries.map(entry => entry.domain).sort(lexical);
  ensure(sourceDomains.join('\n') === domains.join('\n'), 'provenance must cover every selected domain exactly once');
  const groups = { 'liberta-direct': domains };
  for (const [name, group] of Object.entries(registry.classes)) {
    const tag = `liberta-${name.replaceAll('_', '-')}`;
    ensure(!Object.hasOwn(groups, tag), 'duplicate generated rule-set tag');
    groups[tag] = group.domains;
  }
  const files = {};
  const sets = {};
  for (const [tag, group] of Object.entries(groups)) {
    const rendered = renderSet(group);
    sets[tag] = { domains: group.length, files: {} };
    for (const [format, content] of Object.entries(rendered)) {
      const name = `${tag}.${format}`;
      files[name] = content;
      sets[tag].files[format] = { name, sha256: sha256(content), bytes: Buffer.byteLength(content) };
    }
  }
  files['manifest.json'] = json({
    schemaVersion: 1,
    project: 'liberta-routing',
    scope: 'selected-services',
    matching: 'domain-and-subdomains',
    domains: domains.length,
    categories: Object.keys(registry.classes).length,
    registrySha256: sha256(registryBytes),
    provenanceSha256: sha256(provenanceBytes),
    selectionSha256: sha256(json(domains)),
    externalRoutingDatabases: [],
    verification: 'existing-liberta-registry; source review and regional application tests remain separate',
    sets
  });
  return files;
}

export function selectiveTemplate(registry, compatibleTemplate) {
  const domains = selectedDomains(registry);
  const result = structuredClone(compatibleTemplate);
  ensure(result.dns?.servers && result.inbounds && result.outbounds, 'complete base template required');
  result.remarks = 'Liberta Routing — Selective';
  for (const server of result.dns.servers) {
    if (typeof server !== 'object' || !Array.isArray(server.domains)) continue;
    if (server.domains.some(domain => domain.startsWith('geosite:'))) server.domains = domains.map(domain => `domain:${domain}`);
  }
  result.routing = {
    domainStrategy: 'AsIs',
    rules: [
      { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
      { type: 'field', domain: ['regexp:.*\\.local$', 'regexp:.*\\.lan$', 'domain:localhost'], outboundTag: DIRECT_TAG },
      domainRule(domains),
      { type: 'field', ip: ['77.88.8.8/32', '77.88.8.1/32'], port: '53', network: 'tcp,udp', outboundTag: DIRECT_TAG },
      { type: 'field', ip: LOCAL_NETWORKS, outboundTag: DIRECT_TAG },
      { type: 'field', network: 'tcp,udp', outboundTag: PROXY_TAG }
    ]
  };
  ensure(!/(?:geosite:|geoip:|ext:)/.test(json(result)), 'selective template must not depend on external geodata');
  return result;
}

export function matchesDomain(domain, suffix) {
  return domain === suffix || domain.endsWith(`.${suffix}`);
}
