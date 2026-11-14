import { execFileSync } from 'node:child_process';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cidr, validateNetworks } from './network-data.mjs';
import { ensure } from './lib.mjs';

export function scanContent(content) {
  const findings = [];
  const patterns = [
    ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
    ['github-credential', /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
    ['telegram-credential', /\b[0-9]{6,12}:[A-Za-z0-9_-]{30,}\b/],
    ['connection-uri', /\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic):\/\//i],
    ['credential-assignment', /["']?(?:token|api[_-]?key|password|privateKey|secretKey)["']?\s*[:=]\s*["'][A-Za-z0-9_+\/=.-]{8,}["']/i],
    ['ipv4-literal', /\b(?:\d{1,3}\.){3}\d{1,3}\b/],
    ['ip-endpoint', /https?:\/\/\[[0-9a-f:]+\]/i]
  ];
  for (const [kind, pattern] of patterns) if (pattern.test(content)) findings.push(kind);
  return findings;
}
async function filesUnder(root, prefix = '') {
  const result = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (['.git', '.private', '.local', 'node_modules'].includes(entry.name)) continue;
    if (entry.isDirectory()) result.push(...await filesUnder(root, path));
    else result.push(path);
  }
  return result;
}
export async function auditPublic(root = '.') {
  let files;
  try { files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).split('\0').filter(Boolean); }
  catch { files = await filesUnder(root); }
  ensure(files.length > 0, 'public audit: empty file set');
  const approvedNetworks=validateNetworks(JSON.parse(await readFile(join(root,'registry/networks.json'),'utf8'))).entries.map(e=>e.prefix);
  const findings = [];
  for (const path of files) {
    const generatedTemplate = (path.endsWith('/liberta-v1.xray.json') || path === 'dist/liberta.xray.json') || path === 'examples/remnawave/liberta-selective.xray.json';
    if (/(?:^|\/)(?:\.private|\.local|node_modules|\.env)(?:\/|$)|\.(?:pem|key|p12|pfx|log|zip|tgz)$/i.test(path)) findings.push({ path, kind: 'private-or-binary-path' });
    const stat = await lstat(join(root, path));
    if (stat.isSymbolicLink()) { findings.push({ path, kind: 'symlink' }); continue; }
    const content = await readFile(join(root, path), 'utf8');
    if (content.includes('\0')) { findings.push({ path, kind: 'binary-content' }); continue; }
    // Synthetic network addresses and adversarial secrets are confined to code/tests for validation.
    const kinds = scanContent(content).filter(kind => {
      if ((path.startsWith('test/') || path === 'service-canary.mjs' || path === 'scripts/audit-public.mjs') && ['ipv4-literal', 'credential-assignment', 'connection-uri'].includes(kind)) return false;
      if ((path === 'scripts/build.mjs' || path === 'scripts/rule-sets.mjs' || path === 'scripts/integrate.mjs' || path === 'scripts/remnawave-sync.mjs' || path === 'scripts/verify-routing.mjs' || path === 'scripts/verify-dns.mjs' || path.startsWith('examples/happ/') || generatedTemplate) && kind === 'ipv4-literal') {
        const allowed = new Set([...approvedNetworks.map(p=>p.split('/')[0]),'8.8.4.4', '1.1.1.1', '77.88.8.8', '77.88.8.1', '127.0.0.1', '10.0.0.0', '127.0.0.0', '169.254.0.0', '172.16.0.0', '192.168.0.0']);
        return [...content.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].some(match => !allowed.has(match[0]));
      }
      if(kind==='ipv4-literal'&&/^registry\/evidence\/[a-z0-9-]+-networks-(?:\d{8}|latest)\.json$/.test(path)) {
        const data=JSON.parse(content);const prefixes=data.announcements.flatMap(a=>[...a.currentPrefixes,...a.historicalOnlyPrefixes]);for(const prefix of prefixes)cidr(prefix);
        return [...content.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].some(m=>!prefixes.some(p=>p.split('/')[0]===m[0]));
      }
      if(kind==='ipv4-literal' && (path==='registry/network-sources.json'||path==='registry/networks.json'||path.startsWith('rules/liberta-direct-ip.'))) {
        if(path==='registry/network-sources.json') {
          const data=JSON.parse(content);for(const service of data.services)for(const prefix of service.prefixes)cidr(prefix);
          const prefixes=data.services.flatMap(s=>s.prefixes);
          return [...content.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].some(m=>!prefixes.some(p=>p.split('/')[0]===m[0]));
        }
        return [...content.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].some(m=>!approvedNetworks.some(p=>p.split('/')[0]===m[0]));
      }
      return true;
    });
    findings.push(...kinds.map(kind => ({ path, kind })));
    if (/\.json$/.test(path)) {
      let object;
      try { object = JSON.parse(content); } catch { findings.push({ path, kind: 'invalid-json' }); continue; }
      if (generatedTemplate && !object.outbounds?.every(out => ['freedom', 'blackhole'].includes(out.protocol) && ['direct', 'block'].includes(out.tag) && !out.settings?.servers && !out.settings?.vnext)) findings.push({path,kind:'unexpected-connection-outbound'});
      const visit = value => {
        if (!value || typeof value !== 'object') return;
        for (const [key, item] of Object.entries(value)) {
          if ((['outbounds', 'inbounds'].includes(key) && !generatedTemplate) || ['privateKey', 'shortIds', 'uuid', 'token', 'apiKey', 'password', 'nodes'].includes(key)) findings.push({ path, kind: 'server-or-credential-field' });
          visit(item);
        }
      };
      visit(object);
    }
  }
  return { files: files.length, findings };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = await auditPublic();
    // Findings deliberately contain only path and category, never matched secret text.
    if (report.findings.length) { console.error(JSON.stringify(report, null, 2)); process.exitCode = 1; }
    else console.log(`Public audit passed: ${report.files} files. Manual review remains required for domain names and narrative text.`);
  } catch { console.error('Public audit could not complete'); process.exitCode = 1; }
}
