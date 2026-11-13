import { execFileSync } from 'node:child_process';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
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
  const findings = [];
  for (const path of files) {
    if (/(?:^|\/)(?:\.private|\.local|node_modules|\.env)(?:\/|$)|\.(?:pem|key|p12|pfx|log|zip|tgz)$/i.test(path)) findings.push({ path, kind: 'private-or-binary-path' });
    const stat = await lstat(join(root, path));
    if (stat.isSymbolicLink()) { findings.push({ path, kind: 'symlink' }); continue; }
    const content = await readFile(join(root, path), 'utf8');
    if (content.includes('\0')) { findings.push({ path, kind: 'binary-content' }); continue; }
    // Synthetic network addresses and adversarial secrets are confined to code/tests for validation.
    const kinds = scanContent(content).filter(kind => {
      if ((path.startsWith('test/') || path === 'service-canary.mjs' || path === 'scripts/audit-public.mjs') && ['ipv4-literal', 'credential-assignment', 'connection-uri'].includes(kind)) return false;
      if ((path === 'scripts/build.mjs' || path.endsWith('/smart.xray.json')) && kind === 'ipv4-literal') {
        const allowed = new Set(['8.8.4.4', '1.1.1.1', '77.88.8.8', '77.88.8.1', '127.0.0.1']);
        return [...content.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].some(match => !allowed.has(match[0]));
      }
      return true;
    });
    findings.push(...kinds.map(kind => ({ path, kind })));
    if (/\.json$/.test(path)) {
      let object;
      try { object = JSON.parse(content); } catch { findings.push({ path, kind: 'invalid-json' }); continue; }
      if (path.endsWith('/smart.xray.json') && !object.outbounds.every(out => ['freedom', 'blackhole'].includes(out.protocol) && ['direct', 'block'].includes(out.tag) && !out.settings?.servers && !out.settings?.vnext)) findings.push({path,kind:'unexpected-connection-outbound'});
      const visit = value => {
        if (!value || typeof value !== 'object') return;
        for (const [key, item] of Object.entries(value)) {
          if ((['outbounds', 'inbounds'].includes(key) && !path.endsWith('/smart.xray.json')) || ['privateKey', 'shortIds', 'uuid', 'token', 'apiKey', 'password', 'nodes'].includes(key)) findings.push({ path, kind: 'server-or-credential-field' });
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
