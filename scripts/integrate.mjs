import { resolve, relative, isAbsolute, dirname, basename } from 'node:path';
import { mkdir, writeFile, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { args, ensure, readJson, render, json } from './lib.mjs';
import { selectiveTemplate } from './rule-sets.mjs';

export function integrate(base, registry, format, { mode = 'rename', template } = {}) {
  ensure(format === 'xray', 'Automatic replacement of the full sing-box routing is disabled; its source export covers explicit domain rules only');
  ensure(base && typeof base === 'object' && !Array.isArray(base), 'configuration object required');
  const result=structuredClone(base);
  ensure(['rename', 'selective'].includes(mode), 'unknown integration mode');
  if (mode === 'selective') {
    ensure(template && Array.isArray(base.inbounds) && Array.isArray(base.outbounds), 'complete Xray configuration and template required');
    const byTag = new Map(base.outbounds.map(outbound => [outbound.tag, outbound]));
    ensure(byTag.size === base.outbounds.length && byTag.has('proxy') && byTag.get('direct')?.protocol === 'freedom' && byTag.get('block')?.protocol === 'blackhole', 'expected unique proxy/direct/block outbounds; no connection settings will be invented');
    ensure(!base.fakedns && !base.routing?.balancers && !base.routing?.rules?.some(rule => rule.balancerTag), 'existing FakeDNS or balancers require a separate integration review');
    ensure(base.inbounds.every(inbound => ['socks', 'http'].includes(inbound.protocol) && inbound.listen === '127.0.0.1'), 'only local client SOCKS/HTTP inbounds are supported');
    const generated = selectiveTemplate(registry, template);
    result.remarks = 'Liberta Routing v1 — Selective test';
    result.dns = generated.dns;
    result.routing = generated.routing;
    for (const inbound of result.inbounds) inbound.sniffing = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };
    return result;
  }
  result.remarks='Liberta Routing v1';
  return result;
}
export async function privateOutput(target, input) {
  const root = await realpath('.private');
  const output = resolve(target);
  const rel = relative(root, output);
  ensure(rel && !rel.startsWith('..') && !isAbsolute(rel) && resolve(input) !== output, 'output must be a separate file under .private/');
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  const parent = await realpath(dirname(output));
  const parentRelative = relative(root, parent);
  ensure(!parentRelative.startsWith('..') && !isAbsolute(parentRelative), 'output parent escapes .private/');
  return resolve(parent, basename(output));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = args(process.argv.slice(2), ['--base', '--registry', '--format', '--out', '--mode']);
    ensure(options['--base'] && options['--out'] && options['--format'], 'required: --base --format --out');
    const result = integrate(await readJson(options['--base']), await readJson(options['--registry'] ?? 'registry/registry.json'), options['--format'], { mode: options['--mode'] ?? 'rename', template: options['--mode'] === 'selective' ? await readJson('dist/smart.xray.json') : undefined });
    await mkdir('.private', { recursive: true, mode: 0o700 });
    await writeFile(await privateOutput(options['--out'], options['--base']), json(result), { mode: 0o600, flag: 'wx' });
    console.log('Created separate private test configuration. Original profile unchanged. No profile was activated.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
