import { resolve, relative, isAbsolute, dirname, basename } from 'node:path';
import { mkdir, writeFile, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { args, ensure, readJson, render, json } from './lib.mjs';

export function integrate(base, registry, format) {
  ensure(base && typeof base === 'object' && !Array.isArray(base), 'one JSON configuration object required');
  const files = render(registry), result = structuredClone(base);
  const tags = new Set((base.outbounds ?? []).map(outbound => outbound.tag));
  const { directTag, proxyTag } = registry.profile;
  ensure(tags.has(directTag) && tags.has(proxyTag), `existing outbounds must define ${directTag} and ${proxyTag}`);
  if (format === 'xray') {
    ensure(!base.routing?.script, 'Xray routing script requires a separate manual review');
    // This explicitly creates an isolated test profile. The original routing is not merged or rewritten on disk.
    result.routing = JSON.parse(files['smart.xray.json']);
  } else if (format === 'singbox') {
    const source = JSON.parse(files['smart.singbox.json']);
    result.route = {
      ...(base.route ?? {}),
      rules: source.rules.map(rule => ({ ...rule, action: 'route', outbound: directTag })),
      final: proxyTag
    };
    // Liberta rules are embedded for the isolated trial. Preserve existing rule sets because DNS may reference them.
  } else throw new Error('format must be xray or singbox');
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
    const options = args(process.argv.slice(2), ['--base', '--registry', '--format', '--out']);
    ensure(options['--base'] && options['--out'] && options['--format'], 'required: --base --format --out');
    const result = integrate(await readJson(options['--base']), await readJson(options['--registry'] ?? 'registry.json'), options['--format']);
    await mkdir('.private', { recursive: true, mode: 0o700 });
    await writeFile(await privateOutput(options['--out'], options['--base']), json(result), { mode: 0o600, flag: 'wx' });
    console.log('Created separate private test configuration. Original profile unchanged. No profile was activated.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
