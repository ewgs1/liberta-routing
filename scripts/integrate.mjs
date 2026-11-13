import { resolve, relative, isAbsolute, dirname, basename } from 'node:path';
import { mkdir, writeFile, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { args, ensure, readJson, render, json } from './lib.mjs';

export function integrate(base, registry, format) {
  ensure(format === 'xray', 'Automatic replacement of the full sing-box routing is disabled; its source export covers explicit domain rules only');
  ensure(base && typeof base === 'object' && !Array.isArray(base), 'configuration object required');
  const result=structuredClone(base);
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
    const options = args(process.argv.slice(2), ['--base', '--registry', '--format', '--out']);
    ensure(options['--base'] && options['--out'] && options['--format'], 'required: --base --format --out');
    const result = integrate(await readJson(options['--base']), await readJson(options['--registry'] ?? 'registry/registry.json'), options['--format']);
    await mkdir('.private', { recursive: true, mode: 0o700 });
    await writeFile(await privateOutput(options['--out'], options['--base']), json(result), { mode: 0o600, flag: 'wx' });
    console.log('Created separate private test configuration. Original profile unchanged. No profile was activated.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
