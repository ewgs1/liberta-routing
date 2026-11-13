import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, render, manifest, json, atomicDirectory, ensure } from './scripts/lib.mjs';

export async function build({ registryPath = 'registry.json', output, check = false } = {}) {
  const bytes = await readFile(registryPath, 'utf8');
  const registry = JSON.parse(bytes);
  const files = render(registry);
  files['release.json'] = json(manifest(registry, bytes, files));
  const destination = output ?? `releases/v${registry.version}`;
  if (check) {
    const names = (await readdir(destination)).sort();
    ensure(names.join(',') === Object.keys(files).sort().join(','), 'release contains missing/extra files');
    for (const [name, content] of Object.entries(files)) ensure(await readFile(join(destination, name), 'utf8') === content, `artifact differs: ${name}`);
  } else await atomicDirectory(destination, files);
  return { destination, files: Object.keys(files), check };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = args(process.argv.slice(2), ['--registry', '--out', '--check']);
    console.log(json(await build({ registryPath: options['--registry'], output: options['--out'], check: options['--check'] })));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
