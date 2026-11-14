import { readFile, readdir, mkdir, mkdtemp, lstat, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateNetworks } from './network-data.mjs';
import { ensure, json } from './lib.mjs';
import { independentFiles, selectiveTemplate, happProfile } from './rule-sets.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export async function generatedRules() {
  const registryBytes = await readFile(join(ROOT, 'registry/registry.json'), 'utf8');
  const provenanceBytes = await readFile(join(ROOT, 'registry/provenance.json'), 'utf8');
  const registry = JSON.parse(registryBytes), provenance = JSON.parse(provenanceBytes);
  const networks=validateNetworks(JSON.parse(await readFile(join(ROOT,'registry/networks.json'),'utf8')));
  return {
    rules: independentFiles(registry, provenance, registryBytes, provenanceBytes, networks),
    template: json(selectiveTemplate(registry, JSON.parse(await readFile(join(ROOT, 'dist/liberta-v1.xray.json'), 'utf8')), {networks:networks.entries})),
    happ: Object.fromEntries([false, true].flatMap(fakeDNS => {
      const profile = happProfile(registry, { fakeDNS, networks:networks.entries });
      const name = fakeDNS ? 'liberta-selective-fakedns' : 'liberta-selective';
      return [[name + '.json', json(profile)], [name + '.txt', 'happ://routing/add/' + Buffer.from(JSON.stringify(profile)).toString('base64') + '\n']];
    }))
  };
}

export async function writeRules(target, files) {
  await mkdir(dirname(target), { recursive: true });
  let exists = false;
  try { const stat = await lstat(target); ensure(stat.isDirectory() && !stat.isSymbolicLink(), 'rules output must be a regular directory'); exists = true; }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const temporary = await mkdtemp(join(dirname(target), '.liberta-rules-'));
  const backup = temporary + '-previous';
  let backedUp = false;
  try {
    for (const [name, body] of Object.entries(files)) {
      ensure(!name.includes('/') && !name.includes('\\') && /^[a-z0-9.-]+$/.test(name), 'unsafe generated name');
      await writeFile(join(temporary, name), body, { flag: 'wx' });
    }
    if (exists) { await rename(target, backup); backedUp = true; }
    try { await rename(temporary, target); }
    catch (error) { if (backedUp) { await rename(backup, target); backedUp = false; } throw error; }
    if (backedUp) await rm(backup, { recursive: true });
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

export async function buildRules({ check = false } = {}) {
  const generated = await generatedRules();
  const output = join(ROOT, 'rules');
  const example = join(ROOT, 'examples/remnawave/liberta-selective.xray.json');
  if (check) {
    ensure((await readdir(output)).sort().join(',') === Object.keys(generated.rules).sort().join(','), 'independent files missing or unexpected');
    for (const [name, body] of Object.entries(generated.rules)) ensure(await readFile(join(output, name), 'utf8') === body, `independent list differs: ${name}`);
    ensure(await readFile(example, 'utf8') === generated.template, 'selective example differs');
    ensure(await readFile(join(ROOT,'dist/liberta.xray.json'),'utf8') === generated.template, 'primary template differs');
    const happOutput = join(ROOT, 'examples/happ');
    ensure((await readdir(happOutput)).sort().join(',') === Object.keys(generated.happ).sort().join(','), 'unexpected Happ files');
    for (const [name, body] of Object.entries(generated.happ)) ensure(await readFile(join(happOutput, name), 'utf8') === body, `Happ profile differs: ${name}`);
  } else {
    await writeRules(output, generated.rules);
    await mkdir(dirname(example), { recursive: true });
    const temporary = example + '.tmp';
    await writeFile(temporary, generated.template);
    await rename(temporary, example);
    await writeFile(join(ROOT,'dist/liberta.xray.json.tmp'),generated.template);
    await rename(join(ROOT,'dist/liberta.xray.json.tmp'),join(ROOT,'dist/liberta.xray.json'));
    await writeRules(join(ROOT, 'examples/happ'), generated.happ);
  }
  return { domains: JSON.parse(generated.rules['manifest.json']).domains, files: Object.keys(generated.rules).length, check };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    ensure(process.argv.slice(2).every(argument => argument === '--check') && process.argv.length <= 3, 'usage: node scripts/build-rules.mjs [--check]');
    console.log(json(await buildRules({ check: process.argv.includes('--check') })));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
