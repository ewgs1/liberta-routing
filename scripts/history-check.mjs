import { execFileSync } from 'node:child_process';
import { readJson, ensure, json } from './lib.mjs';
import { compare } from '../compare-lists.mjs';

try {
  const base = process.env.BASE_SHA;
  if (!base || /^0+$/.test(base)) console.log('Bootstrap commit: no previous release baseline.');
  else {
    ensure(/^[a-f0-9]{40}$/.test(base), 'invalid base SHA');
    const changed = execFileSync('git', ['diff', '--name-status', '--no-renames', base, 'HEAD', '--', 'releases/'], { encoding: 'utf8' }).trim().split('\n').filter(Boolean);
    ensure(changed.every(line => line.startsWith('A\t')), 'published version directories are immutable; create a new version');
    let oldRegistry;
    try { oldRegistry = JSON.parse(execFileSync('git', ['show', `${base}:registry.json`], { encoding: 'utf8' })); }
    catch { console.log('No previous registry at baseline.'); }
    if (oldRegistry) console.log(json(compare(oldRegistry, await readJson('registry.json'))));
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
