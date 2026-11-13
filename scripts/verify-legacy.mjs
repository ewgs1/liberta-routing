import { readFile, mkdtemp, rm, mkdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { sha256, ensure } from './lib.mjs';

// The supplied private snapshot is never committed. A digest contains no node configuration.
const root = resolve('.private/legacy');
const expected = '399e02f737cc97bab29cdbbe54a145269c091048dd6cbd099435f44dd16e219d';
let directory;
try {
  const saved = await readFile(join(root, 'releases/smart-v5.generated.json'));
  ensure(sha256(saved) === expected, 'legacy baseline differs from the supplied snapshot');
  await mkdir('.private', { recursive: true, mode: 0o700 });
  directory = await mkdtemp(resolve('.private/legacy-check-'));
  const output = join(directory, 'rebuilt.json');
  const result = spawnSync(process.execPath, ['scripts/build.mjs', '--registry', join(root, 'registry/registry.json'), '--out', output], { encoding: 'utf8', timeout: 15000 });
  ensure(!result.error && result.status === 0, 'legacy builder failed');
  const rebuilt=JSON.parse(await readFile(output,'utf8'));
  ensure(rebuilt.remarks === 'Liberta Routing v1','new profile name missing');
  rebuilt.remarks=JSON.parse(saved).remarks;
  ensure(sha256(JSON.stringify(rebuilt,null,2)+'\n') === expected, 'Regression: routing, DNS or other configuration changed');
  console.log(`Rename-only regression passed: all fields except remarks match supplied baseline (${expected}). No live configuration changed.`);
} catch (error) {
  console.error(error.code === 'ENOENT' ? 'Private supplied Smart v5 baseline is unavailable; legacy verification was not performed.' : error.message);
  process.exitCode = 1;
} finally { if (directory) await rm(directory, { recursive: true, force: true }); }
