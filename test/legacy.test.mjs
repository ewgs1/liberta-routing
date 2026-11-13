import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

async function fixture(run) {
  const directory = await mkdtemp(join(tmpdir(), 'liberta-legacy-test-'));
  try {
    const registry = join(directory, 'registry.json');
    const foreign = join(directory, 'foreign.json');
    const home = join(directory, 'home.json');
    const output = join(directory, 'result.json');
    await writeFile(registry, JSON.stringify({ classes: { demo: { explicit: true, domains: ['example.com'] } } }));
    await writeFile(foreign, JSON.stringify({ results: [{ domain: 'unconfirmed.example.com', verdict: 'timeout' }] }));
    await writeFile(home, JSON.stringify({ results: [] }));
    await run({ directory, registry, foreign, home, output });
  } finally { await rm(directory, { recursive: true, force: true }); }
}
const build = values => spawnSync(process.execPath, ['scripts/build.mjs', '--registry', values.registry, '--out', values.output, '--canary', values.foreign, ...(values.baseline ? ['--baseline', values.baseline] : [])], { encoding: 'utf8', timeout: 10000 });
test('compatibility builder refuses foreign-only automatic promotion', async () => fixture(async values => {
  assert.notEqual(build(values).status, 0);
  await assert.rejects(readFile(values.output));
}));
test('compatibility builder does not promote domains using an empty or failed baseline', async () => fixture(async values => {
  for (const results of [[], [{ domain: 'unconfirmed.example.com', verdict: 'timeout' }]]) {
    await writeFile(values.home, JSON.stringify({ results }));
    assert.equal(build({ ...values, baseline: values.home }).status, 0);
    const result = JSON.parse(await readFile(values.output, 'utf8'));
    assert.ok(!result.routing.rules.some(rule => rule.domain?.includes('domain:unconfirmed.example.com')));
  }
}));
test('compatibility builder preserves the paired successful-home workflow', async () => fixture(async values => {
  await writeFile(values.home, JSON.stringify({ results: [{ domain: 'unconfirmed.example.com', verdict: 'ok' }] }));
  assert.equal(build({ ...values, baseline: values.home }).status, 0);
  const result = JSON.parse(await readFile(values.output, 'utf8'));
  assert.ok(result.routing.rules.some(rule => rule.domain?.includes('domain:unconfirmed.example.com')));
  assert.equal(result.remarks, 'Liberta Routing v1');
}));
