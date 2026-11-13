import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson, json, ensure, render } from './lib.mjs';

const directory = await mkdtemp(join(tmpdir(), 'liberta-core-check-'));
try {
  const files = render(await readJson('registry.json'));
  const xray = {
    log: { loglevel: 'none' },
    outbounds: [{ tag: 'proxy', protocol: 'blackhole', settings: {} }, { tag: 'direct', protocol: 'freedom', settings: {} }],
    routing: JSON.parse(files['smart.xray.json'])
  };
  const xrayPath = join(directory, 'xray.json');
  const sourcePath = join(directory, 'source.json');
  const singboxPath = join(directory, 'singbox.json');
  await writeFile(xrayPath, json(xray));
  await writeFile(sourcePath, files['smart.singbox.json']);
  await writeFile(singboxPath, json({
    outbounds: [{ tag: 'proxy', type: 'direct' }, { tag: 'direct', type: 'direct' }],
    route: { rule_set: [{ tag: 'liberta-smart', type: 'local', format: 'source', path: sourcePath }], rules: [{ rule_set: ['liberta-smart'], action: 'route', outbound: 'direct' }], final: 'proxy' }
  }));
  // Parser-only checks: no listeners, node addresses, connections or service requests.
  for (const [binary, argv] of [['xray', ['run', '-test', '-config', xrayPath]], ['sing-box', ['check', '-c', singboxPath]], ['sing-box-current', ['check', '-c', singboxPath]]]) {
    const result = spawnSync(binary, argv, { encoding: 'utf8', timeout: 20000 });
    ensure(!result.error && result.status === 0, `${binary} native validation unavailable or failed${result.error?.code === 'ENOENT' ? ': executable not installed' : ''}`);
    console.log(`${binary}: native configuration accepted`);
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { await rm(directory, { recursive: true, force: true }); }
