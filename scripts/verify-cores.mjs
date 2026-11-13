import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson, json, ensure, render } from './lib.mjs';

const directory = await mkdtemp(join(tmpdir(), 'liberta-core-check-'));
try {
  const files = render(await readJson('registry/compatibility-v1.json'));
  const full=JSON.parse(await readFile('dist/smart.xray.json','utf8'));
  const explicit=full.routing.rules.find(rule=>rule.domain?.length && rule.domain.every(x=>x.startsWith('domain:')));
  const xray = {
    log: { loglevel: 'none' },
    outbounds: [{ tag: 'proxy', protocol: 'blackhole', settings: {} }, { tag: 'direct', protocol: 'freedom', settings: {} }],
    routing: {domainStrategy:'AsIs',rules:[explicit,{type:'field',network:'tcp,udp',outboundTag:'proxy'}]}
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
    console.log(`${binary}: explicit domain rule syntax accepted`);
  }
  // The new independent profile is checked as a whole, without any geodata files.
  const selective = JSON.parse(await readFile('examples/remnawave/liberta-selective.xray.json', 'utf8'));
  selective.outbounds.push({ tag: 'proxy', protocol: 'blackhole', settings: {} });
  await writeFile(xrayPath, json(selective));
  await writeFile(sourcePath, await readFile('rules/liberta-direct.singbox.json', 'utf8'));
  for (const [binary, argv] of [['xray', ['run', '-test', '-config', xrayPath]], ['sing-box', ['check', '-c', singboxPath]], ['sing-box-current', ['check', '-c', singboxPath]]]) {
    const result = spawnSync(binary, argv, { encoding: 'utf8', timeout: 20000 });
    ensure(!result.error && result.status === 0, `${binary}: independent rules/profile rejected`);
    console.log(`${binary}: independent rules/profile accepted without country geodata`);
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { await rm(directory, { recursive: true, force: true }); }
