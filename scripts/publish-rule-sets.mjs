import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensure, json } from './lib.mjs';
import { buildRules } from './build-rules.mjs';

// Manually dispatched publisher. It updates only the public data branch and never
// changes a version tag, GitHub release, production subscription or source branch.
const repository = process.env.GH_REPO;
const source = process.env.GITHUB_SHA;
let temporary;
try {
  ensure(repository === 'ewgs1/liberta-routing', 'unexpected publication repository');
  ensure(/^[a-f0-9]{40}$/.test(source ?? ''), 'verified source commit required');
  ensure(spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim() === source, 'checkout differs from verified source');
  await buildRules({ check: true });
  temporary = await mkdtemp(join(tmpdir(), 'liberta-publish-rules-'));
  let sequence = 0;
  const api = async (method, path, body) => {
    const argv = ['api', '--method', method, `repos/${repository}/${path}`];
    if (body) {
      const input = join(temporary, `${sequence++}.json`);
      await writeFile(input, json(body), { mode: 0o600 });
      argv.push('--input', input);
    }
    const result = spawnSync('gh', argv, { encoding: 'utf8', timeout: 30000 });
    ensure(!result.error && result.status === 0, `GitHub ${method} ${path} failed`);
    return JSON.parse(result.stdout);
  };
  const branches = await api('GET', 'git/matching-refs/heads/release');
  const existing = branches.find(ref => ref.ref === 'refs/heads/release');
  const manifest = JSON.parse(await readFile('rules/manifest.json', 'utf8'));
  const tree = [];
  for (const name of (await readdir('rules')).sort()) {
    let content = await readFile(join('rules', name), 'utf8');
    if (name === 'manifest.json') content = json({ ...JSON.parse(content), sourceCommit: source });
    tree.push({ path: name, mode: '100644', type: 'blob', content });
  }
  tree.push({ path: 'README.md', mode: '100644', type: 'blob', content: `# Liberta Routing rule sets\n\n${manifest.domains} выбранных доменов и ${manifest.categories} категорий из собственного реестра Liberta.\n\nИсточник: https://github.com/${repository}/tree/${source}\n\nПодключение: https://github.com/${repository}/blob/${source}/docs/OWN_RULES.md\n\nЛицензия MIT. Данные не включают country-wide списки, геобазы или подключения VPN-узлов.\n` });
  tree.push({ path: 'LICENSE', mode: '100644', type: 'blob', content: await readFile('LICENSE', 'utf8') });
  const createdTree = await api('POST', 'git/trees', { tree });
  const commit = await api('POST', 'git/commits', { message: `Publish own rule sets from ${source}`, tree: createdTree.sha, parents: [existing?.object.sha ?? source] });
  if (existing) await api('PATCH', 'git/refs/heads/release', { sha: commit.sha, force: false });
  else await api('POST', 'git/refs', { ref: 'refs/heads/release', sha: commit.sha });
  console.log(`Own rule sets published: https://github.com/${repository}/tree/release`);
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { if (temporary) await rm(temporary, { recursive: true, force: true }); }
