import { lstat, readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ARTIFACTS, args, ensure, exactKeys, sha256 } from './lib.mjs';

export async function verifyRelease(directory, expectedManifestHash) {
  ensure(typeof expectedManifestHash === 'string' && /^[a-f0-9]{64}$/.test(expectedManifestHash), 'trusted manifest SHA256 required');
  ensure(!(await lstat(directory)).isSymbolicLink(), 'release directory is a symlink');
  ensure((await readdir(directory)).sort().join(',') === [...ARTIFACTS, 'release.json'].sort().join(','), 'unexpected/missing release files');
  for (const name of [...ARTIFACTS, 'release.json']) ensure((await lstat(join(directory, name))).isFile(), 'release must contain only regular files');
  const bytes = await readFile(join(directory, 'release.json'));
  ensure(sha256(bytes) === expectedManifestHash, 'manifest hash mismatch');
  const release = JSON.parse(bytes.toString('utf8'));
  exactKeys(release, ['schemaVersion', 'version', ...(Object.hasOwn(release, 'releaseTag') ? ['releaseTag'] : []), 'profile', 'registrySha256', 'directHostCount', 'verification', 'files'], 'release');
  ensure(release.schemaVersion === 1 && release.profile === 'smart-alpha' && /^\d+\.\d+\.\d+-(alpha|beta)(\.\d+)?$/.test(release.version), 'invalid release identity');
  if (Object.hasOwn(release, 'releaseTag')) ensure(/^v(?:[1-9]\d*|\d+\.\d+\.\d+-(?:alpha|beta)(?:\.\d+)?)$/.test(release.releaseTag), 'invalid release tag');
  exactKeys(release.files, ARTIFACTS, 'release.files');
  for (const name of ARTIFACTS) {
    exactKeys(release.files[name], ['sha256', 'bytes'], 'release.file');
    const content = await readFile(join(directory, name));
    ensure(sha256(content) === release.files[name].sha256 && content.length === release.files[name].bytes, `release integrity failure: ${name}`);
  }
  return release;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = args(process.argv.slice(2), ['--dir', '--manifest-sha256']);
    ensure(options['--dir'], '--dir required');
    const release = await verifyRelease(options['--dir'], options['--manifest-sha256']);
    console.log(`Verified ${release.version}: all three public artifacts match the pinned manifest.`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
