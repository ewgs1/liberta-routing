import { readJson, validateRegistry, activeEntries, ensure } from './lib.mjs';
try {
  const registry = validateRegistry(await readJson('registry.json'));
  ensure((await readJson('package.json')).version === registry.version, 'package/registry versions differ');
  console.log(`Registry valid: ${registry.entries.length} entries; ${activeEntries(registry).length} approved exact hosts. Regional reachability: not measured.`);
} catch (error) { console.error(error.message); process.exitCode = 1; }
