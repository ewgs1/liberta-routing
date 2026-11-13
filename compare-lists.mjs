import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { activeEntries, validateRegistry, readJson, sha256, json, args, ensure, exactKeys, date } from './scripts/lib.mjs';

export function routeState(registry) {
  validateRegistry(registry, { freshness: false });
  return {
    profile: { id: registry.profile.id, defaultRoute: registry.profile.defaultRoute, directTag: registry.profile.directTag, proxyTag: registry.profile.proxyTag },
    rules: activeEntries(registry).map(({ domain, match, route }) => ({ domain, match, route }))
  };
}
export const routeHash = registry => sha256(json(routeState(registry)));
export function compare(base, next) {
  const before = routeState(base), after = routeState(next);
  const oldMap = new Map(before.rules.map(rule => [rule.domain, rule]));
  const newMap = new Map(after.rules.map(rule => [rule.domain, rule]));
  const added = after.rules.filter(rule => !oldMap.has(rule.domain));
  const removed = before.rules.filter(rule => !newMap.has(rule.domain));
  const changed = after.rules.filter(rule => oldMap.has(rule.domain) && json(oldMap.get(rule.domain)) !== json(rule)).map(rule => ({ before: oldMap.get(rule.domain), after: rule }));
  const profileChanged = json(before.profile) !== json(after.profile);
  return { from: routeHash(base), to: routeHash(next), profileChanged, added, removed, changed, routeChanged: profileChanged || !!(added.length + removed.length + changed.length) };
}
export function checkLock(registry, lock, now = new Date()) {
  exactKeys(lock, ['schemaVersion', 'routeSha256', 'reviewedAt', 'reason'], 'route-lock');
  ensure(lock.schemaVersion === 1 && lock.routeSha256 === routeHash(registry), 'routing changed without an updated reviewed route-lock');
  date(lock.reviewedAt, now, 'route-lock.reviewedAt');
  ensure(typeof lock.reason === 'string' && lock.reason.length >= 20 && lock.reason.length <= 1000, 'route-lock: review reason required');
  return true;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = args(process.argv.slice(2), ['--base', '--next', '--lock', '--strict']);
    const next = await readJson(options['--next'] ?? 'registry.json');
    checkLock(next, await readJson(options['--lock'] ?? 'route-lock.json'));
    if (options['--base']) {
      const report = compare(await readJson(options['--base']), next);
      console.log(json(report));
      if (options['--strict'] && report.routeChanged) process.exitCode = 2;
    } else console.log(`Route lock matches: ${routeHash(next)}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
