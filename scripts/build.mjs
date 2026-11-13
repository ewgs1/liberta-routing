#!/usr/bin/env node
// Собирает клиентский конфиг Xray из реестра сервисов.
// Руками списки доменов не правятся: они появляются здесь из registry.json
// и из отчётов проверялки audit/service-canary.mjs.

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Пути считаются от корня проекта, а не от текущего каталога:
// скрипт одинаково работает из своего каталога и из корня репозитория.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const out = {
    registry: path.join(ROOT, '.private/legacy/registry/registry.json'),
    canary: '',
    baseline: '',
    // Тег gov по умолчанию выключен: geosite:category-ru уже включает
    // category-gov-ru, отдельное правило дублирует его и добавляет лишнюю
    // зависимость от сборки клиента. Нужен, когда category-ru заменяется
    // набором узких категорий (режим Strict).
    gov: false,
    diag: false,
    checkTags: false,
    out: path.join(ROOT, '.private/smart-v5.generated.json')
  };
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const value = argv[i + 1];
    if (key === '--registry') { out.registry = value; i += 1; }
    else if (key === '--canary') { out.canary = value; i += 1; }
    else if (key === '--baseline') { out.baseline = value; i += 1; }
    else if (key === '--gov') { out.gov = true; }
    else if (key === '--diag') { out.diag = true; }
    else if (key === '--check-tags') { out.checkTags = true; }
    else if (key === '--out') { out.out = value; i += 1; }
    else if (key === '--help' || key === '-h') {
      console.log('node routing/build.mjs --canary <отчёт с зарубежной точки> --baseline <отчёт с домашней> [--out ...]');
      process.exit(0);
    }
  }
  return out;
}

// Отказом считаем всё, что не дало нормального ответа. Отдельно стоят
// no-dns (домена нет) и server-error (сервис лежит) — это не про адрес.
const FAIL_VERDICTS = new Set(['blocked', 'blocked-page', 'blocked-redirect', 'timeout', 'reset', 'no-tcp', 'no-route', 'tls-error', 'network-error']);
const OK_VERDICTS = new Set(['ok', 'redirect']);
const DLC = 'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/';

const args = parseArgs(process.argv.slice(2));
const registry = JSON.parse(await readFile(args.registry, 'utf8'));
if (args.canary && !args.baseline) throw new Error('Canary promotion requires a non-empty successful home baseline');


const explicit = new Map();
// Домены, подтверждённые замером, живут в реестре, а не в отчёте:
// иначе сборка без отчёта давала бы другой результат, чем в проде.
for (const item of registry.measured_exceptions || []) explicit.set(item.domain, 'measured');
for (const [name, cls] of Object.entries(registry.classes)) {
  if (cls.explicit !== true) continue;
  for (const domain of cls.domains) explicit.set(domain, name);
}

// В явный список попадает только то, что отказало с зарубежной точки
// и при этом работало с домашней. Один отказ без второго замера — не факт.
const measured = new Map();
if (args.canary) {
  const foreign = JSON.parse(await readFile(args.canary, 'utf8'));
  const home = args.baseline ? JSON.parse(await readFile(args.baseline, 'utf8')) : null;
  const homeByDomain = new Map();
  for (const item of home?.results || []) homeByDomain.set(item.domain, item.verdict);
  for (const item of foreign.results || []) {
    if (!FAIL_VERDICTS.has(item.verdict)) continue;
    if (explicit.has(item.domain)) continue;
    if (!OK_VERDICTS.has(homeByDomain.get(item.domain))) continue;
    measured.set(item.domain, item.verdict);
  }
  for (const domain of measured.keys()) explicit.set(domain, 'measured');
}

const ruDomains = [...explicit.keys()].sort();
// Отдельный тег для государственных ресурсов: в стандартной базе он есть,
// в урезанных сборках клиента может отсутствовать. Держим отдельным правилом,
// чтобы при отказе убрать одну строку, а не пересобирать список.
const govTags = args.gov ? ['geosite:category-gov-ru'] : [];
const ruDnsDomains = ['geosite:category-ru', ...govTags, ...ruDomains.map((domain) => `domain:${domain}`)];

// Два российских резолвера с одинаковыми настройками: Xray считает их одной
// группой и при enableParallelQuery опрашивает одновременно, а между группами
// резерв остаётся последовательным.
const ruServer = (address) => ({
  address,
  port: 53,
  domains: ruDnsDomains,
  timeoutMs: 1500,
  skipFallback: true,
  queryStrategy: 'UseIPv4'
});

const config = {
  remarks: 'Liberta Smart v5',
  log: {
    // В диагностическом профиле журнал включён: без него нельзя доказать,
    // какой outbound выбран для конкретного домена.
    access: args.diag ? '' : 'none',
    dnsLog: args.diag,
    loglevel: args.diag ? 'info' : 'warning',
    maskAddress: 'full'
  },
  dns: {
    hosts: {
      'dns.google': '8.8.4.4',
      'cloudflare-dns.com': '1.1.1.1'
    },
    queryStrategy: 'UseIPv4',
    disableCache: false,
    disableFallback: false,
    // Российские имена не должны получать зарубежный ответ при таймауте.
    disableFallbackIfMatch: true,
    enableParallelQuery: true,
    servers: [
      {
        address: 'localhost',
        domains: ['regexp:.*\\.local$', 'regexp:.*\\.lan$', 'domain:localhost'],
        skipFallback: true,
        queryStrategy: 'UseIPv4'
      },
      ruServer('77.88.8.8'),
      ruServer('77.88.8.1'),
      // Только DoH: обычный DNS после выхода из туннеля идёт открытым текстом
      // и позволяет видеть имена на участке «узел — резолвер».
      'https://cloudflare-dns.com/dns-query',
      'https://dns.google/dns-query'
    ]
  },
  routing: {
    domainMatcher: 'hybrid',
    // IPOnDemand резолвит имя в момент, когда маршрутизатор доходит до правила с IP.
    // IPIfNonMatch здесь не работает: последнее правило перехватывает всё, поэтому
    // второй проход не наступает и geoip:ru к доменам не применяется.
    domainStrategy: 'IPOnDemand',
    rules: [
      {
        type: 'field',
        protocol: ['bittorrent'],
        outboundTag: 'block'
      },
      {
        type: 'field',
        domain: ['regexp:.*\\.local$', 'regexp:.*\\.lan$', 'domain:localhost'],
        outboundTag: 'direct'
      },
      {
        type: 'field',
        domain: ruDomains.map((domain) => `domain:${domain}`),
        outboundTag: 'direct'
      },
      {
        type: 'field',
        domain: govTags,
        outboundTag: 'direct'
      },
      {
        type: 'field',
        domain: ['geosite:category-ru'],
        outboundTag: 'direct'
      },
      {
        type: 'field',
        ip: ['77.88.8.8/32', '77.88.8.1/32'],
        port: '53',
        network: 'tcp,udp',
        outboundTag: 'direct'
      },
      {
        type: 'field',
        ip: ['geoip:private'],
        outboundTag: 'direct'
      },
      {
        type: 'field',
        ip: ['geoip:ru'],
        outboundTag: 'direct'
      },
      {
        type: 'field',
        network: 'tcp,udp',
        outboundTag: 'proxy'
      }
    ]
  },
  inbounds: [
    {
      tag: 'socks',
      port: 10808,
      listen: '127.0.0.1',
      protocol: 'socks',
      settings: { udp: true, auth: 'noauth' },
      sniffing: { enabled: true, routeOnly: true, destOverride: ['http', 'tls', 'quic'] }
    },
    {
      tag: 'http',
      port: 10809,
      listen: '127.0.0.1',
      protocol: 'http',
      settings: { allowTransparent: false },
      sniffing: { enabled: true, routeOnly: true, destOverride: ['http', 'tls', 'quic'] }
    }
  ],
  outbounds: [
    {
      tag: 'direct',
      protocol: 'freedom',
      settings: {},
      // По документации Freedom стратегию разрешения задаёт sockopt, а не settings.
      // UseIPv4 нужен, чтобы прямые соединения по имени шли через встроенный DNS
      // (и его разделение на российский и зарубежный), а не через системный резолвер.
      streamSettings: {
        sockopt: {
          domainStrategy: 'UseIPv4'
        }
      }
    },
    {
      tag: 'block',
      protocol: 'blackhole',
      settings: { response: { type: 'http' } }
    }
  ],
  remnawave: {
    addVirtualHostAsOutbound: true
  }
};

// Пустое правило по домену Xray не примет, поэтому при отключённом gov-теге
// оно просто выпадает из списка.
config.routing.rules = config.routing.rules.filter(
  (rule) => !(Array.isArray(rule.domain) && rule.domain.length === 0)
);

// Проверки, без которых конфиг нельзя считать собранным правильно.
const knownOutbounds = new Set(['direct', 'block', 'proxy']); // proxy добавляет панель
const badOutbounds = config.routing.rules
  .map((rule) => rule.outboundTag)
  .filter((tag) => !knownOutbounds.has(tag));
if (badOutbounds.length) {
  console.error(`Неизвестный outboundTag: ${[...new Set(badOutbounds)].join(', ')}`);
  process.exitCode = 1;
}

const geositeTags = new Set();
for (const rule of config.routing.rules) {
  for (const entry of rule.domain || []) {
    if (entry.startsWith('geosite:')) geositeTags.add(entry.slice('geosite:'.length));
  }
  for (const entry of config.dns.servers.flatMap((server) => server.domains || [])) {
    if (entry.startsWith('geosite:')) geositeTags.add(entry.slice('geosite:'.length));
  }
}

if (args.checkTags) {
  for (const tag of geositeTags) {
    const res = await fetch(`${DLC}${tag}`, { method: 'HEAD', headers: { 'user-agent': 'liberta-build' } });
    console.log(`geosite:${tag} — ${res.ok ? 'есть в базе v2fly' : `нет в базе v2fly (${res.status})`}`);
  }
}

await writeFile(args.out, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
const byClass = {};
for (const [domain, name] of explicit) byClass[name] = (byClass[name] || 0) + 1;
console.log(`Явный список: ${ruDomains.length} доменов`);
console.log(Object.entries(byClass).map(([k, v]) => `${k}: ${v}`).join('  '));
if (measured.size) console.log(`Добавлено по замеру: ${[...measured.keys()].join(', ')}`);
console.log(`Записано: ${args.out}`);
