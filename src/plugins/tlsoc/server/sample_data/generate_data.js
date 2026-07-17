/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLSOC Security Logs sample dataset — deterministic generator (dev tool, not imported at runtime).
 *
 * Regenerate the committed artifact with:
 *   node src/plugins/tlsoc/server/sample_data/generate_data.js
 *
 * v2 design (multi-source SIEM rewrite for the "collection cockpit" Overview page):
 * - ~40k ECS events over the 14 days ENDING at CURRENT_TIME_MARKER (install rebases to "now",
 *   preserveDayOfWeekTimeOfDay: true), business-hours weighted (IST 09:00-18:00 heaviest),
 *   weekend lighter, last day before the marker denser.
 * - A full campus "estate" on every doc: observer.{org,dept,env,server,source_host,
 *   source_program,type,vendor,product} across 11 source types (nginx per-app reverse proxies,
 *   squid forward proxies, firewalls, postfix, sshd/pam, suricata, unbound DNS, roundcube
 *   webmail, an in-house ERP, ModSecurity WAF, Wazuh EDR).
 * - Every doc carries event.ingested (a realistic 200ms-4s ingest lag over @timestamp, 80%
 *   under 1.5s), event.timestamp_source ('log' ~98.5% / 'ingest_fallback' ~1.5%), ecs.version.
 * - Geo/AS is a FIXED lookup keyed by a small pool of external IPs (India ~65%, global ~35%
 *   across US/DE/NL/RU/CN/BR/SG/GB) so aggregations (top talkers, ASN, country) stay internally
 *   consistent. Internal traffic uses private 10.x addresses with no geo.
 * - Four planted stories, tagged tlsoc.story:
 *     1. brute-force   — ~420 failed sshd logins from one external IP at marker-2days, then
 *                         2 successes for svc-ldap; a correlated Wazuh alert ~90s later.
 *     2. waf-ids-spike  — a SQLi burst (ModSecurity + Suricata, same external IP) against
 *                         nginx_app_results at marker-5days, with a matching nginx 5xx bump
 *                         (carries forward the spirit of the old brute-force/web-scan pair).
 *     3. (untagged)     — proxy-07 goes silent for the last 4 days before the marker (a source
 *                         that stopped shipping logs — no special tag, the story IS the gap).
 *     4. onboarding-*   — Wazuh/EDR onboards ~18h before the marker (trickle after); the
 *                         nginx_app_grievance app (web-app-24, staging) onboards ~6h before it.
 * - Only documentation/TEST-NET/private IP ranges for the "attacker" IPs.
 * - Seeded PRNG (LCG) → byte-identical output on every run. No Math.random / Date.now.
 */

/* eslint-disable no-console */
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const CURRENT_TIME_MARKER = '2026-01-05T00:00:00'; // must match index.ts dataIndices config
const MARKER_MS = Date.parse(CURRENT_TIME_MARKER + 'Z');
const DAY = 24 * 60 * 60 * 1000;
const DAYS = 14;
const START_MS = MARKER_MS - DAYS * DAY;
const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
const ECS_VERSION = '8.11.0';

// --- deterministic PRNG (LCG, Numerical Recipes constants) ---
let seed = 0x7150c;
const rand = () => {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 0x100000000;
};
const randInt = (min, max) => min + Math.floor(rand() * (max - min + 1));
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const randHex = (len) => {
  let s = '';
  for (let i = 0; i < len; i++) s += Math.floor(rand() * 16).toString(16);
  return s;
};

const iso = (ms) => new Date(ms).toISOString();

// --- ingest-lag stamping: every doc gets event.ingested + event.timestamp_source + ecs.version ---
const ingestLagMs = () => (rand() < 0.8 ? randInt(200, 1500) : randInt(1501, 4000));
const stampTimes = (tsMs) => {
  const fallback = rand() < 0.015;
  // 'ingest_fallback' docs still need event.ingested strictly > @timestamp (never equal).
  const lag = fallback ? randInt(1, 50) : ingestLagMs();
  return { ts: iso(tsMs), ingested: iso(tsMs + lag), timestampSource: fallback ? 'ingest_fallback' : 'log' };
};

const makeDoc = (tsMs, { message, event, observer, ...rest }) => {
  const t = stampTimes(tsMs);
  return {
    '@timestamp': t.ts,
    ecs: { version: ECS_VERSION },
    ...(message ? { message } : {}),
    event: { ...event, ingested: t.ingested, timestamp_source: t.timestampSource },
    observer,
    ...rest,
  };
};

// --- day/time weighting: business-hours (IST) heaviest, weekend lighter, last day denser ---
const dayWeights = () => {
  const weights = [];
  for (let d = 0; d < DAYS; d++) {
    const dow = new Date(START_MS + d * DAY).getUTCDay(); // 0 Sun .. 6 Sat
    let w = dow === 0 || dow === 6 ? 0.55 : 1.0;
    if (d === DAYS - 1) w *= 1.6; // the day immediately before the marker
    weights.push(w);
  }
  return weights;
};
const DAY_WEIGHTS = dayWeights();

const distributeInt = (total, weights) => {
  const sum = weights.reduce((a, b) => a + b, 0);
  const raw = weights.map((w) => (w / sum) * total);
  const counts = raw.map(Math.floor);
  const assigned = counts.reduce((a, b) => a + b, 0);
  const remainder = total - assigned;
  const order = raw.map((r, i) => [r - Math.floor(r), i]).sort((a, b) => b[0] - a[0] || a[1] - b[1]);
  for (let i = 0; i < remainder; i++) counts[order[i % order.length][1]]++;
  return counts;
};
const countsPerDay = (total) => distributeInt(total, DAY_WEIGHTS);

const eventTimeInDay = (dayStart, businessWeight) => {
  const hourIst = rand() < businessWeight ? randInt(9, 17) : randInt(0, 23);
  const msOfDay = hourIst * 3600000 + randInt(0, 3599999);
  return dayStart + msOfDay - IST_OFFSET_MS;
};

// --- geo/AS lookup: a FIXED pool of external IPs, each mapped to one consistent tuple ---
const INDIA_GEOS = [
  { ip: '49.36.16.42', city: 'Mumbai', lat: 19.076, lon: 72.8777, asn: 24560, asOrg: 'Bharti Airtel Limited' },
  { ip: '49.36.201.118', city: 'Pune', lat: 18.5204, lon: 73.8567, asn: 24560, asOrg: 'Bharti Airtel Limited' },
  { ip: '103.21.58.44', city: 'Bengaluru', lat: 12.9716, lon: 77.5946, asn: 55836, asOrg: 'Reliance Jio Infocomm Limited' },
  { ip: '103.21.212.9', city: 'Delhi', lat: 28.6139, lon: 77.209, asn: 55836, asOrg: 'Reliance Jio Infocomm Limited' },
  { ip: '117.198.45.3', city: 'Hyderabad', lat: 17.385, lon: 78.4867, asn: 45609, asOrg: 'Bharat Sanchar Nigam Limited' },
  { ip: '117.198.121.187', city: 'Chennai', lat: 13.0827, lon: 80.2707, asn: 45609, asOrg: 'Bharat Sanchar Nigam Limited' },
  { ip: '106.51.22.90', city: 'Kolkata', lat: 22.5726, lon: 88.3639, asn: 24560, asOrg: 'Bharti Airtel Limited' },
  { ip: '157.32.66.14', city: 'Ahmedabad', lat: 23.0225, lon: 72.5714, asn: 17488, asOrg: 'Hathway Cable and Datacom Limited' },
  { ip: '122.161.9.201', city: 'Jaipur', lat: 26.9124, lon: 75.7873, asn: 9829, asOrg: 'National Internet Backbone' },
  { ip: '223.176.15.90', city: 'Nagpur', lat: 21.1458, lon: 79.0882, asn: 45609, asOrg: 'Bharat Sanchar Nigam Limited' },
].map((g) => ({ ...g, iso: 'IN', country: 'India' }));

const GLOBAL_GEOS = [
  { ip: '3.109.45.201', iso: 'US', country: 'United States', city: 'Ashburn', lat: 39.0438, lon: -77.4874, asn: 16509, asOrg: 'Amazon.com, Inc.' },
  { ip: '34.201.67.88', iso: 'US', country: 'United States', city: 'Seattle', lat: 47.6062, lon: -122.3321, asn: 16509, asOrg: 'Amazon.com, Inc.' },
  { ip: '85.214.132.117', iso: 'DE', country: 'Germany', city: 'Frankfurt', lat: 50.1109, lon: 8.6821, asn: 24940, asOrg: 'Hetzner Online GmbH' },
  { ip: '176.9.44.201', iso: 'DE', country: 'Germany', city: 'Nuremberg', lat: 49.4521, lon: 11.0767, asn: 24940, asOrg: 'Hetzner Online GmbH' },
  { ip: '188.68.52.19', iso: 'NL', country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, asn: 60781, asOrg: 'LeaseWeb Netherlands B.V.' },
  { ip: '5.188.62.14', iso: 'RU', country: 'Russia', city: 'Moscow', lat: 55.7558, lon: 37.6173, asn: 49505, asOrg: 'Selectel Ltd.' },
  { ip: '223.71.167.42', iso: 'CN', country: 'China', city: 'Shanghai', lat: 31.2304, lon: 121.4737, asn: 4134, asOrg: 'Chinanet' },
  { ip: '177.32.65.9', iso: 'BR', country: 'Brazil', city: 'São Paulo', lat: -23.5505, lon: -46.6333, asn: 262589, asOrg: 'Locaweb Serviços de Internet S.A.' },
  { ip: '128.199.28.113', iso: 'SG', country: 'Singapore', city: 'Singapore', lat: 1.3521, lon: 103.8198, asn: 14061, asOrg: 'DigitalOcean, LLC' },
  { ip: '185.86.77.5', iso: 'GB', country: 'United Kingdom', city: 'London', lat: 51.5074, lon: -0.1278, asn: 20473, asOrg: 'The Constant Company, LLC' },
];

const pickGeo = () => (rand() < 0.65 ? pick(INDIA_GEOS) : pick(GLOBAL_GEOS));
const geoOf = (g) => ({
  country_iso_code: g.iso,
  country_name: g.country,
  city_name: g.city,
  location: { lat: g.lat, lon: g.lon },
});
const asOf = (g) => ({ number: g.asn, organization: { name: g.asOrg } });

// dedicated "attacker" IPs — documentation/TEST-NET ranges, fixed geo tuples
const BRUTE_IP = '203.0.113.66'; // TEST-NET-3
const BRUTE_GEO = { iso: 'RU', country: 'Russia', city: 'Moscow', lat: 55.7558, lon: 37.6173, asn: 48666, asOrg: 'DDoS-Guard Corp.' };
const bruteSource = () => ({ ip: BRUTE_IP, port: randInt(1024, 65535), geo: geoOf(BRUTE_GEO), as: asOf(BRUTE_GEO) });

const WAF_SPIKE_IP = '198.51.100.77'; // TEST-NET-2
const WAF_SPIKE_GEO = { iso: 'NL', country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, asn: 60781, asOrg: 'LeaseWeb Netherlands B.V.' };
const wafSpikeSource = () => ({ ip: WAF_SPIKE_IP, port: randInt(1024, 65535), geo: geoOf(WAF_SPIKE_GEO), as: asOf(WAF_SPIKE_GEO) });

// --- internal address space (no geo) ---
const INTERNAL_IPS = [];
for (let i = 0; i < 100; i++) INTERNAL_IPS.push(`10.20.${randInt(1, 60)}.${randInt(2, 250)}`);
const internalIp = () => pick(INTERNAL_IPS);
const internalSource = () => ({ ip: internalIp(), port: randInt(1024, 65535) });
const externalSource = () => {
  const g = pickGeo();
  return { ip: g.ip, port: randInt(1024, 65535), geo: geoOf(g), as: asOf(g) };
};
const externalIpOnly = () => pickGeo().ip;

// deterministic per-host internal server address (10.10.x.x), independent of the client pool
const hostIp = (host) => {
  let hash = 0;
  for (let i = 0; i < host.length; i++) hash = (hash * 31 + host.charCodeAt(i)) >>> 0;
  return `10.10.${10 + (hash % 40)}.${10 + (Math.floor(hash / 40) % 200)}`;
};

// --- the campus estate ---
const DOMAIN = 'iitb.ac.in';

// 25 app names; position 7 (1-based) = 'results' -> web-app-07, position 24 = 'grievance' -> web-app-24
const APP_NAMES = [
  'moodle', 'erp_portal', 'library', 'placements', 'webmail_ui', 'hostel_portal', 'results', 'exam',
  'admission', 'alumni', 'research', 'finance', 'hr', 'tenders', 'convocation', 'scholarships',
  'gymkhana', 'sports', 'ncc_nss', 'medical', 'transport', 'hostel_mess', 'guest_house', 'grievance',
  'phd_admissions',
];
const APP_DEPT = {
  moodle: 'cse', erp_portal: 'admin', library: 'library', placements: 'cse', webmail_ui: 'admin',
  hostel_portal: 'hostel', results: 'cse', exam: 'cse', admission: 'admin', alumni: 'admin',
  research: 'cse', finance: 'admin', hr: 'admin', tenders: 'admin', convocation: 'admin',
  scholarships: 'admin', gymkhana: 'hostel', sports: 'hostel', ncc_nss: 'hostel', medical: 'hostel',
  transport: 'admin', hostel_mess: 'hostel', guest_house: 'hostel', grievance: 'admin',
  phd_admissions: 'cse',
};
const appHost = (app) => `web-app-${String(APP_NAMES.indexOf(app) + 1).padStart(2, '0')}`;
const GRIEVANCE_APP = 'grievance';
const RESULTS_APP = 'results';
const REGULAR_APPS = APP_NAMES.filter((a) => a !== GRIEVANCE_APP);

const HOSTS_META = {};
for (let i = 1; i <= 10; i++) {
  HOSTS_META[`proxy-${String(i).padStart(2, '0')}`] = {
    dept: 'datacenter', program: 'squid', type: 'proxy', vendor: 'Squid Cache Project', product: 'Squid',
  };
}
for (const app of APP_NAMES) {
  HOSTS_META[appHost(app)] = {
    dept: APP_DEPT[app], program: `nginx_app_${app}`, type: 'web', vendor: 'nginx', product: 'NGINX',
  };
}
HOSTS_META['mail-01'] = { dept: 'admin', program: 'postfix', type: 'email', vendor: 'Postfix', product: 'Postfix MTA' };
HOSTS_META['webmail-01'] = { dept: 'admin', program: 'roundcube', type: 'webmail', vendor: 'Roundcube', product: 'Roundcube Webmail' };
HOSTS_META['waf-01'] = { dept: 'datacenter', program: 'modsecurity', type: 'waf', vendor: 'OWASP', product: 'ModSecurity' };
HOSTS_META['ids-01'] = { dept: 'datacenter', program: 'suricata', type: 'ids', vendor: 'OISF', product: 'Suricata' };
HOSTS_META['fw-01'] = { dept: 'datacenter', program: 'iptables', type: 'firewall', vendor: 'Netfilter', product: 'iptables' };
HOSTS_META['fw-02'] = { dept: 'datacenter', program: 'pf', type: 'firewall', vendor: 'pfSense', product: 'pfSense' };
HOSTS_META['auth-dc-01'] = { dept: 'datacenter', program: 'sshd', type: 'idp', vendor: 'OpenSSH', product: 'OpenSSH/PAM' };
HOSTS_META['auth-dc-02'] = { dept: 'datacenter', program: 'sshd', type: 'idp', vendor: 'OpenSSH', product: 'OpenSSH/PAM' };
HOSTS_META['erp-01'] = { dept: 'admin', program: 'erp_app', type: 'erp', vendor: 'TLSOC', product: 'Campus ERP' };
HOSTS_META['edr-mgr-01'] = { dept: 'datacenter', program: 'wazuh', type: 'edr', vendor: 'Wazuh', product: 'Wazuh EDR' };
HOSTS_META['dns-01'] = { dept: 'datacenter', program: 'unbound', type: 'dns', vendor: 'NLnet Labs', product: 'Unbound' };

const pickOrg = () => (rand() < 0.92 ? 'iitb' : 'iitb-hostel');
const pickEnv = (forced) => forced || (rand() < 0.1 ? 'staging' : 'production');
const estateFor = (host, forcedEnv) => {
  const meta = HOSTS_META[host];
  return {
    org: pickOrg(),
    dept: meta.dept,
    env: pickEnv(forcedEnv),
    server: `${host}.${DOMAIN}`,
    source_host: host,
    source_program: meta.program,
    type: meta.type,
    vendor: meta.vendor,
    product: meta.product,
  };
};

// --- shared pools ---
const USERS = [
  'a.verma', 'p.iyer', 's.kulkarni', 'r.nair', 'm.desai', 'k.rao', 'j.mathew', 'd.singh',
  'n.joshi', 't.banerjee', 'v.menon', 'r.pillai', 'a.shetty', 's.gupta', 'k.reddy', 'm.bose',
];
const ATTACK_USERS = ['root', 'admin', 'ubuntu', 'test', 'oracle', 'guest', 'administrator', 'postgres'];
const URL_PATHS = [
  '/', '/login', '/dashboard', '/api/v1/status', '/api/v1/reports', '/assets/app.js',
  '/assets/app.css', '/profile', '/admin', '/search', '/docs', '/api/v1/users', '/uploads/file.pdf',
  '/api/v1/notifications', '/settings',
];
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile Safari/604.1',
  'curl/8.5.0',
];

const docs = [];

// ============================================================================
// 1. nginx_app_* (25 apps, one nginx per web-app host) — ~45% of total
// ============================================================================
const NGINX_TOTAL = 18000;
const GRIEVANCE_COUNT = 55; // onboarding story — confined to the last 6h
const REGULAR_TOTAL = NGINX_TOTAL - GRIEVANCE_COUNT;
const appWeights = REGULAR_APPS.map(() => 0.6 + rand() * 0.8);
const appCountsArr = distributeInt(REGULAR_TOTAL, appWeights);
const appCounts = {};
REGULAR_APPS.forEach((a, i) => {
  appCounts[a] = appCountsArr[i];
});
appCounts[GRIEVANCE_APP] = GRIEVANCE_COUNT;

const nginxMethod = () => {
  const r = rand();
  if (r < 0.7) return 'GET';
  if (r < 0.92) return 'POST';
  if (r < 0.97) return 'HEAD';
  return 'PUT';
};
const nginxStatus = () => {
  const r = rand();
  if (r < 0.8) return 200;
  if (r < 0.86) return pick([301, 302]);
  if (r < 0.88) return 401;
  if (r < 0.93) return 404;
  if (r < 0.95) return 403;
  return pick([500, 502, 503]);
};

const nginxAppEvent = (tsMs, app, story) => {
  const host = appHost(app);
  const forcedEnv = app === GRIEVANCE_APP ? 'staging' : undefined;
  const method = nginxMethod();
  const status = nginxStatus();
  const src = rand() < 0.55 ? externalSource() : internalSource();
  const urlPath = pick(URL_PATHS);
  const user = rand() < 0.55 ? pick(USERS) : undefined;
  return makeDoc(tsMs, {
    message: `${src.ip} - ${user || '-'} "${method} ${urlPath} HTTP/1.1" ${status}`,
    event: {
      module: 'nginx', dataset: 'nginx.access', kind: 'event', category: ['web'],
      action: 'http_request', outcome: status < 400 ? 'success' : 'failure',
    },
    observer: estateFor(host, forcedEnv),
    source: src,
    destination: { ip: hostIp(host), port: 443 },
    ...(user ? { user: { name: user } } : {}),
    url: { domain: `${app}.${DOMAIN}`, path: urlPath, original: `https://${app}.${DOMAIN}${urlPath}` },
    http: { request: { method }, response: { status_code: status, body: { bytes: randInt(200, 60000) } } },
    user_agent: { original: pick(USER_AGENTS) },
    network: { protocol: 'http', transport: 'tcp' },
    tlsoc: { story: story || 'background' },
  });
};

for (const app of APP_NAMES) {
  const total = appCounts[app];
  if (app === GRIEVANCE_APP) {
    const windowStart = MARKER_MS - 6 * 3600000;
    for (let i = 0; i < total; i++) {
      const ms = windowStart + Math.floor((i / total) * (6 * 3600000 - 60000)) + randInt(0, 60000);
      docs.push(nginxAppEvent(ms, app, 'onboarding-grievance'));
    }
    continue;
  }
  const perDay = countsPerDay(total);
  for (let d = 0; d < DAYS; d++) {
    const dayStart = START_MS + d * DAY;
    for (let i = 0; i < perDay[d]; i++) {
      docs.push(nginxAppEvent(eventTimeInDay(dayStart, 0.75), app));
    }
  }
}

// ============================================================================
// 2. web-proxy (squid, proxy-01..10) — ~22% of total; proxy-07 goes SILENT the last 4 days
// ============================================================================
const PROXY_HOSTS = [];
for (let i = 1; i <= 10; i++) PROXY_HOSTS.push(`proxy-${String(i).padStart(2, '0')}`);
const PROXY_TOTAL = 8800;
const proxyPerDay = countsPerDay(PROXY_TOTAL);
const PROXY_DOMAINS = [
  ...APP_NAMES.map((a) => `${a}.${DOMAIN}`),
  'google.com', 'github.com', 'stackoverflow.com', 'youtube.com', 'nptel.ac.in', 'gmail.com', 'wikipedia.org', 'zoom.us',
];
const proxyStatus = () => {
  const r = rand();
  if (r < 0.72) return 200;
  if (r < 0.82) return 304;
  if (r < 0.87) return 407;
  if (r < 0.91) return 403;
  if (r < 0.96) return 404;
  return 502;
};

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  const pool = d >= DAYS - 4 ? PROXY_HOSTS.filter((h) => h !== 'proxy-07') : PROXY_HOSTS;
  for (let i = 0; i < proxyPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.7);
    const host = pick(pool);
    const src = rand() < 0.55 ? externalSource() : internalSource();
    const status = proxyStatus();
    const method = rand() < 0.92 ? 'GET' : pick(['POST', 'CONNECT']);
    const domain = pick(PROXY_DOMAINS);
    docs.push(
      makeDoc(ms, {
        message: `${src.ip} ${method} ${domain} ${status}`,
        event: {
          module: 'squid', dataset: 'squid.access', kind: 'event', category: ['web'],
          action: 'http_request', outcome: status < 400 ? 'success' : 'failure',
        },
        observer: estateFor(host),
        source: src,
        destination: { ip: hostIp(host), port: 3128 },
        url: { domain, path: '/', original: `https://${domain}/` },
        http: { request: { method }, response: { status_code: status, body: { bytes: randInt(200, 90000) } } },
        user_agent: { original: pick(USER_AGENTS) },
        network: { protocol: 'http', transport: 'tcp' },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// ============================================================================
// 3. firewall (fw-01/fw-02) — ~12% of total
// ============================================================================
const FW_HOSTS = ['fw-01', 'fw-02'];
const FW_TOTAL = 4800;
const fwPerDay = countsPerDay(FW_TOTAL);
const SERVICE_PORTS = [443, 80, 22, 25, 53, 3128];
const fwTransport = () => {
  const r = rand();
  if (r < 0.85) return 'tcp';
  if (r < 0.95) return 'udp';
  return 'icmp';
};

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < fwPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.55);
    const host = pick(FW_HOSTS);
    const inbound = rand() < 0.5;
    const port = pick(SERVICE_PORTS);
    let src;
    let dst;
    if (inbound) {
      src = rand() < 0.7 ? externalSource() : internalSource();
      dst = { ip: hostIp(pick(APP_NAMES.map(appHost))), port };
    } else {
      src = internalSource();
      dst = { ip: rand() < 0.6 ? externalIpOnly() : internalIp(), port: pick([443, 80, 53]) };
    }
    const action = rand() < 0.8 ? 'allow' : 'deny';
    docs.push(
      makeDoc(ms, {
        message: `${action} ${src.ip} -> ${dst.ip}:${dst.port}`,
        event: {
          module: 'firewall', dataset: 'firewall.log', kind: 'event', category: ['network'],
          action, type: [action === 'allow' ? 'allowed' : 'denied'], outcome: 'success',
        },
        observer: estateFor(host),
        source: { ...src, bytes: randInt(60, 15000) },
        destination: { ...dst, bytes: randInt(60, 150000) },
        network: { transport: fwTransport() },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// ============================================================================
// 4. postfix (mail-01) — ~6% of total
// ============================================================================
const POSTFIX_TOTAL = 2400;
const pfPerDay = countsPerDay(POSTFIX_TOTAL);
const EXTERNAL_MAIL_DOMAINS = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com'];
const mailAction = () => {
  const r = rand();
  if (r < 0.4) return 'queued';
  if (r < 0.75) return 'sent';
  if (r < 0.83) return 'bounced';
  if (r < 0.93) return 'rejected';
  return 'deferred';
};

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < pfPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.6);
    const action = mailAction();
    const outcome = action === 'sent' || action === 'queued' ? 'success' : 'failure';
    const inbound = rand() < 0.4;
    const fromDomain = inbound ? pick(EXTERNAL_MAIL_DOMAINS) : DOMAIN;
    const toDomain = inbound ? DOMAIN : pick(EXTERNAL_MAIL_DOMAINS);
    const fromAddr = `${pick(USERS)}@${fromDomain}`;
    const toAddr = `${pick(USERS)}@${toDomain}`;
    docs.push(
      makeDoc(ms, {
        message: `${action}: ${fromAddr} -> ${toAddr}`,
        event: { module: 'postfix', dataset: 'postfix.log', kind: 'event', category: ['email'], action, outcome },
        observer: estateFor('mail-01'),
        source: internalSource(),
        destination: { ip: hostIp('mail-01'), port: 25 },
        email: {
          from: { address: fromAddr },
          to: { address: toAddr },
          sender_domain: fromDomain,
          recipient_domain: toDomain,
          message_id: `<${randHex(16)}@mail-01.${DOMAIN}>`,
        },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// ============================================================================
// 5. sshd + pam auth (auth-dc-01/02, erp-01) — ~5% of total, incl. story 1
// ============================================================================
const BRUTE_FAILS = 420;
const AUTH_TOTAL = 2000;
const AUTH_BACKGROUND_TOTAL = AUTH_TOTAL - BRUTE_FAILS - 2;
const authPerDay = countsPerDay(AUTH_BACKGROUND_TOTAL);
const authHost = () => {
  const r = rand();
  if (r < 0.55) return 'auth-dc-01';
  if (r < 0.85) return 'auth-dc-02';
  return 'erp-01';
};
const FAIL_REASONS = ['Invalid user', 'Authentication failure', 'Too many authentication failures'];

const sshdEvent = (tsMs, host, src, user, outcome, story, reason) =>
  makeDoc(tsMs, {
    message: `${outcome === 'success' ? 'Accepted' : 'Failed'} password for ${user} from ${src.ip} port ${randInt(30000, 64000)} ssh2`,
    event: {
      module: 'system', dataset: 'system.auth', kind: 'event', category: ['authentication'], action: 'login',
      outcome, type: [outcome === 'success' ? 'start' : 'denied'], ...(reason ? { reason } : {}),
    },
    observer: estateFor(host),
    source: src,
    destination: { ip: hostIp(host), port: 22 },
    user: { name: user },
    network: { protocol: 'ssh', transport: 'tcp' },
    process: { name: 'sshd' },
    tlsoc: { story },
  });

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < authPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.5);
    const host = authHost();
    const outcome = rand() < 0.7 ? 'success' : 'failure';
    const external = outcome === 'failure' ? rand() < 0.6 : rand() < 0.15;
    const src = external ? externalSource() : internalSource();
    const user = outcome === 'failure' && rand() < 0.5 ? pick(ATTACK_USERS) : pick(USERS);
    const reason = outcome === 'failure' ? pick(FAIL_REASONS) : undefined;
    docs.push(sshdEvent(ms, host, src, user, outcome, 'background', reason));
  }
}

// --- story 1: brute-force burst at marker-2days ~02:10-02:24, then 2 successes for svc-ldap ---
const bruteDayStart = START_MS + (DAYS - 2) * DAY; // marker-2days
const bruteStart = bruteDayStart + 2 * 3600000 + 10 * 60000; // 02:10
const bruteEnd = bruteDayStart + 2 * 3600000 + 24 * 60000; // 02:24
for (let i = 0; i < BRUTE_FAILS; i++) {
  const ms = bruteStart + Math.floor((i / BRUTE_FAILS) * (bruteEnd - bruteStart)) + randInt(0, 1000);
  const user = pick(ATTACK_USERS);
  docs.push(sshdEvent(ms, 'auth-dc-01', bruteSource(), user, 'failure', 'brute-force', 'Authentication failure'));
}
docs.push(sshdEvent(bruteEnd + 30000, 'auth-dc-01', bruteSource(), 'svc-ldap', 'success', 'brute-force'));
docs.push(sshdEvent(bruteEnd + 45000, 'auth-dc-01', bruteSource(), 'svc-ldap', 'success', 'brute-force'));

// ============================================================================
// 6. suricata (ids-01) — ~3% of total, incl. story 2's spike
// ============================================================================
const SURICATA_SPIKE = 90;
const SURICATA_TOTAL = 1200;
const SURICATA_BG = SURICATA_TOTAL - SURICATA_SPIKE;
const suricataPerDay = countsPerDay(SURICATA_BG);
const SURICATA_SIGNATURES = [
  { name: 'ET SCAN Nmap Scripting Engine User-Agent Detected', sid: 2013504, threat: 'Reconnaissance' },
  { name: 'ET SCAN Suspicious inbound to mySQL port 3306', sid: 2010935, threat: 'Reconnaissance' },
  { name: 'ET POLICY curl User-Agent Outbound', sid: 2013028, threat: 'Policy Violation' },
  { name: 'ET WEB_SERVER PHP Possible Command Injection', sid: 2010938, threat: 'Web Application Attack' },
  { name: 'ET SCAN Potential SSH Scan', sid: 2001219, threat: 'Reconnaissance' },
  { name: 'ET INFO SSH session in progress on unusual port', sid: 2001978, threat: 'Policy Violation' },
  { name: 'ET EXPLOIT Possible ETERNALBLUE Probe', sid: 2024218, threat: 'Exploit' },
];

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < suricataPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.5);
    const sig = pick(SURICATA_SIGNATURES);
    const blocked = rand() < 0.4;
    const src = rand() < 0.7 ? externalSource() : internalSource();
    const proto = pick(['tcp', 'udp']);
    docs.push(
      makeDoc(ms, {
        message: `[**] ${sig.name} [**]`,
        event: {
          module: 'suricata', dataset: 'suricata.alert', kind: 'alert',
          category: ['network', 'intrusion_detection'], action: blocked ? 'blocked' : 'allowed', severity: randInt(2, 4),
        },
        observer: estateFor('ids-01'),
        source: src,
        destination: { ip: hostIp(pick(['web-app-01', 'auth-dc-01', 'fw-01'])), port: pick([22, 80, 443, 3389]) },
        network: { protocol: proto, transport: proto },
        rule: { id: String(sig.sid), name: sig.name },
        threat: { name: sig.threat },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// --- story 2 (part): suricata SQLi burst against nginx_app_results, marker-5days 14:00-14:40 ---
const spikeDayStart = START_MS + (DAYS - 5) * DAY; // marker-5days
const spikeStart = spikeDayStart + 14 * 3600000; // 14:00
const spikeEnd = spikeStart + 40 * 60000; // 14:40
const SURICATA_SPIKE_SIGNATURES = [
  { name: 'ET WEB_SERVER SQL Injection Attempt', sid: 2016360 },
  { name: 'ET WEB_SERVER Possible SQL Injection UNION SELECT', sid: 2006446 },
];
for (let i = 0; i < SURICATA_SPIKE; i++) {
  const ms = spikeStart + Math.floor((i / SURICATA_SPIKE) * (spikeEnd - spikeStart)) + randInt(0, 3000);
  const sig = pick(SURICATA_SPIKE_SIGNATURES);
  docs.push(
    makeDoc(ms, {
      message: `[**] ${sig.name} [**]`,
      event: {
        module: 'suricata', dataset: 'suricata.alert', kind: 'alert',
        category: ['network', 'intrusion_detection'], action: 'blocked', severity: randInt(3, 4),
      },
      observer: estateFor('ids-01'),
      source: wafSpikeSource(),
      destination: { ip: hostIp(appHost(RESULTS_APP)), port: 443 },
      network: { protocol: 'tcp', transport: 'tcp' },
      rule: { id: String(sig.sid), name: sig.name },
      threat: { name: 'Web Application Attack' },
      tlsoc: { story: 'waf-ids-spike' },
    })
  );
}

// ============================================================================
// 7. dns (unbound, dns-01) — ~2.5% of total
// ============================================================================
const DNS_TOTAL = 1000;
const dnsPerDay = countsPerDay(DNS_TOTAL);
const DNS_DOMAINS = [
  ...APP_NAMES.map((a) => `${a}.${DOMAIN}`),
  'google.com', 'github.com', 'gmail.com', 'outlook.com', 'npm.im', 'ubuntu.com', 'wikipedia.org',
];
const dnsType = () => {
  const r = rand();
  if (r < 0.6) return 'A';
  if (r < 0.75) return 'AAAA';
  if (r < 0.85) return 'MX';
  if (r < 0.93) return 'CNAME';
  return 'TXT';
};

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < dnsPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.6);
    const qname = pick(DNS_DOMAINS);
    const rcode = rand() < 0.92 ? 'NOERROR' : pick(['NXDOMAIN', 'SERVFAIL']);
    docs.push(
      makeDoc(ms, {
        message: `query: ${qname}`,
        event: {
          module: 'unbound', dataset: 'dns.log', kind: 'event', category: ['network'],
          action: 'query', outcome: rcode === 'NOERROR' ? 'success' : 'failure',
        },
        observer: estateFor('dns-01'),
        source: internalSource(),
        network: { protocol: 'dns', transport: 'udp' },
        dns: { question: { name: qname, type: dnsType() }, response_code: rcode },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// ============================================================================
// 8. roundcube (webmail-01) — ~2% of total
// ============================================================================
const ROUNDCUBE_TOTAL = 800;
const rcPerDay = countsPerDay(ROUNDCUBE_TOTAL);

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < rcPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.75);
    const outcome = rand() < 0.88 ? 'success' : 'failure';
    const user = `${pick(USERS)}@${DOMAIN}`;
    const src = rand() < 0.65 ? externalSource() : internalSource();
    docs.push(
      makeDoc(ms, {
        message: `${outcome === 'success' ? 'Login' : 'Failed login'} for ${user} from ${src.ip}`,
        event: {
          module: 'roundcube', dataset: 'roundcube.userlogins', kind: 'event',
          category: ['authentication'], action: 'user_login', outcome,
        },
        observer: estateFor('webmail-01'),
        source: src,
        destination: { ip: hostIp('webmail-01'), port: 443 },
        user: { name: user },
        url: { domain: `webmail.${DOMAIN}`, path: '/roundcube/?_task=login', original: `https://webmail.${DOMAIN}/roundcube/?_task=login` },
        http: { request: { method: 'POST' }, response: { status_code: outcome === 'success' ? 200 : 401 } },
        user_agent: { original: pick(USER_AGENTS) },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// ============================================================================
// 9. erp_app (erp-01) — ~1.5% of total
// ============================================================================
const ERP_TOTAL = 600;
const erpPerDay = countsPerDay(ERP_TOTAL);
const ERP_ACTIONS = ['invoice.create', 'po.approve', 'payroll.run', 'login'];
const ERP_MODULE_OF = { 'invoice.create': 'Finance', 'po.approve': 'Procurement', 'payroll.run': 'Payroll', login: 'Access' };
const ERP_PATH_OF = {
  'invoice.create': '/erp/finance/invoice/create', 'po.approve': '/erp/procurement/po/approve',
  'payroll.run': '/erp/payroll/run', login: '/erp/login',
};

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < erpPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.85);
    const action = pick(ERP_ACTIONS);
    const outcome = rand() < 0.92 ? 'success' : 'failure';
    const status = outcome === 'success' ? 200 : pick([400, 403, 500]);
    const user = pick(USERS);
    const erpPath = ERP_PATH_OF[action];
    docs.push(
      makeDoc(ms, {
        message: `${action} by ${user}: ${outcome}`,
        event: { module: 'erp_app', dataset: 'erp.transactions', kind: 'event', category: ['web'], action, outcome },
        observer: estateFor('erp-01'),
        source: internalSource(),
        destination: { ip: hostIp('erp-01'), port: 443 },
        user: { name: user },
        url: { domain: `erp.${DOMAIN}`, path: erpPath, original: `https://erp.${DOMAIN}${erpPath}` },
        http: { request: { method: 'POST' }, response: { status_code: status } },
        erp:
          action === 'login'
            ? { module: ERP_MODULE_OF[action] }
            : {
                module: ERP_MODULE_OF[action],
                txn_id: `TXN-2026-${String(randInt(1, 999999)).padStart(6, '0')}`,
                record_id: `REC-${randInt(10000, 99999)}`,
                amount: Math.round(rand() * 500000) / 100,
              },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// ============================================================================
// 10. modsecurity / WAF (waf-01) — ~0.7% of total, incl. story 2's spike
// ============================================================================
const MODSEC_SPIKE = 160;
const MODSEC_TOTAL = 280;
const MODSEC_BG = MODSEC_TOTAL - MODSEC_SPIKE;
const modsecPerDay = countsPerDay(MODSEC_BG);
const MODSEC_RULES = [
  { id: '942100', name: 'SQL Injection Attack Detected via libinjection' },
  { id: '941100', name: 'XSS Attack Detected via libinjection' },
  { id: '930100', name: 'Path Traversal Attack' },
  { id: '913100', name: 'Found User-Agent associated with Security Scanner' },
];

for (let d = 0; d < DAYS; d++) {
  const dayStart = START_MS + d * DAY;
  for (let i = 0; i < modsecPerDay[d]; i++) {
    const ms = eventTimeInDay(dayStart, 0.55);
    const rule = pick(MODSEC_RULES);
    const app = pick(REGULAR_APPS);
    const urlPath = pick(URL_PATHS);
    docs.push(
      makeDoc(ms, {
        message: `ModSecurity: ${rule.name}`,
        event: {
          module: 'modsecurity', dataset: 'modsecurity.audit', kind: 'alert',
          category: ['web', 'intrusion_detection'], action: 'blocked', outcome: 'failure', severity: randInt(3, 5),
        },
        observer: estateFor('waf-01'),
        source: externalSource(),
        url: { domain: `${app}.${DOMAIN}`, path: urlPath, original: `https://${app}.${DOMAIN}${urlPath}` },
        http: { response: { status_code: 403 } },
        rule: { id: rule.id, name: rule.name, ruleset: 'OWASP CRS' },
        threat: { name: 'Web Application Attack' },
        tlsoc: { story: 'background' },
      })
    );
  }
}

// --- story 2 (part): ModSecurity SQLi burst against nginx_app_results, same window as suricata ---
const MODSEC_SPIKE_PATHS = ['/results/api/v1/marks', '/results/view', '/results/search'];
for (let i = 0; i < MODSEC_SPIKE; i++) {
  const ms = spikeStart + Math.floor((i / MODSEC_SPIKE) * (spikeEnd - spikeStart)) + randInt(0, 2000);
  const urlPath = pick(MODSEC_SPIKE_PATHS);
  docs.push(
    makeDoc(ms, {
      message: 'ModSecurity: SQL Injection Attack Detected via libinjection',
      event: {
        module: 'modsecurity', dataset: 'modsecurity.audit', kind: 'alert',
        category: ['web', 'intrusion_detection'], action: 'blocked', outcome: 'failure', severity: randInt(4, 5),
      },
      observer: estateFor('waf-01'),
      source: wafSpikeSource(),
      url: { domain: `${RESULTS_APP}.${DOMAIN}`, path: urlPath, original: `https://${RESULTS_APP}.${DOMAIN}${urlPath}` },
      http: { response: { status_code: 403 } },
      rule: { id: '942100', name: 'SQL Injection Attack Detected via libinjection', ruleset: 'OWASP CRS' },
      threat: { name: 'Web Application Attack' },
      tlsoc: { story: 'waf-ids-spike' },
    })
  );
}

// --- story 2 (part): nginx_app_results 5xx bump during the same spike window ---
const NGINX_SPIKE_BUMP = 50;
for (let i = 0; i < NGINX_SPIKE_BUMP; i++) {
  const ms = spikeStart + Math.floor((i / NGINX_SPIKE_BUMP) * (spikeEnd - spikeStart)) + randInt(0, 5000);
  const status = pick([500, 502, 503, 500, 500]);
  const urlPath = pick(['/results/view', '/results/api/v1/marks', '/results/download']);
  docs.push(
    makeDoc(ms, {
      message: `${WAF_SPIKE_IP} - - "GET ${urlPath} HTTP/1.1" ${status}`,
      event: { module: 'nginx', dataset: 'nginx.access', kind: 'event', category: ['web'], action: 'http_request', outcome: 'failure' },
      observer: estateFor(appHost(RESULTS_APP)),
      source: wafSpikeSource(),
      destination: { ip: hostIp(appHost(RESULTS_APP)), port: 443 },
      url: { domain: `${RESULTS_APP}.${DOMAIN}`, path: urlPath, original: `https://${RESULTS_APP}.${DOMAIN}${urlPath}` },
      http: { request: { method: 'GET' }, response: { status_code: status, body: { bytes: randInt(100, 2000) } } },
      user_agent: { original: pick(USER_AGENTS) },
      network: { protocol: 'http', transport: 'tcp' },
      tlsoc: { story: 'waf-ids-spike' },
    })
  );
}

// ============================================================================
// 11. wazuh / EDR (edr-mgr-01) — ~0.3% of total; story 4 onboarding + story 1's correlated alert
// ============================================================================
const WAZUH_TOTAL = 120;
const WAZUH_TRICKLE = WAZUH_TOTAL - 1; // the 1 is the brute-force-correlated alert below
const WAZUH_ONBOARD_START = MARKER_MS - 18 * 3600000; // marker-18h
const WAZUH_RULES = [
  { id: '5710', name: 'sshd: Multiple authentication failures', severity: [4, 5] },
  { id: '100002', name: 'Suspicious process execution detected', severity: [3, 4] },
  { id: '100010', name: 'File integrity monitoring: unexpected change', severity: [3, 4] },
  { id: '100020', name: 'Outbound connection to known-bad reputation IP', severity: [4, 5] },
  { id: '100030', name: 'Malware signature match: generic trojan dropper', severity: [4, 5] },
];
const MONITORED_HOSTS = ['web-app-07', 'auth-dc-01', 'auth-dc-02', 'erp-01', 'mail-01', 'proxy-03', 'dns-01'];

// NOTE (documented interpretation — the brief's stories 1 and 4 conflict: story 4 wants
// edr-mgr-01's FIRST-EVER event ~18h before the marker, but story 1 needs a correlated alert
// at marker-2days, ~46h earlier. Resolved as best-effort: the trickle (the onboarding "steady
// light cadence") is confined to the last 18h; the brute-force-correlated alert is kept as the
// one earlier exception, consistent with the brief's "best-effort given the date-shift" note.
for (let i = 0; i < WAZUH_TRICKLE; i++) {
  const ms = WAZUH_ONBOARD_START + Math.floor((i / WAZUH_TRICKLE) * (MARKER_MS - WAZUH_ONBOARD_START - 60000)) + randInt(0, 60000);
  const rule = pick(WAZUH_RULES);
  const host = pick(MONITORED_HOSTS);
  docs.push(
    makeDoc(ms, {
      message: `Wazuh alert: ${rule.name} on ${host}`,
      event: {
        module: 'wazuh', dataset: 'wazuh.alerts', kind: 'alert',
        category: ['intrusion_detection', 'malware'], action: 'threat_detected', severity: pick(rule.severity),
      },
      observer: estateFor('edr-mgr-01'),
      host: { name: host, risk_score: Math.round((30 + rand() * 60) * 10) / 10 },
      rule: { id: rule.id, name: rule.name },
      threat: { name: rule.name },
      user: { name: pick(USERS) },
      tlsoc: { story: 'onboarding-edr' },
    })
  );
}
docs.push(
  makeDoc(bruteEnd + 90000, {
    message: 'Wazuh alert: sshd: Multiple authentication failures on auth-dc-01',
    event: {
      module: 'wazuh', dataset: 'wazuh.alerts', kind: 'alert',
      category: ['intrusion_detection', 'malware'], action: 'threat_detected', severity: 5,
    },
    observer: estateFor('edr-mgr-01'),
    host: { name: 'auth-dc-01', risk_score: 92.5 },
    rule: { id: '5710', name: 'sshd: Multiple authentication failures' },
    threat: { name: 'Brute Force Attack' },
    user: { name: 'root' },
    tlsoc: { story: 'brute-force' },
  })
);

// --- sort by time, serialize NDJSON, gzip ---
docs.sort((a, b) => a['@timestamp'].localeCompare(b['@timestamp']));
const ndjson = docs.map((d) => JSON.stringify(d)).join('\n') + '\n';
const out = path.join(__dirname, 'tlsoc_security_logs.json.gz');
fs.writeFileSync(out, zlib.gzipSync(Buffer.from(ndjson), { level: 9 }));

console.log(`wrote ${docs.length} docs (${ndjson.length} bytes raw) -> ${out} (${fs.statSync(out).size} bytes gz)`);
console.log(`brute-force docs: ${docs.filter((d) => d.tlsoc.story === 'brute-force').length}`);
console.log(`waf-ids-spike docs: ${docs.filter((d) => d.tlsoc.story === 'waf-ids-spike').length}`);
console.log(`onboarding-edr docs: ${docs.filter((d) => d.tlsoc.story === 'onboarding-edr').length}`);
console.log(`onboarding-grievance docs: ${docs.filter((d) => d.tlsoc.story === 'onboarding-grievance').length}`);
const distinctPrograms = new Set(docs.map((d) => d.observer.source_program));
const distinctHosts = new Set(docs.map((d) => d.observer.source_host));
console.log(`distinct observer.source_program: ${distinctPrograms.size}`);
console.log(`distinct observer.source_host: ${distinctHosts.size}`);
console.log(`event.ingested > @timestamp on all docs: ${docs.every((d) => d.event.ingested >= d['@timestamp'])}`);
