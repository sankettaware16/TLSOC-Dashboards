/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single source of truth for SIEM source-type classification. Used by:
 *  - the client + route to fold observer.source_program buckets into types (classify),
 *  - the route's events-over-time "by type" filters aggregation (TYPE_QUERY_STRING),
 *  - the source-type filter (which expands to the same query_string clauses).
 * Keeping the regexes and the query_string patterns in one file prevents the two from drifting.
 */

export type SourceType =
  | 'web-proxy'
  | 'web-app'
  | 'mail'
  | 'webmail'
  | 'waf'
  | 'ids'
  | 'firewall'
  | 'auth'
  | 'edr'
  | 'erp'
  | 'dns'
  | 'other';

/** All classified types in a stable display order (most-common first, alerts grouped). */
export const SOURCE_TYPES: SourceType[] = [
  'web-app',
  'web-proxy',
  'firewall',
  'auth',
  'mail',
  'webmail',
  'dns',
  'ids',
  'waf',
  'edr',
  'erp',
  'other',
];

export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  'web-proxy': 'Web proxy',
  'web-app': 'Web app (nginx/apache)',
  mail: 'Mail (postfix)',
  webmail: 'Webmail',
  waf: 'WAF',
  ids: 'IDS/IPS',
  firewall: 'Firewall',
  auth: 'Authentication',
  edr: 'EDR',
  erp: 'ERP',
  dns: 'DNS',
  other: 'Other',
};

/**
 * Ordered classification rules. ORDER MATTERS: webmail before mail (roundcube contains no "mail"
 * but horde/webmail must not fall to mail), edr's wazuh/ossec before auth's generic "security".
 */
const RULES: Array<[RegExp, SourceType]> = [
  [/squid|bluecoat|forcepoint|zscaler|swg|web-?proxy|proxy/i, 'web-proxy'],
  [/roundcube|horde|rainloop|webmail/i, 'webmail'],
  [/modsec|modsecurity|waf|naxsi/i, 'waf'],
  [/suricata|snort|zeek|\bbro\b|\bids\b|\bips\b/i, 'ids'],
  [/wazuh|ossec|osquery|sysmon|\bedr\b|crowdstrike|defender|elastic-agent/i, 'edr'],
  [/iptables|ufw|pfsense|opnsense|fortigate|firewall|\basa\b|palo|panos|fw[-_]|\bpf\b/i, 'firewall'],
  [/postfix|sendmail|exim|dovecot|smtp/i, 'mail'],
  [/sshd|sudo|\bpam\b|login|kerberos|winlogon|\bauth\b/i, 'auth'],
  [/sap|odoo|tally|peoplesoft|\berp/i, 'erp'],
  [/named|bind|unbound|dnsmasq|coredns|\bdns\b/i, 'dns'],
  [/nginx|apache|httpd|haproxy|tomcat|gunicorn|php-?fpm/i, 'web-app'],
];

/** Classify a log source (observer.source_program) into a SIEM source type. */
export function classifySource(program: string | null | undefined): SourceType {
  const p = (program ?? '').toLowerCase();
  for (const [re, type] of RULES) {
    if (re.test(p)) return type;
  }
  return 'other';
}

/**
 * query_string pattern per type, matched against observer.source_program. Used for the
 * events-over-time `filters` aggregation and the source-type filter expansion. Mirrors RULES.
 * 'other' has no pattern (it is the filters agg's other_bucket).
 */
export const TYPE_QUERY_STRING: Record<Exclude<SourceType, 'other'>, string> = {
  'web-proxy': 'squid* OR *proxy* OR bluecoat* OR forcepoint* OR zscaler*',
  webmail: 'roundcube* OR horde* OR rainloop* OR *webmail*',
  waf: 'modsec* OR modsecurity* OR waf* OR naxsi*',
  ids: 'suricata* OR snort* OR zeek* OR bro OR ids OR ips',
  edr: 'wazuh* OR ossec* OR osquery* OR sysmon* OR *edr* OR crowdstrike* OR defender*',
  firewall: 'iptables* OR ufw* OR pfsense* OR opnsense* OR fortigate* OR firewall* OR palo* OR fw* OR pf',
  mail: 'postfix* OR sendmail* OR exim* OR dovecot* OR smtp*',
  auth: 'sshd* OR sudo* OR pam* OR login* OR kerberos* OR auth*',
  erp: 'sap* OR odoo* OR tally* OR erp*',
  dns: 'named* OR bind* OR unbound* OR dnsmasq* OR coredns* OR dns*',
  'web-app': 'nginx* OR apache* OR httpd* OR haproxy* OR tomcat* OR gunicorn*',
};

/**
 * Fold raw program buckets into per-type buckets. Returns { type, events, sources } sorted by
 * events desc, plus the raw programs under 'other' so the UI can offer an "audit other" affordance.
 */
export function foldProgramsToTypes(
  programs: Array<{ program: string; events: number; endpoints?: number }>
): {
  byType: Array<{ type: SourceType; label: string; events: number; sources: number; endpoints: number }>;
  otherPrograms: string[];
} {
  const acc = new Map<SourceType, { events: number; sources: number; endpoints: number }>();
  const otherPrograms: string[] = [];
  for (const b of programs) {
    const t = classifySource(b.program);
    if (t === 'other') otherPrograms.push(b.program);
    const cur = acc.get(t) ?? { events: 0, sources: 0, endpoints: 0 };
    cur.events += b.events;
    cur.sources += 1;
    cur.endpoints += b.endpoints ?? 0;
    acc.set(t, cur);
  }
  const byType = Array.from(acc.entries())
    .map(([type, v]) => ({ type, label: SOURCE_TYPE_LABELS[type], ...v }))
    .sort((a, b) => b.events - a.events);
  return { byType, otherPrograms };
}
