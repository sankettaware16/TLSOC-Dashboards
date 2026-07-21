/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The TLSOC starter pack (v1.2.3 D10) — 10 curated detection rules for the university SOC
 * estate, bundled as content, installed through the EXISTING import + create paths (no new
 * execution surface):
 *
 * - 8 rules are Sigma YAML (as TS template strings — YAML-as-TS is deliberate: no fs/packaging,
 *   the sample-data precedent without its file plumbing). Every one of them MUST stay inside the
 *   `parseSigmaImport` supported subset (common/detection/sigma_import.ts) FOREVER — that is
 *   pinned by the pack invariant test (starter_pack.test.ts), which runs the real importer with
 *   the real MITRE catalog over every bundled YAML. Edit a rule here → the test tells you
 *   immediately if it fell out of the subset.
 * - 2 rules are native TLSOC rules ({ mode, rule } — exactly the create route's SaveBody) for
 *   shapes Sigma event_count correlations cannot express (rejected-by-name honesty,
 *   research_r6 §C3): the D4 enhanced-threshold web-scanner rule and a D5 new-terms rule.
 *
 * CONTENT CONTRACT (research_r6 §C2/§C3, live-verified against the shipped sample dataset
 * `opensearch_dashboards_sample_data_tlsoc-security` — mappings in server/sample_data/
 * field_mappings.ts): every field referenced below is keyword/ip/long-mapped there, EXCEPT
 * `user_agent.original`, which is text + `.keyword` subfield — so the scanner rule's group-by
 * uses the RESOLVED name `user_agent.original.keyword` (a terms/composite agg on analyzed text
 * fails at monitor runtime with NO alert written — the silent-failure class, research_r2 §a).
 *
 * INDEX REBIND: every rule ships with {@link PACK_DEFAULT_INDEX} as its index hint
 * (`logsource: {product: …}` on the Sigma rules — the importer's index-hint shape). The install
 * modal (public/detection/starter_pack_modal.tsx) applies ONE user-chosen pattern to ALL rules
 * before POSTing — the bundled value is a hint, never a promise. Live `fosstlsoc-logs-*` pipeline
 * indices are dynamically mapped (text fields, several ECS fields absent — research_r6 §C2 trap);
 * the pack works as authored against the sample dataset or any properly-ECS-mapped pipeline.
 */

import type { DetectionMode } from './registry';
import type { NewTermsRuleDefinition } from './new_terms';
import type { ThresholdRuleDefinition } from './types';

/** The default index pattern the pack ships with (the distro's primary log pattern). */
export const PACK_DEFAULT_INDEX = 'fosstlsoc-logs-*';

/** A native pack rule: exactly the `{mode, rule}` the create route accepts (SaveBody). */
export type PackNativeRule =
  | { mode: 'stateful'; rule: ThresholdRuleDefinition }
  | { mode: 'new_terms'; rule: NewTermsRuleDefinition };

/** One bundled starter-pack rule. */
export interface PackRule {
  /** Stable pack-internal id (never shown as the rule name). */
  id: string;
  /** The rule name as it will appear in the Detections list. */
  title: string;
  kind: 'sigma' | 'native';
  /**
   * The mode this rule parses/installs as — pinned by the pack invariant test so a drifting
   * importer (or a drifting rule) is caught, never silently reinterpreted.
   */
  expectedMode: DetectionMode;
  /** Sigma YAML source (kind 'sigma' only). */
  yaml?: string;
  /** The native rule body (kind 'native' only). */
  native?: PackNativeRule;
  /** MITRE ATT&CK ids for the preview list (tactic and technique/sub-technique ids). */
  mitre: string[];
}

// ————————————————————————————————————————————————————————————————————————————————————————————
// The 8 Sigma rules (research_r6 §C3 #1–#8). Subset discipline per §C1: unmodified equals,
// list ⇒ is_one_of, `startswith`, `all of them` / `1 of sel*` over SINGLE-FIELD selections only;
// stateful = 2-doc event_count correlation (correlation doc first, exporter layout); `level`
// present on every rule; logsource `{product: <pattern>}` alone = the index hint.
// ————————————————————————————————————————————————————————————————————————————————————————————

const SSH_BRUTE_FORCE_YAML = `title: SSH brute force
status: experimental
description: More than 10 failed SSH authentications from one source IP within 5 minutes.
correlation:
  type: event_count
  rules:
    - ssh_brute_force_base
  group-by:
    - source.ip
  timespan: 5m
  condition:
    gte: 10
level: high
tags:
  - attack.credential_access
  - attack.t1110
---
title: SSH brute force (base)
name: ssh_brute_force_base
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    event.category: authentication
  sel1:
    event.outcome: failure
  sel2:
    observer.source_program: sshd
  condition: all of them
`;

const PRIVILEGED_SSH_LOGIN_YAML = `title: Successful privileged SSH login
status: experimental
description: A successful authentication as a privileged account (root/admin/administrator).
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    event.category: authentication
  sel1:
    event.outcome: success
  sel2:
    user.name:
      - root
      - admin
      - administrator
  condition: all of them
level: high
tags:
  - attack.initial_access
  - attack.t1078
`;

const SENSITIVE_PATH_PROBING_YAML = `title: Sensitive-path probing
status: experimental
description: A request for a well-known sensitive path (.git, .env, wp-admin, phpmyadmin).
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    url.path|startswith: '/.git'
  sel1:
    url.path|startswith: '/.env'
  sel2:
    url.path|startswith: '/wp-admin'
  sel3:
    url.path|startswith: '/phpmyadmin'
  condition: 1 of sel*
level: medium
tags:
  - attack.reconnaissance
  - attack.t1595.003
`;

const WAF_BLOCK_BURST_YAML = `title: WAF block burst per source
status: experimental
description: More than 20 ModSecurity blocks from one source IP within 15 minutes.
correlation:
  type: event_count
  rules:
    - waf_block_burst_base
  group-by:
    - source.ip
  timespan: 15m
  condition:
    gte: 20
level: high
tags:
  - attack.initial_access
  - attack.t1190
---
title: WAF block burst per source (base)
name: waf_block_burst_base
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    event.module: modsecurity
  sel1:
    event.action: blocked
  condition: all of them
`;

const IDS_THREAT_BURST_YAML = `title: IDS threat burst per source
status: experimental
description: More than 10 Suricata threat detections from one source IP within 15 minutes.
correlation:
  type: event_count
  rules:
    - ids_threat_burst_base
  group-by:
    - source.ip
  timespan: 15m
  condition:
    gte: 10
level: high
tags:
  - attack.initial_access
  - attack.t1190
---
title: IDS threat burst per source (base)
name: ids_threat_burst_base
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    event.module: suricata
  sel1:
    event.action: threat_detected
  condition: all of them
`;

const FIREWALL_DENY_SCAN_YAML = `title: Firewall deny scan
status: experimental
description: More than 100 firewall denies/blocks from one source IP within 5 minutes.
correlation:
  type: event_count
  rules:
    - firewall_deny_scan_base
  group-by:
    - source.ip
  timespan: 5m
  condition:
    gte: 100
level: medium
tags:
  - attack.discovery
  - attack.t1046
---
title: Firewall deny scan (base)
name: firewall_deny_scan_base
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    event.category: network
  sel1:
    event.action:
      - deny
      - blocked
  condition: all of them
`;

const DNS_NXDOMAIN_BURST_YAML = `title: DNS NXDOMAIN burst per host
status: experimental
description: More than 50 NXDOMAIN responses for one source IP within 10 minutes (DGA/C2 beaconing).
correlation:
  type: event_count
  rules:
    - dns_nxdomain_burst_base
  group-by:
    - source.ip
  timespan: 10m
  condition:
    gte: 50
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.004
---
title: DNS NXDOMAIN burst per host (base)
name: dns_nxdomain_burst_base
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    dns.response_code: NXDOMAIN
  condition: all of them
`;

const MAIL_BOUNCE_STORM_YAML = `title: Mail bounce storm per sender domain
status: experimental
description: More than 20 Postfix bounces for one sender domain within 30 minutes.
correlation:
  type: event_count
  rules:
    - mail_bounce_storm_base
  group-by:
    - email.sender_domain
  timespan: 30m
  condition:
    gte: 20
level: medium
tags:
  - attack.initial_access
  - attack.t1566
---
title: Mail bounce storm per sender domain (base)
name: mail_bounce_storm_base
logsource:
  product: ${PACK_DEFAULT_INDEX}
detection:
  sel0:
    event.module: postfix
  sel1:
    event.action: bounced
  condition: all of them
`;

// ————————————————————————————————————————————————————————————————————————————————————————————
// The 2 native rules (research_r6 §C3 #9–#10) — shapes Sigma event_count cannot express.
// ————————————————————————————————————————————————————————————————————————————————————————————

/**
 * #9 — the D4 enhanced-threshold acceptance rule (the "web scanner"): per (source.ip,
 * user-agent), ≥40 distinct url.path AND ≥50 error responses within 10 minutes.
 *
 * FIELD RESOLUTION (author-time, against the SAMPLE dataset's mappings — field_mappings.ts):
 * `user_agent.original` is text with a `.keyword` subfield → the group-by carries the RESOLVED
 * `user_agent.original.keyword`; `url.path` and `source.ip` are keyword/ip and stay verbatim.
 * The install modal rebinds `index` only — field names ship pre-resolved, so this rule needs an
 * index whose mapping matches the sample-data/ECS shape (the pack's documented contract).
 */
const WEB_SCANNER_RULE: ThresholdRuleDefinition = {
  name: 'Web scanner behavior (distinct paths + errors)',
  description:
    'One client (source IP + user agent) requested 40+ distinct URL paths AND received 50+ ' +
    'HTTP 4xx/5xx responses within 10 minutes — wordlist/vulnerability scanning behavior.',
  severity: 'high',
  index: PACK_DEFAULT_INDEX,
  filter: {
    logic: 'AND',
    conditions: [{ field: 'event.category', operator: 'equals', value: 'web' }],
  },
  groupBy: ['source.ip', 'user_agent.original.keyword'],
  window: { value: 10, unit: 'MINUTES' },
  // Superseded by advanced.having when `advanced` is present (the documented D4 contract in
  // types.ts) — kept minimal-and-valid for the shared validator.
  threshold: { operator: 'gte', value: 1 },
  advanced: {
    // Mirrors groupBy (which is authoritative at compile — ThresholdRuleDefinition.advanced).
    by: ['source.ip', 'user_agent.original.keyword'],
    metrics: [
      { alias: 'unique_paths', fn: 'cardinality', field: 'url.path' },
      {
        alias: 'error_hits',
        fn: 'count',
        filter: {
          logic: 'AND',
          conditions: [{ field: 'http.response.status_code', operator: 'gte', value: 400 }],
        },
      },
    ],
    having: {
      kind: 'and',
      operands: [
        { kind: 'cmp', alias: 'unique_paths', op: 'gte', value: 40 },
        { kind: 'cmp', alias: 'error_hits', op: 'gte', value: 50 },
      ],
    },
  },
  threat: [
    {
      framework: 'MITRE ATT&CK',
      tactic: {
        id: 'TA0043',
        name: 'Reconnaissance',
        reference: 'https://attack.mitre.org/tactics/TA0043/',
      },
      technique: [
        {
          id: 'T1595',
          name: 'Active Scanning',
          reference: 'https://attack.mitre.org/techniques/T1595/',
          subtechnique: [
            {
              id: 'T1595.003',
              name: 'Wordlist Scanning',
              reference: 'https://attack.mitre.org/techniques/T1595/003/',
            },
          ],
        },
      ],
    },
  ],
};

/**
 * #10 — a D5 new-terms rule. HONEST ADAPTATION of research_r6 §C3's "new country per user":
 * v1 new_terms tracks exactly ONE term field (combination-newness has no clean OpenSearch
 * primitive — the documented D5 decision), so this rule is "first-seen source country ACROSS
 * THE ESTATE", not per-user. The per-user variant is deliberately not shipped rather than
 * shipped with silently different semantics.
 *
 * `source.geo.country_iso_code` is keyword-mapped in the sample dataset (field_mappings.ts) —
 * already aggregatable, no .keyword resolution needed. Install note: creating this rule
 * bootstraps its seen-state server-side (the create route aggregates the 30-day history), so
 * the rebind pattern MUST match at least one existing index or the route refuses by name.
 */
const FIRST_SEEN_COUNTRY_RULE: NewTermsRuleDefinition = {
  name: 'First-seen source country',
  description:
    'A network source country ISO code appeared for the first time in 30 days. Adapted from ' +
    '"new country per user": TLSOC new-terms rules track one field in v1, so this fires on ' +
    'countries never seen estate-wide, not per user.',
  severity: 'medium',
  index: PACK_DEFAULT_INDEX,
  termField: 'source.geo.country_iso_code',
  historyWindow: { value: 30, unit: 'DAYS' },
  // Must be exactly [termField] — enforced by assertValidNewTermsRule (flyout key labels).
  groupBy: ['source.geo.country_iso_code'],
  threat: [
    {
      framework: 'MITRE ATT&CK',
      tactic: {
        id: 'TA0001',
        name: 'Initial Access',
        reference: 'https://attack.mitre.org/tactics/TA0001/',
      },
      technique: [
        {
          id: 'T1078',
          name: 'Valid Accounts',
          reference: 'https://attack.mitre.org/techniques/T1078/',
        },
      ],
    },
  ],
};

/** The starter pack, in install/preview order (research_r6 §C3 order). */
export const STARTER_PACK: readonly PackRule[] = [
  {
    id: 'ssh-brute-force',
    title: 'SSH brute force',
    kind: 'sigma',
    expectedMode: 'stateful',
    yaml: SSH_BRUTE_FORCE_YAML,
    mitre: ['TA0006', 'T1110'],
  },
  {
    id: 'privileged-ssh-login',
    title: 'Successful privileged SSH login',
    kind: 'sigma',
    expectedMode: 'stateless',
    yaml: PRIVILEGED_SSH_LOGIN_YAML,
    mitre: ['TA0001', 'T1078'],
  },
  {
    id: 'sensitive-path-probing',
    title: 'Sensitive-path probing',
    kind: 'sigma',
    expectedMode: 'stateless',
    yaml: SENSITIVE_PATH_PROBING_YAML,
    mitre: ['TA0043', 'T1595.003'],
  },
  {
    id: 'waf-block-burst',
    title: 'WAF block burst per source',
    kind: 'sigma',
    expectedMode: 'stateful',
    yaml: WAF_BLOCK_BURST_YAML,
    mitre: ['TA0001', 'T1190'],
  },
  {
    id: 'ids-threat-burst',
    title: 'IDS threat burst per source',
    kind: 'sigma',
    expectedMode: 'stateful',
    yaml: IDS_THREAT_BURST_YAML,
    mitre: ['TA0001', 'T1190'],
  },
  {
    id: 'firewall-deny-scan',
    title: 'Firewall deny scan',
    kind: 'sigma',
    expectedMode: 'stateful',
    yaml: FIREWALL_DENY_SCAN_YAML,
    mitre: ['TA0007', 'T1046'],
  },
  {
    id: 'dns-nxdomain-burst',
    title: 'DNS NXDOMAIN burst per host',
    kind: 'sigma',
    expectedMode: 'stateful',
    yaml: DNS_NXDOMAIN_BURST_YAML,
    mitre: ['TA0011', 'T1071.004'],
  },
  {
    id: 'mail-bounce-storm',
    title: 'Mail bounce storm per sender domain',
    kind: 'sigma',
    expectedMode: 'stateful',
    yaml: MAIL_BOUNCE_STORM_YAML,
    mitre: ['TA0001', 'T1566'],
  },
  {
    id: 'web-scanner',
    title: 'Web scanner behavior (distinct paths + errors)',
    kind: 'native',
    expectedMode: 'stateful',
    native: { mode: 'stateful', rule: WEB_SCANNER_RULE },
    mitre: ['TA0043', 'T1595.003'],
  },
  {
    id: 'first-seen-country',
    title: 'First-seen source country',
    kind: 'native',
    expectedMode: 'new_terms',
    native: { mode: 'new_terms', rule: FIRST_SEEN_COUNTRY_RULE },
    mitre: ['TA0001', 'T1078'],
  },
];
