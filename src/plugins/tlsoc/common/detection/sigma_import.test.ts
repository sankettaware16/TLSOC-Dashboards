/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { compileToSigma, compileToSigmaCorrelation, parseSigmaImport } from './index';
import { MitreCatalogLookup, SigmaImportFailure } from './sigma_import';
import { Condition, RuleDefinition, ThresholdRuleDefinition } from './types';

/** Small inline catalog covering only the tactics/techniques the fixtures below use. */
const STUB_CATALOG: MitreCatalogLookup = {
  tactics: [
    { id: 'TA0006', name: 'Credential Access', shortname: 'credential-access' },
    { id: 'TA0002', name: 'Execution', shortname: 'execution' },
  ],
  techniques: [
    {
      id: 'T1110',
      name: 'Brute Force',
      tactics: ['credential-access'],
      sub: [{ id: 'T1110.001', name: 'Password Guessing' }],
    },
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactics: ['execution'], sub: [] },
  ],
};

const ruleWith = (
  condition: Condition,
  overrides: Partial<RuleDefinition> = {}
): RuleDefinition => ({
  name: 'r',
  severity: 'medium',
  index: 'fosstlsoc-logs-*',
  group: { logic: 'AND', conditions: [condition] },
  ...overrides,
});

function expectRejected(result: ReturnType<typeof parseSigmaImport>, construct: string) {
  expect(result.ok).toBe(false);
  const failure = result as SigmaImportFailure;
  expect(failure.errors.some((e) => e.construct === construct)).toBe(true);
}

// -------------------------------------------------------------------------------------------
// ROUND-TRIP STATELESS — every operator.
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — round-trip stateless, per operator', () => {
  const cases: Array<[string, Condition]> = [
    ['equals', { field: 'event.module', operator: 'equals', value: 'ssh' }],
    ['not_equals', { field: 'event.module', operator: 'not_equals', value: 'ssh' }],
    ['contains', { field: 'url.path', operator: 'contains', value: 'admin' }],
    ['not_contains', { field: 'url.path', operator: 'not_contains', value: 'health' }],
    ['starts_with', { field: 'url.path', operator: 'starts_with', value: '/admin' }],
    ['ends_with', { field: 'process.name', operator: 'ends_with', value: '.exe' }],
    ['is_one_of', { field: 'source.ip', operator: 'is_one_of', values: ['a', 'b'] }],
    ['is_not_one_of', { field: 'source.ip', operator: 'is_not_one_of', values: ['a', 'b'] }],
    ['exists', { field: 'user.name', operator: 'exists' }],
    ['not_exists', { field: 'user.name', operator: 'not_exists' }],
    ['gt', { field: 'http.response.status_code', operator: 'gt', value: 500 }],
    ['gte', { field: 'http.response.status_code', operator: 'gte', value: 500 }],
    ['lt', { field: 'x', operator: 'lt', value: 1 }],
    ['lte', { field: 'x', operator: 'lte', value: 1 }],
    ['matches_regex', { field: 'url.original', operator: 'matches_regex', value: '(?i)etc/passwd' }],
  ];

  it.each(cases)('%s round-trips losslessly', (_label, condition) => {
    const rule = ruleWith(condition);
    const parsed = parseSigmaImport(compileToSigma(rule));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.mode).toBe('stateless');
      expect(parsed.rule).toEqual(rule);
    }
  });

  it('a combined AND rule (multiple selections) round-trips in order', () => {
    const rule = ruleWith(
      { field: 'event.outcome', operator: 'equals', value: 'failure' },
      {
        group: {
          logic: 'AND',
          conditions: [
            { field: 'event.outcome', operator: 'equals', value: 'failure' },
            { field: 'url.path', operator: 'contains', value: 'admin' },
            { field: 'source.ip', operator: 'not_equals', value: '10.0.0.1' },
          ],
        },
      }
    );
    const parsed = parseSigmaImport(compileToSigma(rule));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.rule).toEqual(rule);
  });

  it('a combined OR rule round-trips', () => {
    const rule = ruleWith(
      { field: 'a', operator: 'equals', value: 'x' },
      {
        group: {
          logic: 'OR',
          conditions: [
            { field: 'a', operator: 'equals', value: 'x' },
            { field: 'b', operator: 'contains', value: 'y' },
          ],
        },
      }
    );
    const parsed = parseSigmaImport(compileToSigma(rule));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.rule).toEqual(rule);
  });
});

// -------------------------------------------------------------------------------------------
// ROUND-TRIP STATELESS — metadata.
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — round-trip stateless metadata', () => {
  it('threat (tactic + technique + subtechnique), falsePositives, references, author, date, id, description', () => {
    const rule: RuleDefinition = {
      id: 'abc-123',
      name: 'SSH Brute Force Detection',
      description: 'Detects repeated SSH auth failures from a single source.',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      group: { logic: 'AND', conditions: [{ field: 'event.module', operator: 'equals', value: 'ssh' }] },
      references: ['https://example.test/rule'],
      author: 'TLSOC',
      date: '2026/06/22',
      falsePositives: ['Scheduled maintenance window', 'Known scanner IP'],
      threat: [
        {
          framework: 'MITRE ATT&CK',
          tactic: {
            id: 'TA0006',
            name: 'Credential Access',
            reference: 'https://attack.mitre.org/tactics/TA0006/',
          },
          technique: [
            {
              id: 'T1110',
              name: 'Brute Force',
              reference: 'https://attack.mitre.org/techniques/T1110/',
              subtechnique: [
                {
                  id: 'T1110.001',
                  name: 'Password Guessing',
                  reference: 'https://attack.mitre.org/techniques/T1110/001/',
                },
              ],
            },
          ],
        },
      ],
    };
    const parsed = parseSigmaImport(compileToSigma(rule), { catalog: STUB_CATALOG });
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.rule).toEqual(rule);
  });

  it.each(['low', 'medium', 'high', 'critical'] as const)('severity %s round-trips', (severity) => {
    const rule = ruleWith({ field: 'a', operator: 'equals', value: 'b' }, { severity });
    const parsed = parseSigmaImport(compileToSigma(rule));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect((parsed.rule as RuleDefinition).severity).toBe(severity);
  });
});

// -------------------------------------------------------------------------------------------
// ROUND-TRIP STATEFUL — filter, groupBy, window, threshold, name, severity.
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — round-trip stateful', () => {
  function expectStatefulRoundTrip(rule: ThresholdRuleDefinition) {
    const parsed = parseSigmaImport(compileToSigmaCorrelation(rule));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.mode).toBe('stateful');
    const r = parsed.rule as ThresholdRuleDefinition;
    expect(r.name).toBe(rule.name);
    expect(r.severity).toBe(rule.severity);
    expect(r.filter).toEqual(rule.filter);
    expect(r.groupBy).toEqual(rule.groupBy);
    expect(r.window).toEqual(rule.window);
    expect(r.threshold).toEqual(rule.threshold);
  }

  it('single group-by, MINUTES window', () => {
    expectStatefulRoundTrip({
      id: 'corr-001',
      name: 'Brute force: over 10 failed SSH logins from one source IP in 5 minutes',
      description: 'A single source IP failing SSH authentication more than 10 times in 5 minutes.',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      filter: {
        logic: 'AND',
        conditions: [
          { field: 'event.outcome', operator: 'equals', value: 'failure' },
          { field: 'event.module', operator: 'equals', value: 'ssh' },
        ],
      },
      groupBy: ['source.ip'],
      window: { value: 5, unit: 'MINUTES' },
      threshold: { operator: 'gt', value: 10 },
    });
  });

  it('multi group-by, HOURS window', () => {
    expectStatefulRoundTrip({
      name: 'Same account hitting many distinct URLs in an hour',
      severity: 'medium',
      index: 'fosstlsoc-logs-*',
      filter: {
        logic: 'AND',
        conditions: [{ field: 'http.response.status_code', operator: 'gte', value: 400 }],
      },
      groupBy: ['user.name', 'url.path'],
      window: { value: 1, unit: 'HOURS' },
      threshold: { operator: 'gte', value: 3 },
    });
  });

  it('DAYS window, lte threshold, OR filter', () => {
    // NOTE: an OR-vs-AND group.logic only round-trips when there are 2+ conditions — with exactly
    // one condition the Sigma condition string is just "sel0" either way (buildConditionString has
    // no joiner to encode the logic), so a single-condition OR is not a meaningful round-trip case.
    expectStatefulRoundTrip({
      name: 'Sparse-but-persistent scan over multiple days',
      severity: 'low',
      index: 'fosstlsoc-logs-*',
      filter: {
        logic: 'OR',
        conditions: [
          { field: 'event.category', operator: 'equals', value: 'network' },
          { field: 'event.category', operator: 'equals', value: 'authentication' },
        ],
      },
      groupBy: ['source.ip'],
      window: { value: 3, unit: 'DAYS' },
      threshold: { operator: 'lte', value: 2 },
    });
  });
});

// -------------------------------------------------------------------------------------------
// Wildcards.
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — wildcard heuristics', () => {
  function parseSingleValue(value: string) {
    return parseSigmaImport(compileToSigma(ruleWith({ field: 'f', operator: 'equals', value })));
  }

  it('trailing "*" → starts_with', () => {
    const parsed = parseSingleValue('v*');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const cond = (parsed.rule as RuleDefinition).group.conditions[0];
      expect(cond).toEqual({ field: 'f', operator: 'starts_with', value: 'v' });
    }
  });

  it('leading "*" → ends_with', () => {
    const parsed = parseSingleValue('*v');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const cond = (parsed.rule as RuleDefinition).group.conditions[0];
      expect(cond).toEqual({ field: 'f', operator: 'ends_with', value: 'v' });
    }
  });

  it('leading+trailing "*" → contains, with a warning', () => {
    const parsed = parseSingleValue('*v*');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const cond = (parsed.rule as RuleDefinition).group.conditions[0];
      expect(cond).toEqual({ field: 'f', operator: 'contains', value: 'v' });
      expect(parsed.warnings.some((w) => w.includes('contains'))).toBe(true);
    }
  });

  it('interior "*" (e.g. "a*b") is rejected', () => {
    expectRejected(parseSingleValue('a*b'), 'wildcard');
  });

  it('an escaped "\\*" is a literal asterisk → equals', () => {
    const parsed = parseSingleValue('\\*lit');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const cond = (parsed.rule as RuleDefinition).group.conditions[0];
      expect(cond).toEqual({ field: 'f', operator: 'equals', value: '*lit' });
    }
  });

  it('an unescaped "?" is rejected', () => {
    expectRejected(parseSingleValue('a?b'), 'wildcard');
  });
});

// -------------------------------------------------------------------------------------------
// Rejects — each names the exact unsupported construct.
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — rejects unsupported constructs by name', () => {
  const baseHeader = `
title: Test rule
logsource:
  product: linux
level: medium
`;

  it('parenthesized conditions', () => {
    const yaml = `${baseHeader}
detection:
  sel1:
    a: one
  sel2:
    b: two
  condition: (sel1 and sel2)
`;
    expectRejected(parseSigmaImport(yaml), 'parentheses');
  });

  it('mixed and/or in one condition expression', () => {
    const yaml = `${baseHeader}
detection:
  sel1:
    a: one
  sel2:
    b: two
  sel3:
    c: three
  condition: sel1 and sel2 or sel3
`;
    expectRejected(parseSigmaImport(yaml), 'mixed-logic');
  });

  it('a list-of-maps (OR-of-AND) selection', () => {
    const yaml = `${baseHeader}
detection:
  selection:
    - a: one
    - b: two
  condition: selection
`;
    expectRejected(parseSigmaImport(yaml), 'or-of-ands');
  });

  it('a keywords list (field-less full-text) selection', () => {
    const yaml = `${baseHeader}
detection:
  selection:
    - foo
    - bar
  condition: selection
`;
    expectRejected(parseSigmaImport(yaml), 'keywords');
  });

  it('the cidr modifier', () => {
    const yaml = `${baseHeader}
detection:
  selection:
    source.ip|cidr: '10.0.0.0/8'
  condition: selection
`;
    expectRejected(parseSigmaImport(yaml), 'modifier');
  });

  it('chained modifiers', () => {
    const yaml = `${baseHeader}
detection:
  selection:
    a|contains|all: 'x'
  condition: selection
`;
    expectRejected(parseSigmaImport(yaml), 'modifier');
  });

  it('a null value', () => {
    const yaml = `${baseHeader}
detection:
  selection:
    a: null
  condition: selection
`;
    expectRejected(parseSigmaImport(yaml), 'null');
  });

  it('correlation type other than event_count ("value_count")', () => {
    const yaml = `
title: Corr
correlation:
  type: value_count
  rules: [base]
  group-by: [source.ip]
  timespan: 5m
  condition:
    gt: 1
level: medium
---
name: base
title: Base
detection:
  selection:
    a: b
  condition: selection
logsource:
  product: linux
level: medium
`;
    expectRejected(parseSigmaImport(yaml), 'correlation-type');
  });

  it('a correlation timespan in seconds', () => {
    const yaml = `
title: Corr
correlation:
  type: event_count
  rules: [base]
  group-by: [source.ip]
  timespan: 30s
  condition:
    gt: 1
level: medium
---
name: base
title: Base
detection:
  selection:
    a: b
  condition: selection
logsource:
  product: linux
level: medium
`;
    expectRejected(parseSigmaImport(yaml), 'timespan-seconds');
  });

  it('an unsupported correlation condition operator ({eq: 5})', () => {
    const yaml = `
title: Corr
correlation:
  type: event_count
  rules: [base]
  group-by: [source.ip]
  timespan: 5m
  condition:
    eq: 5
level: medium
---
name: base
title: Base
detection:
  selection:
    a: b
  condition: selection
logsource:
  product: linux
level: medium
`;
    expectRejected(parseSigmaImport(yaml), 'threshold-operator');
  });

  it('a two-key correlation condition range ({gt, lt})', () => {
    const yaml = `
title: Corr
correlation:
  type: event_count
  rules: [base]
  group-by: [source.ip]
  timespan: 5m
  condition:
    gt: 5
    lt: 10
level: medium
---
name: base
title: Base
detection:
  selection:
    a: b
  condition: selection
logsource:
  product: linux
level: medium
`;
    expectRejected(parseSigmaImport(yaml), 'threshold-operator');
  });

  it('more than 2 YAML documents', () => {
    const doc = `${baseHeader}
detection:
  selection:
    a: one
  condition: selection
`;
    const yaml = `${doc}---\n${doc}---\n${doc}`;
    expectRejected(parseSigmaImport(yaml), 'documents');
  });

  it('input exceeding the 1 MB import limit', () => {
    const huge = 'a'.repeat(1024 * 1024 + 10);
    expectRejected(parseSigmaImport(huge), 'input');
  });

  it('invalid YAML syntax', () => {
    const yaml = `title: [unterminated`;
    expectRejected(parseSigmaImport(yaml), 'yaml');
  });
});

// -------------------------------------------------------------------------------------------
// Warnings — visible, never silent.
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — warnings', () => {
  it('level "informational" clamps to severity "low" with a visible warning', () => {
    const yaml = `
title: Test rule
logsource:
  product: linux
level: informational
detection:
  selection:
    a: one
  condition: selection
`;
    const parsed = parseSigmaImport(yaml);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect((parsed.rule as RuleDefinition).severity).toBe('low');
      expect(parsed.warnings.some((w) => w.includes('informational'))).toBe(true);
    }
  });

  it('a missing title defaults the name and warns', () => {
    const yaml = `
logsource:
  product: linux
level: medium
detection:
  selection:
    a: one
  condition: selection
`;
    const parsed = parseSigmaImport(yaml);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect((parsed.rule as RuleDefinition).name).toBe('Untitled Sigma import');
      expect(parsed.warnings.some((w) => w.toLowerCase().includes('title'))).toBe(true);
    }
  });

  it('an unresolved tactic tag warns (no catalog given) but does not hard-reject', () => {
    const yaml = `
title: Test rule
logsource:
  product: linux
level: medium
detection:
  selection:
    a: one
  condition: selection
tags:
  - attack.credential_access
`;
    const parsed = parseSigmaImport(yaml);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect((parsed.rule as RuleDefinition).threat).toBeUndefined();
      expect(parsed.warnings.some((w) => w.includes('attack.credential_access'))).toBe(true);
    }
  });

  it('"1 of them" maps to OR over all selections', () => {
    const yaml = `
title: Test rule
logsource:
  product: linux
level: medium
detection:
  sel1:
    a: one
  sel2:
    b: two
  condition: 1 of them
`;
    const parsed = parseSigmaImport(yaml);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const group = (parsed.rule as RuleDefinition).group;
      expect(group.logic).toBe('OR');
      expect(group.conditions).toHaveLength(2);
    }
  });
});

// -------------------------------------------------------------------------------------------
// Hand-written "public-style" Sigma fixture (self-authored, spec-shaped — not a SigmaHQ rule).
// -------------------------------------------------------------------------------------------

describe('parseSigmaImport — a realistic hand-written sshd brute-force rule', () => {
  const sshdYaml = `
title: SSH Brute Force - Multiple Failed Logins
id: 3d4e5f6a-1234-5678-9abc-def012345678
status: experimental
description: Detects multiple failed SSH login attempts from a single source, indicating a possible brute-force attack.
author: TLSOC Detection Team
date: 2026/07/18
references:
  - https://attack.mitre.org/techniques/T1110/
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.module: sshd
    event.outcome: failure
  condition: selection
falsepositives:
  - Misconfigured automation retrying with the wrong credentials
level: high
tags:
  - attack.credential_access
  - attack.t1110
`;

  it('parses to a valid stateless rule with threat resolved via the stub catalog', () => {
    const parsed = parseSigmaImport(sshdYaml, { catalog: STUB_CATALOG });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.mode).toBe('stateless');
    const rule = parsed.rule as RuleDefinition;
    expect(rule.name).toBe('SSH Brute Force - Multiple Failed Logins');
    expect(rule.severity).toBe('high');
    expect(rule.logSource).toEqual({ product: 'linux', service: 'sshd' });
    expect(rule.group.logic).toBe('AND');
    expect(rule.group.conditions).toEqual(
      expect.arrayContaining([
        { field: 'event.module', operator: 'equals', value: 'sshd' },
        { field: 'event.outcome', operator: 'equals', value: 'failure' },
      ])
    );
    expect(rule.group.conditions).toHaveLength(2);
    expect(rule.falsePositives).toEqual(['Misconfigured automation retrying with the wrong credentials']);
    expect(rule.threat).toEqual([
      {
        framework: 'MITRE ATT&CK',
        tactic: {
          id: 'TA0006',
          name: 'Credential Access',
          reference: 'https://attack.mitre.org/tactics/TA0006/',
        },
        technique: [
          {
            id: 'T1110',
            name: 'Brute Force',
            reference: 'https://attack.mitre.org/techniques/T1110/',
          },
        ],
      },
    ]);
  });
});
