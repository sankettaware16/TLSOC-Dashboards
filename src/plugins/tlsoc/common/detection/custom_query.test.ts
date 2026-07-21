/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  CustomQueryRuleDefinition,
  assertValidCustomQueryRule,
  compileCustomQueryText,
  compileCustomQueryToMonitor,
} from './custom_query';
import { compileToDocLevelMonitor } from './monitor';

const luceneRule = (
  overrides: Partial<CustomQueryRuleDefinition> = {}
): CustomQueryRuleDefinition => ({
  name: 'Suspicious admin probe',
  severity: 'high',
  index: 'fosstlsoc-logs-*',
  language: 'lucene',
  queryText: 'url.path:*admin* AND NOT http.response.status_code:200',
  ...overrides,
});

describe('compileCustomQueryToMonitor — Lucene passthrough golden (handcrafted expected JSON)', () => {
  it('compiles the full doc-level monitor, byte-pinned', () => {
    const rule = luceneRule({
      description: 'Any request probing an admin path that did not return 200.',
    });
    expect(compileCustomQueryToMonitor(rule)).toEqual({
      type: 'monitor',
      name: 'Suspicious admin probe',
      monitor_type: 'doc_level_monitor',
      enabled: true,
      schedule: { period: { interval: 1, unit: 'MINUTES' } },
      inputs: [
        {
          doc_level_input: {
            description: 'Any request probing an admin path that did not return 200.',
            indices: ['fosstlsoc-logs-*'],
            queries: [
              {
                id: 'suspicious_admin_probe',
                name: 'suspicious_admin_probe',
                query: 'url.path:*admin* AND NOT http.response.status_code:200',
                tags: ['tlsoc', 'high'],
              },
            ],
          },
        },
      ],
      triggers: [
        {
          document_level_trigger: {
            name: 'Suspicious admin probe matched',
            severity: '2',
            condition: {
              script: { source: 'query[name=suspicious_admin_probe]', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('the Lucene text is a passthrough — full Lucene syntax survives verbatim (trimmed only)', () => {
    const query =
      'status:[400 TO 499] AND (src_ip:"10.0.0.66" OR ua:*sqlmap*) AND NOT url:/.*health.*/';
    const m = compileCustomQueryToMonitor(luceneRule({ queryText: `  ${query}  ` }));
    expect(m.inputs[0].doc_level_input.queries[0].query).toBe(query);
  });

  it('missing description compiles to the empty string (the monitor.ts twin default)', () => {
    const m = compileCustomQueryToMonitor(luceneRule());
    expect(m.inputs[0].doc_level_input.description).toBe('');
  });

  it('runEvery drives the schedule verbatim; absent = the legacy 1-minute default', () => {
    expect(
      compileCustomQueryToMonitor(luceneRule({ runEvery: { value: 5, unit: 'MINUTES' } })).schedule
    ).toEqual({ period: { interval: 5, unit: 'MINUTES' } });
    expect(compileCustomQueryToMonitor(luceneRule()).schedule).toEqual({
      period: { interval: 1, unit: 'MINUTES' },
    });
  });

  it('severity maps to the monitor trigger severity and the query tag, for all four levels', () => {
    const expected: Array<[CustomQueryRuleDefinition['severity'], string]> = [
      ['critical', '1'],
      ['high', '2'],
      ['medium', '3'],
      ['low', '4'],
    ];
    for (const [severity, monitorSeverity] of expected) {
      const m = compileCustomQueryToMonitor(luceneRule({ severity }));
      expect(m.triggers[0].document_level_trigger.severity).toBe(monitorSeverity);
      expect(m.inputs[0].doc_level_input.queries[0].tags).toEqual(['tlsoc', severity]);
    }
  });
});

describe('compileCustomQueryToMonitor — kuery (DQL) translation golden', () => {
  it('compiles the translated query into the same monitor envelope, byte-pinned', () => {
    const rule: CustomQueryRuleDefinition = {
      name: 'Scanner fingerprint (DQL)',
      description: 'sqlmap UA from the flagged source.',
      severity: 'critical',
      index: 'fosstlsoc-logs-moodle-*',
      language: 'kuery',
      queryText: 'source.ip:"10.0.0.66" and user_agent.original:*sqlmap*',
      runEvery: { value: 5, unit: 'MINUTES' },
    };
    expect(compileCustomQueryToMonitor(rule)).toEqual({
      type: 'monitor',
      name: 'Scanner fingerprint (DQL)',
      monitor_type: 'doc_level_monitor',
      enabled: true,
      schedule: { period: { interval: 5, unit: 'MINUTES' } },
      inputs: [
        {
          doc_level_input: {
            description: 'sqlmap UA from the flagged source.',
            indices: ['fosstlsoc-logs-moodle-*'],
            queries: [
              {
                id: 'scanner_fingerprint_dql',
                name: 'scanner_fingerprint_dql',
                query: '(source.ip:"10.0.0.66") AND (user_agent.original:*sqlmap*)',
                tags: ['tlsoc', 'critical'],
              },
            ],
          },
        },
      ],
      triggers: [
        {
          document_level_trigger: {
            name: 'Scanner fingerprint (DQL) matched',
            severity: '1',
            condition: {
              script: { source: 'query[name=scanner_fingerprint_dql]', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('DQL ranges + exists translate inside the compile path too', () => {
    const m = compileCustomQueryToMonitor(
      luceneRule({
        language: 'kuery',
        queryText: 'http.response.status_code >= 400 and user.name:*',
      })
    );
    expect(m.inputs[0].doc_level_input.queries[0].query).toBe(
      '(http.response.status_code:>=400) AND (_exists_:user.name)'
    );
  });

  it('compile throws the translator rejection message VERBATIM (nested)', () => {
    const rule = luceneRule({ language: 'kuery', queryText: 'user:{ first:"bob" }' });
    expect(() => compileCustomQueryToMonitor(rule)).toThrow(
      'nested query "user:{ … }": nested field groups have no Lucene (doc-level) equivalent. ' +
        'Full DQL, including nested queries, is available in threshold rules.'
    );
  });

  it('compile throws the translator rejection message VERBATIM (field-less term)', () => {
    const rule = luceneRule({ language: 'kuery', queryText: 'sqlmap' });
    expect(() => compileCustomQueryToMonitor(rule)).toThrow(
      'field-less term "sqlmap": a bare term searches every field (multi_match), which has no ' +
        'faithful Lucene twin — qualify it with a field, e.g. some.field:sqlmap. ' +
        'Full DQL is available in threshold rules.'
    );
  });

  it('compile surfaces a DQL syntax error by name', () => {
    const rule = luceneRule({ language: 'kuery', queryText: '(status:' });
    expect(() => compileCustomQueryToMonitor(rule)).toThrow(/^DQL syntax error: /);
  });
});

describe('emission-twin pin: compileCustomQueryToMonitor ≡ compileToDocLevelMonitor', () => {
  it('an equivalent rule produces a BYTE-IDENTICAL monitor through both compilers', () => {
    // The no-code twin: equals compiles to x:"y" — feed the custom-query compiler exactly that
    // Lucene and every other byte of the two monitors must match. This is the drift guard for
    // schedule default, queries[] shape, tags, trigger name and the query[name=slug] condition.
    const shared = {
      name: 'Twin rule — emission parity!',
      description: 'twin',
      severity: 'medium' as const,
      index: 'security-logs',
    };
    const viaStateless = compileToDocLevelMonitor({
      ...shared,
      group: { logic: 'AND', conditions: [{ field: 'x', operator: 'equals', value: 'y' }] },
    });
    const viaCustomQuery = compileCustomQueryToMonitor({
      ...shared,
      language: 'lucene',
      queryText: 'x:"y"',
    });
    expect(viaCustomQuery).toEqual(viaStateless);
  });

  it('slugify drives id, name and trigger condition identically to the twin', () => {
    const m = compileCustomQueryToMonitor(luceneRule({ name: '  Weird — name!! (v2)  ' }));
    const q = m.inputs[0].doc_level_input.queries[0];
    expect(q.id).toBe('weird_name_v2');
    expect(q.name).toBe('weird_name_v2');
    expect(m.triggers[0].document_level_trigger.condition.script.source).toBe(
      'query[name=weird_name_v2]'
    );
  });
});

describe('assertValidCustomQueryRule — reject-by-name validation', () => {
  it('accepts a valid lucene rule and a valid kuery rule', () => {
    expect(() => assertValidCustomQueryRule(luceneRule())).not.toThrow();
    expect(() =>
      assertValidCustomQueryRule(luceneRule({ language: 'kuery', queryText: 'a:1' }))
    ).not.toThrow();
  });

  it('empty name', () => {
    expect(() => assertValidCustomQueryRule(luceneRule({ name: '   ' }))).toThrow(
      'Custom-query rule must have a non-empty name.'
    );
  });

  it('empty index', () => {
    expect(() => assertValidCustomQueryRule(luceneRule({ index: '' }))).toThrow(
      'Custom-query rule "Suspicious admin probe" must specify a data view.'
    );
  });

  it('unknown language is named exactly', () => {
    expect(() =>
      assertValidCustomQueryRule(
        luceneRule({ language: 'sql' as CustomQueryRuleDefinition['language'] })
      )
    ).toThrow(
      'Custom-query rule "Suspicious admin probe" has an unsupported query language "sql". ' +
        'Supported: lucene, kuery.'
    );
  });

  it('empty query text', () => {
    expect(() => assertValidCustomQueryRule(luceneRule({ queryText: '  ' }))).toThrow(
      'Custom-query rule "Suspicious admin probe" must have a non-empty query.'
    );
  });

  it('unknown severity is named exactly (silent-failure guard)', () => {
    expect(() =>
      assertValidCustomQueryRule(
        luceneRule({ severity: 'urgent' as CustomQueryRuleDefinition['severity'] })
      )
    ).toThrow('Custom-query rule "Suspicious admin probe" has an unknown severity "urgent".');
  });

  it('non-positive / non-integer runEvery', () => {
    expect(() =>
      assertValidCustomQueryRule(luceneRule({ runEvery: { value: 0, unit: 'MINUTES' } }))
    ).toThrow('Custom-query rule "Suspicious admin probe" must have a positive run-every value.');
    expect(() =>
      assertValidCustomQueryRule(luceneRule({ runEvery: { value: 1.5, unit: 'MINUTES' } }))
    ).toThrow('Custom-query rule "Suspicious admin probe" must have a positive run-every value.');
  });

  it('a non-member runEvery unit is rejected BY NAME (W3 review fix-the-class)', () => {
    expect(() =>
      assertValidCustomQueryRule(luceneRule({ runEvery: { value: 5, unit: 'weeks' as never } }))
    ).toThrow(
      'Custom-query rule "Suspicious admin probe" has an unknown run-every unit "weeks". ' +
        'Supported: MINUTES, HOURS, DAYS.'
    );
  });

  it('a kuery rule outside the subset fails VALIDATION too (validate ⊇ compile throws)', () => {
    expect(() =>
      assertValidCustomQueryRule(luceneRule({ language: 'kuery', queryText: 'machine*:web' }))
    ).toThrow(/^wildcard field name "machine\*": /);
  });
});

describe('compileCustomQueryText', () => {
  it('lucene: trimmed passthrough', () => {
    expect(compileCustomQueryText(luceneRule({ queryText: '  a:1  ' }))).toBe('a:1');
  });

  it('kuery: the translation', () => {
    expect(
      compileCustomQueryText(luceneRule({ language: 'kuery', queryText: 'a:1 and b:*x*' }))
    ).toBe('(a:1) AND (b:*x*)');
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions + the suppression conversion (incl. the kuery
 * translation riding into the bucket filter).
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { compileSuppressedCustomQueryToBucketMonitor } = require('./custom_query');

describe('v1.2.3 D9 — custom-query exceptions (doc-level fragment)', () => {
  it('byte identity: exceptions absent and exceptions [] compile identically', () => {
    const withAbsent = compileCustomQueryToMonitor(luceneRule());
    const withEmpty = compileCustomQueryToMonitor(luceneRule({ exceptions: [] }));
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));
  });

  it('lucene rule: the executed query is wrapped and the fragment appended', () => {
    const monitor = compileCustomQueryToMonitor(
      luceneRule({ exceptions: [{ field: 'user.name', op: 'equals', values: ['svc-scan'] }] })
    );
    expect(monitor.inputs[0].doc_level_input.queries[0].query).toBe(
      '(url.path:*admin* AND NOT http.response.status_code:200) AND NOT (user.name:"svc-scan")'
    );
  });

  it('kuery rule: the TRANSLATION gets the fragment (never the raw DQL)', () => {
    const monitor = compileCustomQueryToMonitor({
      name: 'dql rule',
      severity: 'medium',
      index: 'logs-*',
      language: 'kuery',
      queryText: 'event.outcome:failure and event.category:authentication',
      exceptions: [{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }],
    });
    expect(monitor.inputs[0].doc_level_input.queries[0].query).toBe(
      '((event.outcome:failure) AND (event.category:authentication))' +
        ' AND NOT (source.ip:"10.0.0.0/8")'
    );
  });

  it('invalid exceptions are rejected at validate time, by name', () => {
    expect(() =>
      assertValidCustomQueryRule(
        luceneRule({ exceptions: [{ field: 's', op: 'cidr', values: ['not-a-cidr'] }] })
      )
    ).toThrow('"not-a-cidr" is not a valid CIDR');
  });
});

describe('v1.2.3 D9 — custom-query suppression (the doc→bucket conversion)', () => {
  const suppressed = (overrides: Partial<CustomQueryRuleDefinition> = {}) =>
    luceneRule({
      suppression: { groupBy: ['source.ip'], window: { value: 10, unit: 'MINUTES' } },
      ...overrides,
    });

  it('compileCustomQueryToMonitor REFUSES a suppressed rule by name', () => {
    expect(() => compileCustomQueryToMonitor(suppressed())).toThrow(
      'carries suppression — it compiles to a grouped (bucket-level) monitor via ' +
        'compileSuppressedCustomQueryToBucketMonitor'
    );
  });

  it('the converter refuses a rule WITHOUT suppression by name', () => {
    expect(() => compileSuppressedCustomQueryToBucketMonitor(luceneRule())).toThrow(
      'has no suppression — compile it through compileCustomQueryToMonitor'
    );
  });

  it('golden: the suppressed bucket monitor for a KUERY rule (translated Lucene as the filter)', () => {
    expect(
      compileSuppressedCustomQueryToBucketMonitor({
        name: 'Failed auth grouped',
        severity: 'high',
        index: 'fosstlsoc-logs-*',
        language: 'kuery',
        queryText: 'event.outcome:failure and event.category:authentication',
        suppression: { groupBy: ['source.ip'], window: { value: 10, unit: 'MINUTES' } },
      })
    ).toEqual({
      type: 'monitor',
      name: 'Failed auth grouped',
      monitor_type: 'bucket_level_monitor',
      enabled: true,
      schedule: { period: { interval: 10, unit: 'MINUTES' } },
      inputs: [
        {
          search: {
            indices: ['fosstlsoc-logs-*'],
            query: {
              size: 0,
              query: {
                bool: {
                  filter: [
                    {
                      range: {
                        '@timestamp': {
                          from: '{{period_end}}||-10m',
                          to: '{{period_end}}',
                          include_lower: true,
                          include_upper: true,
                          format: 'epoch_millis',
                        },
                      },
                    },
                    {
                      query_string: {
                        query: '(event.outcome:failure) AND (event.category:authentication)',
                        analyze_wildcard: true,
                      },
                    },
                  ],
                },
              },
              aggregations: {
                tlsoc_groups: {
                  composite: {
                    size: 100,
                    sources: [
                      { source_ip: { terms: { field: 'source.ip', missing_bucket: false } } },
                    ],
                  },
                },
              },
            },
          },
        },
      ],
      triggers: [
        {
          bucket_level_trigger: {
            name: 'Failed auth grouped matched',
            severity: '2',
            condition: {
              parent_bucket_path: 'tlsoc_groups',
              buckets_path: { _count: '_count' },
              script: { source: 'params._count >= 1', lang: 'painless' },
            },
          },
        },
      ],
    });
  });

  it('exceptions ride structured (must_not clause), NEVER folded into the Lucene filter', () => {
    const monitor = compileSuppressedCustomQueryToBucketMonitor(
      suppressed({ exceptions: [{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }] })
    );
    const filter = monitor.inputs[0].search.query.query.bool.filter as Array<
      Record<string, unknown>
    >;
    expect(filter[1]).toEqual({
      query_string: {
        query: 'url.path:*admin* AND NOT http.response.status_code:200',
        analyze_wildcard: true,
      },
    });
    expect(filter[2]).toEqual({
      bool: { must_not: [{ term: { 'source.ip': '10.0.0.0/8' } }] },
    });
  });

  it('a stale groupBy mirror is rejected by name', () => {
    expect(() =>
      compileSuppressedCustomQueryToBucketMonitor(suppressed({ groupBy: ['user.name'] }))
    ).toThrow('groupBy must mirror suppression.groupBy (source.ip)');
  });
});
