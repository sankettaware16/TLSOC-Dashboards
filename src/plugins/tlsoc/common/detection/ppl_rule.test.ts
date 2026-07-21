/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { AggregationCompileInput } from './agg_types';
import { parsePpl, PplRuleAst } from './ppl_parse';
import {
  assertValidPplRule,
  likePatternToWildcard,
  lowerPplToCompileInput,
  makeFieldResolver,
  PplRuleDefinition,
  pplRuleToCompileInput,
  ResolveField,
} from './ppl_rule';

/**
 * Lowering goldens: PPL text → parsed AST → the FROZEN AggregationCompileInput shapes of
 * agg_types.ts, pinned verbatim per research_r4.md §3.4 (which reproduces the 3.7 Calcite
 * pushdown, explain-verified). If any of these change shape, the compiled monitor changes —
 * treat a diff here like a golden-test diff.
 */

// The scanner rule VERBATIM (R4 §5 case 1, thresholds 40/50).
const SCANNER_PPL =
  'source = fosstlsoc-logs-moodle-* | where http.response.status_code >= 400 | ' +
  'stats dc(url.path) as unique_paths, count() as errors by source.ip, user_agent.original | ' +
  'where unique_paths >= 40 and errors >= 50';

/** The moodle data view's text→keyword resolution (mirrors the live index mapping, R4 §7). */
const MOODLE_FIELD_MAP: Record<string, string> = {
  'url.path': 'url.path.keyword',
  'user_agent.original': 'user_agent.original.keyword',
};
const moodleResolver: ResolveField = (f) => MOODLE_FIELD_MAP[f] ?? f;

function parseAst(pplText: string): PplRuleAst {
  const parsed = parsePpl(pplText);
  if (!parsed.ok) {
    throw new Error(`test query failed to parse: ${JSON.stringify(parsed.errors)}`);
  }
  return parsed.rule;
}

function makeRule(pplText: string, overrides: Partial<PplRuleDefinition> = {}): PplRuleDefinition {
  const ast = parseAst(pplText);
  return {
    name: 'Test PPL rule',
    severity: 'high',
    index: ast.indices.join(','),
    pplText,
    window: { value: 5, unit: 'MINUTES' },
    groupBy: ast.by.map((f) => f.name),
    ...overrides,
  };
}

function lower(pplText: string, resolveField: ResolveField = (f) => f): AggregationCompileInput {
  return lowerPplToCompileInput(parseAst(pplText), makeRule(pplText), resolveField);
}

function firstClause(pplText: string, resolveField: ResolveField = (f) => f): unknown {
  const out = lower(pplText, resolveField);
  if (out.filter === null || out.filter.kind !== 'dsl') {
    throw new Error('expected a dsl filter');
  }
  return out.filter.clauses[0];
}

describe('lowerPplToCompileInput — the scanner-rule golden (R4 §5 case 1, RT)', () => {
  it('lowers the scanner rule verbatim to the pinned AggregationCompileInput JSON', () => {
    const rule = makeRule(SCANNER_PPL, {
      name: 'Scanner — many distinct error paths per source',
      severity: 'high',
    });
    const out = lowerPplToCompileInput(parseAst(SCANNER_PPL), rule, moodleResolver);
    expect(out).toEqual({
      name: 'Scanner — many distinct error paths per source',
      severity: 'high',
      index: 'fosstlsoc-logs-moodle-*',
      filter: {
        kind: 'dsl',
        clauses: [{ range: { 'http.response.status_code': { gte: 400 } } }],
      },
      spec: {
        by: ['source.ip', 'user_agent.original.keyword'],
        metrics: [{ alias: 'unique_paths', fn: 'cardinality', field: 'url.path.keyword' }],
        having: {
          kind: 'and',
          operands: [
            { kind: 'cmp', alias: 'unique_paths', op: 'gte', value: 40 },
            { kind: 'cmp', alias: '_count', op: 'gte', value: 50 },
          ],
        },
      },
      window: { value: 5, unit: 'MINUTES' },
    });
    // count() as errors is NOT a sub-agg: the trigger reads the bucket's own doc_count.
    expect(out.spec.metrics).toHaveLength(1);
    // runEvery is absent when the rule has none (the compiler falls back to window).
    expect('runEvery' in out).toBe(false);
  });

  it('carries runEvery through when the rule sets it', () => {
    const rule = makeRule(SCANNER_PPL, { runEvery: { value: 1, unit: 'MINUTES' } });
    const out = lowerPplToCompileInput(parseAst(SCANNER_PPL), rule, moodleResolver);
    expect(out.runEvery).toEqual({ value: 1, unit: 'MINUTES' });
  });
});

describe('lowerPplToCompileInput — where-clause DSL shapes (explain-verified, R4 §3.4)', () => {
  it("'=' compiles to a term on the RESOLVED field", () => {
    expect(firstClause("source=x | where f = 'v' | stats count() by g", moodleResolver)).toEqual({
      term: { f: 'v' },
    });
    expect(
      firstClause("source=x | where url.path = '/admin' | stats count() by g", moodleResolver)
    ).toEqual({ term: { 'url.path.keyword': '/admin' } });
  });

  it("'!=' carries the exists null-guard: RAW field in exists, RESOLVED in must_not term", () => {
    expect(
      firstClause("source=x | where url.path != '/x' | stats count() by g", moodleResolver)
    ).toEqual({
      bool: {
        must: [{ exists: { field: 'url.path' } }],
        must_not: [{ term: { 'url.path.keyword': '/x' } }],
      },
    });
  });

  it('ranges address the RAW field (numeric context — no keyword resolution)', () => {
    const resolveAll: ResolveField = (f) => `${f}.KW`;
    expect(firstClause('source=x | where n > 4 | stats count() by g', resolveAll)).toEqual({
      range: { n: { gt: 4 } },
    });
    expect(firstClause('source=x | where n >= 4 | stats count() by g')).toEqual({
      range: { n: { gte: 4 } },
    });
    expect(firstClause('source=x | where n < 4 | stats count() by g')).toEqual({
      range: { n: { lt: 4 } },
    });
    expect(firstClause('source=x | where n <= 4 | stats count() by g')).toEqual({
      range: { n: { lte: 4 } },
    });
  });

  it('like translates %→* and _→? into a case-insensitive wildcard on the resolved field', () => {
    expect(
      firstClause("source=x | where like(url.path, '%a_b%') | stats count() by g", moodleResolver)
    ).toEqual({
      wildcard: {
        'url.path.keyword': { wildcard: '*a?b*', case_insensitive: true },
      },
    });
  });

  it('in compiles to terms on the resolved field', () => {
    expect(
      firstClause("source=x | where url.path in ('/a', '/b') | stats count() by g", moodleResolver)
    ).toEqual({ terms: { 'url.path.keyword': ['/a', '/b'] } });
    expect(firstClause('source=x | where s in (403, 404) | stats count() by g')).toEqual({
      terms: { s: [403, 404] },
    });
  });

  it('not-of-a-leaf carries the exists null-guard around the negated leaf', () => {
    expect(
      firstClause(
        "source=x | where not like(url.path, '%login%') | stats count() by g",
        moodleResolver
      )
    ).toEqual({
      bool: {
        must: [{ exists: { field: 'url.path' } }],
        must_not: [
          {
            wildcard: {
              'url.path.keyword': { wildcard: '*login*', case_insensitive: true },
            },
          },
        ],
      },
    });
  });

  it('not-of-a-compound is a plain must_not (no synthetic guard)', () => {
    expect(firstClause('source=x | where not (a=1 or b=2) | stats count() by g')).toEqual({
      bool: {
        must_not: [
          {
            bool: {
              should: [{ term: { a: 1 } }, { term: { b: 2 } }],
              minimum_should_match: 1,
            },
          },
        ],
      },
    });
  });

  it('precedence tree: a=1 or b=2 and c=3 → should[term, filter[term, term]]', () => {
    expect(firstClause('source=x | where a=1 or b=2 and c=3 | stats count() by g')).toEqual({
      bool: {
        should: [
          { term: { a: 1 } },
          { bool: { filter: [{ term: { b: 2 } }, { term: { c: 3 } }] } },
        ],
        minimum_should_match: 1,
      },
    });
  });

  it('multiple wheres fold into MULTIPLE top-level filter clauses', () => {
    const out = lower('source=x | where a=1 | where b=2 | stats count() by g');
    expect(out.filter).toEqual({
      kind: 'dsl',
      clauses: [{ term: { a: 1 } }, { term: { b: 2 } }],
    });
  });

  it('a single top-level AND also flattens to multiple clauses', () => {
    const out = lower('source=x | where a=1 and b=2 | stats count() by g');
    expect(out.filter).toEqual({
      kind: 'dsl',
      clauses: [{ term: { a: 1 } }, { term: { b: 2 } }],
    });
  });

  it('boolean equality compiles to a term with the boolean value', () => {
    expect(firstClause('source=x | where flag = true | stats count() by g')).toEqual({
      term: { flag: true },
    });
  });

  it('no pre-stats where → filter is null (window-range-only rule)', () => {
    expect(lower('source=x | stats count() by g').filter).toBeNull();
  });
});

describe('lowerPplToCompileInput — metrics and having', () => {
  it('metric fns normalize: count(f)→value_count(raw), dc→cardinality(resolved), sum stays raw', () => {
    const out = lower(
      'source=x | stats count(url.path) as cnt, dc(url.path) as u, sum(bytes) as b by g',
      moodleResolver
    );
    expect(out.spec.metrics).toEqual([
      { alias: 'cnt', fn: 'value_count', field: 'url.path' },
      { alias: 'u', fn: 'cardinality', field: 'url.path.keyword' },
      { alias: 'b', fn: 'sum', field: 'bytes' },
    ]);
  });

  it('by fields resolve through resolveField, order preserved', () => {
    const out = lower(
      'source=x | stats count() by source.ip, user_agent.original',
      moodleResolver
    );
    expect(out.spec.by).toEqual(['source.ip', 'user_agent.original.keyword']);
  });

  it('unaliased metrics get deterministic positional aliases (m<i>)', () => {
    const out = lower('source=x | stats dc(f), sum(g) as total by h');
    expect(out.spec.metrics).toEqual([
      { alias: 'm0', fn: 'cardinality', field: 'f' },
      { alias: 'total', fn: 'sum', field: 'g' },
    ]);
  });

  it('synthetic aliases never collide with user aliases', () => {
    const out = lower('source=x | stats sum(a) as m1, dc(b) by c');
    expect(out.spec.metrics).toEqual([
      { alias: 'm1', fn: 'sum', field: 'a' },
      { alias: 'm1_', fn: 'cardinality', field: 'b' },
    ]);
  });

  it('a bare count() alias resolves to the reserved _count buckets_path key in having', () => {
    const out = lower('source=x | stats count() as errors by g | where errors >= 50');
    expect(out.spec.metrics).toEqual([]);
    expect(out.spec.having).toEqual({ kind: 'cmp', alias: '_count', op: 'gte', value: 50 });
  });

  it('having ops map: > >= < <= = != → gt gte lt lte eq neq', () => {
    const cases: Array<[string, string]> = [
      ['>', 'gt'],
      ['>=', 'gte'],
      ['<', 'lt'],
      ['<=', 'lte'],
      ['=', 'eq'],
      ['!=', 'neq'],
    ];
    cases.forEach(([pplOp, irOp]) => {
      const out = lower(`source=x | stats count() as n by g | where n ${pplOp} 3`);
      expect(out.spec.having).toEqual({ kind: 'cmp', alias: '_count', op: irOp, value: 3 });
    });
  });

  it('having and/or trees lower structurally with aliases mapped', () => {
    const out = lower(
      'source=x | stats count() as a, dc(f) as b by g | where (a >= 3 and b >= 5) or a >= 100'
    );
    expect(out.spec.having).toEqual({
      kind: 'or',
      operands: [
        {
          kind: 'and',
          operands: [
            { kind: 'cmp', alias: '_count', op: 'gte', value: 3 },
            { kind: 'cmp', alias: 'b', op: 'gte', value: 5 },
          ],
        },
        { kind: 'cmp', alias: '_count', op: 'gte', value: 100 },
      ],
    });
  });

  it('no having → default _count > 0 (fires per group with any match; parse warns)', () => {
    const out = lower('source=x | stats count() by g');
    expect(out.spec.having).toEqual({ kind: 'cmp', alias: '_count', op: 'gt', value: 0 });
  });

  it('an empty by is rejected at lowering (AggregationSpec.by may not be empty in v1.2.3)', () => {
    const pplText = 'source=x | stats count()';
    const rule = makeRule(pplText);
    expect(() => lowerPplToCompileInput(parseAst(pplText), rule, (f) => f)).toThrow(
      /group by at least one field/
    );
  });

  it('resolveField errors propagate (unknown-field compile errors name the field — case 25)', () => {
    const strictResolver: ResolveField = (f) => {
      if (f === 'nope') {
        throw new Error(`Unknown field "nope" — it is not in the data view.`);
      }
      return f;
    };
    expect(() =>
      lower('source=x | stats dc(nope) as n by g | where n > 1', strictResolver)
    ).toThrow(/Unknown field "nope"/);
    expect(() => lower('source=x | stats count() by nope', strictResolver)).toThrow(
      /Unknown field "nope"/
    );
  });
});

describe('assertValidPplRule', () => {
  const VALID = makeRule(SCANNER_PPL);

  it('accepts a valid rule', () => {
    expect(() => assertValidPplRule(VALID)).not.toThrow();
  });

  it('rejects a missing/empty name', () => {
    expect(() => assertValidPplRule({ ...VALID, name: '' })).toThrow(/non-empty name/);
  });

  it('rejects a missing index', () => {
    expect(() => assertValidPplRule({ ...VALID, index: '' })).toThrow(/data view/);
  });

  it('rejects an empty pplText', () => {
    expect(() => assertValidPplRule({ ...VALID, pplText: '  ' })).toThrow(/PPL query/);
  });

  it('rejects a pplText that fails to parse, naming the construct', () => {
    expect(() =>
      assertValidPplRule({ ...VALID, pplText: 'source=x | sort - c | stats count() by g' })
    ).toThrow(/sort/);
  });

  it('rejects an index that does not match the query source', () => {
    expect(() => assertValidPplRule({ ...VALID, index: 'other-*' })).toThrow(
      /must match the query's source/
    );
  });

  it('rejects a groupBy that does not mirror the by fields (the flyout-label invariant)', () => {
    expect(() => assertValidPplRule({ ...VALID, groupBy: ['source.ip'] })).toThrow(
      /groupBy must mirror/
    );
    expect(() =>
      assertValidPplRule({
        ...VALID,
        groupBy: ['user_agent.original', 'source.ip'], // wrong order
      })
    ).toThrow(/groupBy must mirror/);
  });

  it('rejects a rule whose query has no by (single-bucket rules are out in v1.2.3)', () => {
    const pplText = 'source=x | stats count()';
    expect(() =>
      assertValidPplRule({ ...VALID, pplText, index: 'x', groupBy: [] })
    ).toThrow(/group by at least one field/);
  });

  it('rejects a non-positive window', () => {
    expect(() =>
      assertValidPplRule({ ...VALID, window: { value: 0, unit: 'MINUTES' } })
    ).toThrow(/positive time window/);
  });

  it('rejects runEvery > window (the never-evaluated-gap invariant)', () => {
    expect(() =>
      assertValidPplRule({ ...VALID, runEvery: { value: 10, unit: 'MINUTES' } })
    ).toThrow(/run-every must not exceed/);
    expect(() =>
      assertValidPplRule({ ...VALID, runEvery: { value: 5, unit: 'MINUTES' } })
    ).not.toThrow();
  });

  it('rejects non-member window/runEvery units BY NAME (W3 review fix-the-class)', () => {
    expect(() =>
      assertValidPplRule({ ...VALID, window: { value: 5, unit: 'FORTNIGHTS' as never } })
    ).toThrow(/unknown time window unit "FORTNIGHTS"/);
    // Without the membership check, windowMinutes NaNs and the R ≤ T guard silently passes.
    expect(() =>
      assertValidPplRule({ ...VALID, runEvery: { value: 1, unit: 'weeks' as never } })
    ).toThrow(/unknown run-every unit "weeks"/);
  });
});

describe('pplRuleToCompileInput + makeFieldResolver (the registry compile path)', () => {
  it('parses + validates + lowers using the saved fieldMap', () => {
    const rule = makeRule(SCANNER_PPL, { fieldMap: MOODLE_FIELD_MAP });
    const out = pplRuleToCompileInput(rule);
    expect(out.spec.by).toEqual(['source.ip', 'user_agent.original.keyword']);
    expect(out.spec.metrics[0].field).toBe('url.path.keyword');
  });

  it('fields absent from fieldMap pass through unchanged', () => {
    const resolve = makeFieldResolver(makeRule(SCANNER_PPL, { fieldMap: { a: 'a.keyword' } }));
    expect(resolve('a')).toBe('a.keyword');
    expect(resolve('b')).toBe('b');
  });

  it('an explicit resolveField overrides the fieldMap', () => {
    const rule = makeRule('source=x | stats dc(f) as n by g | where n > 1', {
      fieldMap: { f: 'WRONG' },
    });
    const out = pplRuleToCompileInput(rule, (f) => `${f}.kw`);
    expect(out.spec.metrics[0].field).toBe('f.kw');
  });

  it('throws (never returns garbage) when the stored pplText is invalid', () => {
    const rule = makeRule(SCANNER_PPL);
    expect(() => pplRuleToCompileInput({ ...rule, pplText: 'source=x | head 5' })).toThrow(
      /head/
    );
  });
});

describe('likePatternToWildcard', () => {
  it('maps % to * and _ to ?, leaving everything else literal', () => {
    expect(likePatternToWildcard('%a_b%')).toBe('*a?b*');
    expect(likePatternToWildcard('/mod/%')).toBe('/mod/*');
    expect(likePatternToWildcard('plain')).toBe('plain');
    expect(likePatternToWildcard('')).toBe('');
    expect(likePatternToWildcard('a%b_c%d')).toBe('a*b?c*d');
  });
});

/*
 * ————————————————————————————————————————————————————————————————————————————————————————————
 * v1.2.3 W4b (D9) — ADDITIVE tests: exceptions on the PPL lowering.
 * ————————————————————————————————————————————————————————————————————————————————————————————
 */
describe('v1.2.3 D9 — PPL exceptions (bucket must_not clause)', () => {
  const d9Rule = (overrides: Partial<PplRuleDefinition> = {}): PplRuleDefinition => ({
    name: 'ppl exc',
    severity: 'medium',
    index: 'fosstlsoc-logs-*',
    pplText:
      "source = fosstlsoc-logs-* | where event.outcome = 'failure' | stats count() as c by source.ip | where c > 10",
    window: { value: 5, unit: 'MINUTES' },
    groupBy: ['source.ip'],
    ...overrides,
  });

  it('byte identity: exceptions absent and [] lower to the identical input', () => {
    const withAbsent = pplRuleToCompileInput(d9Rule());
    const withEmpty = pplRuleToCompileInput(d9Rule({ exceptions: [] }));
    expect(JSON.stringify(withEmpty)).toBe(JSON.stringify(withAbsent));
  });

  it('with exceptions: the clause is appended LAST after the where clauses', () => {
    const input = pplRuleToCompileInput(
      d9Rule({ exceptions: [{ field: 'user.name', op: 'equals', values: ['svc'] }] })
    );
    expect(input.filter).toEqual({
      kind: 'dsl',
      clauses: [
        { term: { 'event.outcome': 'failure' } },
        { bool: { must_not: [{ term: { 'user.name': 'svc' } }] } },
      ],
    });
  });

  it('a where-less rule with exceptions still gets a dsl filter (exceptions only)', () => {
    const input = pplRuleToCompileInput(
      d9Rule({
        pplText: 'source = fosstlsoc-logs-* | stats count() as c by source.ip | where c > 10',
        exceptions: [{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }],
      })
    );
    expect(input.filter).toEqual({
      kind: 'dsl',
      clauses: [{ bool: { must_not: [{ term: { 'source.ip': '10.0.0.0/8' } }] } }],
    });
  });

  it('exception fields are NOT fieldMap-resolved (documented — the editor offers raw fields)', () => {
    const input = pplRuleToCompileInput(
      d9Rule({
        fieldMap: { 'user.name': 'user.name.keyword' },
        exceptions: [{ field: 'user.name', op: 'equals', values: ['svc'] }],
      })
    );
    const clauses = (input.filter as { clauses: object[] }).clauses;
    expect(clauses[clauses.length - 1]).toEqual({
      bool: { must_not: [{ term: { 'user.name': 'svc' } }] },
    });
  });

  it('invalid exceptions are rejected with the PPL label', () => {
    expect(() =>
      assertValidPplRule(d9Rule({ exceptions: [{ field: 'f', op: 'equals', values: [] }] }))
    ).toThrow('PPL rule "ppl exc": exception 1 ("f") must list at least one value');
  });
});
