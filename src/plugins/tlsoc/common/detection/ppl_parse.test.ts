/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  buildPplPreviewQuery,
  FieldRef,
  parsePpl,
  PplParseFailure,
  PplParseSuccess,
  PplRuleAst,
  WhereExpr,
} from './ppl_parse';

/**
 * The R4 §5 battery — all 35 cases at the parse level (lower-level goldens live in
 * ppl_rule.test.ts) — plus the full §4 reject-by-name sweep and offset sanity checks.
 */

// The scanner rule VERBATIM (R4 §5 case 1, thresholds 40/50).
const SCANNER =
  'source = fosstlsoc-logs-moodle-* | where http.response.status_code >= 400 | ' +
  'stats dc(url.path) as unique_paths, count() as errors by source.ip, user_agent.original | ' +
  'where unique_paths >= 40 and errors >= 50';

function ok(query: string): PplParseSuccess {
  const result = parsePpl(query);
  if (!result.ok) {
    throw new Error(
      `expected "${query}" to parse, got: ${JSON.stringify((result as PplParseFailure).errors)}`
    );
  }
  return result;
}

function fail(query: string): PplParseFailure {
  const result = parsePpl(query);
  if (result.ok) {
    throw new Error(`expected "${query}" to be rejected, but it parsed`);
  }
  expect(result.errors.length).toBeGreaterThan(0);
  return result;
}

/** Strip FieldRef spans so trees can be pinned without offset noise (spans tested separately). */
function stripWhere(expr: WhereExpr | null): unknown {
  if (expr === null) return null;
  switch (expr.kind) {
    case 'and':
    case 'or':
      return { kind: expr.kind, operands: expr.operands.map((o) => stripWhere(o)) };
    case 'not':
      return { kind: 'not', operand: stripWhere(expr.operand) };
    case 'cmp':
      return { kind: 'cmp', field: expr.field.name, op: expr.op, value: expr.value };
    case 'like':
      return { kind: 'like', field: expr.field.name, pattern: expr.pattern };
    case 'in':
      return { kind: 'in', field: expr.field.name, values: expr.values };
  }
}

function sketch(rule: PplRuleAst) {
  return {
    indices: rule.indices,
    where: stripWhere(rule.where),
    metrics: rule.metrics,
    by: rule.by.map((f) => f.name),
    having: rule.having,
  };
}

function collectFieldRefs(rule: PplRuleAst): FieldRef[] {
  const refs: FieldRef[] = [...rule.by];
  const walk = (e: WhereExpr | null): void => {
    if (e === null) return;
    switch (e.kind) {
      case 'and':
      case 'or':
        e.operands.forEach(walk);
        break;
      case 'not':
        walk(e.operand);
        break;
      default:
        refs.push(e.field);
    }
  };
  walk(rule.where);
  return refs;
}

describe('parsePpl — accepted subset (R4 §5 positive cases)', () => {
  it('case 1: the scanner rule VERBATIM parses to the pinned AST', () => {
    const { rule, warnings } = ok(SCANNER);
    expect(sketch(rule)).toEqual({
      indices: ['fosstlsoc-logs-moodle-*'],
      where: { kind: 'cmp', field: 'http.response.status_code', op: '>=', value: 400 },
      metrics: [
        { fn: 'dc', field: 'url.path', alias: 'unique_paths' },
        { fn: 'count', field: null, alias: 'errors' },
      ],
      by: ['source.ip', 'user_agent.original'],
      having: {
        kind: 'and',
        operands: [
          { kind: 'cmp', metricAlias: 'unique_paths', op: '>=', value: 40 },
          { kind: 'cmp', metricAlias: 'errors', op: '>=', value: 50 },
        ],
      },
    });
    expect(warnings).toEqual([]);
  });

  it('case 1b: every FieldRef span slices back to its own source text', () => {
    const { rule } = ok(SCANNER);
    const refs = collectFieldRefs(rule);
    expect(refs.length).toBeGreaterThan(0);
    refs.forEach((ref) => {
      const sliced = SCANNER.slice(ref.span[0], ref.span[1]);
      expect(sliced === ref.name || sliced === `\`${ref.name}\``).toBe(true);
    });
  });

  it('case 2: spaces around "=" in source are accepted', () => {
    const { rule } = ok('source = idx | stats count()');
    expect(rule.indices).toEqual(['idx']);
    expect(rule.metrics).toEqual([{ fn: 'count', field: null, alias: null }]);
    expect(rule.by).toEqual([]);
    expect(rule.having).toBeNull();
  });

  it('case 2b: a rule without a post-stats threshold warns (fires on every group)', () => {
    const { warnings } = ok('source = idx | stats count() by f');
    expect(warnings.some((w) => /threshold/.test(w))).toBe(true);
  });

  it('case 3: backticked index + backticked field + "==" normalizes to "="', () => {
    const { rule } = ok(
      'source=`idx` | where `http.response.status_code` == 404 | stats count()'
    );
    expect(rule.indices).toEqual(['idx']);
    expect(stripWhere(rule.where)).toEqual({
      kind: 'cmp',
      field: 'http.response.status_code',
      op: '=',
      value: 404,
    });
  });

  it('case 4: wildcard index pattern', () => {
    const { rule } = ok('source=fosstlsoc-logs-moodle-* | stats count()');
    expect(rule.indices).toEqual(['fosstlsoc-logs-moodle-*']);
  });

  it('case 5: comma multi-index; spaces tolerated with a warning', () => {
    const tight = ok('source=a,b | stats count()');
    expect(tight.rule.indices).toEqual(['a', 'b']);
    expect(tight.warnings.some((w) => /spaces/.test(w))).toBe(false);

    const spaced = ok('source=a, b | stats count()');
    expect(spaced.rule.indices).toEqual(['a', 'b']);
    expect(spaced.warnings.some((w) => /spaces/.test(w))).toBe(true);
  });

  it('case 6: keywords and commands are case-insensitive', () => {
    const { rule } = ok('SOURCE=x | WHERE a=1 AND b=2 | STATS COUNT() BY c');
    expect(stripWhere(rule.where)).toEqual({
      kind: 'and',
      operands: [
        { kind: 'cmp', field: 'a', op: '=', value: 1 },
        { kind: 'cmp', field: 'b', op: '=', value: 2 },
      ],
    });
    expect(rule.metrics).toEqual([{ fn: 'count', field: null, alias: null }]);
    expect(rule.by.map((f) => f.name)).toEqual(['c']);
  });

  it('case 6b: the optional leading "search" keyword is accepted', () => {
    const { rule } = ok('search source = x | stats count()');
    expect(rule.indices).toEqual(['x']);
  });

  it('case 7: precedence — and binds tighter than or (live-verified)', () => {
    const { rule } = ok('source=x | where a=1 or b=2 and c=3 | stats count() by g');
    expect(stripWhere(rule.where)).toEqual({
      kind: 'or',
      operands: [
        { kind: 'cmp', field: 'a', op: '=', value: 1 },
        {
          kind: 'and',
          operands: [
            { kind: 'cmp', field: 'b', op: '=', value: 2 },
            { kind: 'cmp', field: 'c', op: '=', value: 3 },
          ],
        },
      ],
    });
  });

  it('case 8: parentheses override precedence', () => {
    const { rule } = ok('source=x | where (a=1 or b=2) and c=3 | stats count() by g');
    expect(stripWhere(rule.where)).toEqual({
      kind: 'and',
      operands: [
        {
          kind: 'or',
          operands: [
            { kind: 'cmp', field: 'a', op: '=', value: 1 },
            { kind: 'cmp', field: 'b', op: '=', value: 2 },
          ],
        },
        { kind: 'cmp', field: 'c', op: '=', value: 3 },
      ],
    });
  });

  it('case 9: not like(…) parses as not-of-a-like leaf', () => {
    const { rule } = ok("source=x | where not like(url.path, '%login%') | stats count() by g");
    expect(stripWhere(rule.where)).toEqual({
      kind: 'not',
      operand: { kind: 'like', field: 'url.path', pattern: '%login%' },
    });
  });

  it('case 10: != comparison', () => {
    const { rule } = ok("source=x | where f != 'x' | stats count() by g");
    expect(stripWhere(rule.where)).toEqual({ kind: 'cmp', field: 'f', op: '!=', value: 'x' });
  });

  it('case 11: in with numbers', () => {
    const { rule } = ok('source=x | where s in (403, 404) | stats count() by g');
    expect(stripWhere(rule.where)).toEqual({ kind: 'in', field: 's', values: [403, 404] });
  });

  it('case 12: in with mixed quote styles', () => {
    const { rule } = ok('source=x | where d in (\'a\', "b") | stats count() by g');
    expect(stripWhere(rule.where)).toEqual({ kind: 'in', field: 'd', values: ['a', 'b'] });
  });

  it('case 13: like() pattern is stored raw (%→*/_→? happens at lowering)', () => {
    const { rule } = ok("source=x | where like(f, '%a_b%') | stats count() by g");
    expect(stripWhere(rule.where)).toEqual({ kind: 'like', field: 'f', pattern: '%a_b%' });
  });

  it('case 14: infix like ≡ function-form like', () => {
    const infix = ok("source=x | where f like '/mod/%' | stats count() by g");
    const fn = ok("source=x | where like(f, '/mod/%') | stats count() by g");
    expect(sketch(infix.rule)).toEqual(sketch(fn.rule));
  });

  it("case 15: doubled-quote escapes — 'it''s' and \"it's\" both mean it's", () => {
    const singled = ok("source=x | where f = 'it''s' | stats count() by g");
    const doubled = ok('source=x | where f = "it\'s" | stats count() by g');
    expect(stripWhere(singled.rule.where)).toEqual({
      kind: 'cmp',
      field: 'f',
      op: '=',
      value: "it's",
    });
    expect(stripWhere(doubled.rule.where)).toEqual(stripWhere(singled.rule.where));
  });

  it('case 16: multiple pre-stats wheres fold with AND', () => {
    const { rule } = ok('source=x | where a=1 | where b=2 | stats count() by g');
    expect(stripWhere(rule.where)).toEqual({
      kind: 'and',
      operands: [
        { kind: 'cmp', field: 'a', op: '=', value: 1 },
        { kind: 'cmp', field: 'b', op: '=', value: 2 },
      ],
    });
  });

  it('case 17: multi-metric + multi-by, order preserved', () => {
    const { rule } = ok(
      'source=x | stats count() as errors, dc(url.path) as paths by source.ip, user_agent.original'
    );
    expect(rule.metrics).toEqual([
      { fn: 'count', field: null, alias: 'errors' },
      { fn: 'dc', field: 'url.path', alias: 'paths' },
    ]);
    expect(rule.by.map((f) => f.name)).toEqual(['source.ip', 'user_agent.original']);
  });

  it('case 18: count-alias referenced in having (the _count mapping is a lowering concern)', () => {
    const { rule } = ok('source=x | stats count() as errors by g | where errors >= 50');
    expect(rule.having).toEqual({ kind: 'cmp', metricAlias: 'errors', op: '>=', value: 50 });
  });

  it('case 19: having supports or + parentheses', () => {
    const { rule } = ok(
      'source=x | stats count() as a, dc(f) as b by g | where (a >= 3 and b >= 5) or a >= 100'
    );
    expect(rule.having).toEqual({
      kind: 'or',
      operands: [
        {
          kind: 'and',
          operands: [
            { kind: 'cmp', metricAlias: 'a', op: '>=', value: 3 },
            { kind: 'cmp', metricAlias: 'b', op: '>=', value: 5 },
          ],
        },
        { kind: 'cmp', metricAlias: 'a', op: '>=', value: 100 },
      ],
    });
  });

  it('case 21: c(), bare count, bare c all normalize to count()', () => {
    expect(ok('source=x | stats c() as n').rule.metrics).toEqual([
      { fn: 'count', field: null, alias: 'n' },
    ]);
    expect(ok('source=x | stats count').rule.metrics).toEqual([
      { fn: 'count', field: null, alias: null },
    ]);
    expect(ok('source=x | stats c').rule.metrics).toEqual([
      { fn: 'count', field: null, alias: null },
    ]);
  });

  it('case 22: distinct_count(f) normalizes to dc', () => {
    expect(ok('source=x | stats distinct_count(f) as n by g').rule.metrics).toEqual([
      { fn: 'dc', field: 'f', alias: 'n' },
    ]);
  });

  it('count(field) keeps its field (value_count at lowering)', () => {
    expect(ok('source=x | stats count(f) as n by g').rule.metrics).toEqual([
      { fn: 'count', field: 'f', alias: 'n' },
    ]);
  });

  it('sum/avg/min/max parse with their field', () => {
    const { rule } = ok(
      'source=x | stats sum(a) as s, avg(b) as av, min(c) as mn, max(d) as mx by g'
    );
    expect(rule.metrics).toEqual([
      { fn: 'sum', field: 'a', alias: 's' },
      { fn: 'avg', field: 'b', alias: 'av' },
      { fn: 'min', field: 'c', alias: 'mn' },
      { fn: 'max', field: 'd', alias: 'mx' },
    ]);
  });

  it('boolean and negative-number literals', () => {
    expect(
      stripWhere(ok('source=x | where flag = true | stats count() by g').rule.where)
    ).toEqual({ kind: 'cmp', field: 'flag', op: '=', value: true });
    expect(stripWhere(ok('source=x | where n = -5 | stats count() by g').rule.where)).toEqual({
      kind: 'cmp',
      field: 'n',
      op: '=',
      value: -5,
    });
  });

  it('having accepts = and != against numbers ("==" normalizes)', () => {
    expect(
      ok('source=x | stats count() as n by g | where n == 3').rule.having
    ).toEqual({ kind: 'cmp', metricAlias: 'n', op: '=', value: 3 });
    expect(
      ok('source=x | stats count() as n by g | where n != 0').rule.having
    ).toEqual({ kind: 'cmp', metricAlias: 'n', op: '!=', value: 0 });
  });

  it('backtick fields with dots parse (multi-segment paths)', () => {
    const { rule } = ok(
      'source=x | stats dc(`resource.attributes.service.name`) as n by `some.field`'
    );
    expect(rule.metrics[0].field).toBe('resource.attributes.service.name');
    expect(rule.by[0].name).toBe('some.field');
  });
});

describe('parsePpl — rejects BY NAME (R4 §4)', () => {
  const REJECTED_COMMANDS = [
    'fields',
    'table',
    'sort',
    'head',
    'eval',
    'dedup',
    'top',
    'rare',
    'rename',
    'parse',
    'regex',
    'rex',
    'sed',
    'punct',
    'grok',
    'patterns',
    'bin',
    'chart',
    'timechart',
    'timewrap',
    'trendline',
    'transpose',
    'addtotals',
    'addcoltotals',
    'eventstats',
    'streamstats',
    'fillnull',
    'flatten',
    'convert',
    'expand',
    'mvexpand',
    'mvcombine',
    'nomv',
    'spath',
    'reverse',
    'replace',
    'fieldformat',
    'join',
    'lookup',
    'graphlookup',
    'append',
    'appendcol',
    'appendpipe',
    'union',
    'multisearch',
    'kmeans',
    'ad',
    'ml',
    'describe',
    'explain',
    'show',
    'foreach',
  ];

  it.each(REJECTED_COMMANDS)('rejects the "%s" command quoting its name', (cmd) => {
    const { errors } = fail(`source=x | ${cmd} something | stats count()`);
    expect(errors[0].construct).toBe(cmd);
    expect(errors[0].reason).toContain(`"${cmd}" command is not supported in detection rules`);
  });

  it('cases 27-29: sort/head/eval rejected even after stats + having', () => {
    ['sort - c', 'head 10', 'eval x=1'].forEach((tail) => {
      const cmd = tail.split(' ')[0];
      const q = `source=x | stats count() as n by g | where n > 1 | ${tail}`;
      const { errors } = fail(q);
      expect(errors[0].construct).toBe(cmd);
      expect(errors[0].offset).toBe(q.indexOf(cmd, q.indexOf('| where') + 1));
    });
  });

  const REJECTED_AGGS = [
    'distinct_count_approx',
    'estdc',
    'estdc_error',
    'percentile',
    'percentile_approx',
    'median',
    'mean',
    'mode',
    'range',
    'stdev',
    'stdevp',
    'var_samp',
    'var_pop',
    'stddev_samp',
    'stddev_pop',
    'sumsq',
    'take',
    'earliest',
    'latest',
    'first',
    'last',
    'list',
    'values',
  ];

  it.each(REJECTED_AGGS)('rejects the "%s" aggregation quoting its name', (agg) => {
    const { errors } = fail(`source=x | stats ${agg}(f) by g`);
    expect(errors[0].construct).toBe(agg);
    expect(errors[0].reason).toContain(`aggregation "${agg}" is not supported`);
  });

  it('rejects percN / pN shorthands', () => {
    expect(fail('source=x | stats p95(f) by g').errors[0].construct).toBe('p95');
    expect(fail('source=x | stats perc99(f) by g').errors[0].construct).toBe('perc99');
  });

  it('rejects count(eval(…)) by name', () => {
    const { errors } = fail('source=x | stats count(eval(status >= 400)) by g');
    expect(errors[0].construct).toBe('count(eval())');
    expect(errors[0].reason).toContain('use a "| where" filter instead');
  });

  it('case 30: bare search expressions after the source are rejected', () => {
    const q = 'source=idx status=404 | stats count()';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('search-expression');
    expect(errors[0].reason).toContain('"| where"');
    expect(errors[0].offset).toBe(q.indexOf('status=404'));
  });

  it('case 31: earliest/latest time modifiers are rejected quoting the snippet', () => {
    const q = 'source=idx earliest=-7d | stats count()';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('earliest');
    expect(errors[0].reason).toContain('remove "earliest=-7d"');
    expect(errors[0].offset).toBe(q.indexOf('earliest'));

    expect(fail('source=idx latest=now | stats count()').errors[0].construct).toBe('latest');
  });

  it('cross-cluster sources are rejected', () => {
    const { errors } = fail('source=cluster1:idx | stats count()');
    expect(errors[0].construct).toBe('cross-cluster-source');
    expect(errors[0].reason).toContain('cluster:index');
  });

  it('case 32: span() in by is rejected', () => {
    const q = 'source=x | stats count() by span(@timestamp, 1h)';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('span()');
    expect(errors[0].reason).toContain('the rule window is the time bucket');
    expect(errors[0].offset).toBe(q.indexOf('span('));
  });

  it('bucket_nullable= is rejected', () => {
    const { errors } = fail('source=x | stats bucket_nullable=false count() by g');
    expect(errors[0].construct).toBe('bucket_nullable');
  });

  it('case 33: xor is rejected (precedence hazard)', () => {
    const q = 'source=x | where a=1 xor b=2 | stats count() by g';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('xor');
    expect(errors[0].offset).toBe(q.indexOf('xor'));
  });

  it('xor is also rejected in the threshold condition', () => {
    expect(
      fail('source=x | stats count() as n by g | where n > 1 xor n < 5').errors[0].construct
    ).toBe('xor');
  });

  it('arithmetic in predicates is rejected', () => {
    const q = 'source=x | where age > 25 + 5 | stats count() by g';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('arithmetic');
    expect(errors[0].offset).toBe(q.indexOf('+'));
  });

  it.each(['isnull', 'isnotnull', 'cidrmatch', 'regexp', 'coalesce', 'if'])(
    'rejects the %s() function generically, quoting its name',
    (fn) => {
      const { errors } = fail(`source=x | where ${fn}(f) | stats count() by g`);
      expect(errors[0].construct).toBe(`${fn}()`);
      expect(errors[0].reason).toContain(`function "${fn}()" is not supported`);
    }
  );

  it('IS NULL / IS NOT NULL are rejected', () => {
    expect(fail('source=x | where f is null | stats count() by g').errors[0].construct).toBe(
      'is-null'
    );
  });

  it('BETWEEN is rejected', () => {
    expect(
      fail('source=x | where age between 1 and 5 | stats count() by g').errors[0].construct
    ).toBe('between');
  });

  it('postfix "not in" is rejected (prefix not (… in …) is the supported form)', () => {
    const { errors } = fail('source=x | where f not in (1, 2) | stats count() by g');
    expect(errors[0].construct).toBe('not-in');
    // …and the prefix form parses:
    ok('source=x | where not (f in (1, 2)) | stats count() by g');
  });

  it('case 26: .keyword suffixes are rejected with the resolution hint', () => {
    const byQ = 'source=x | stats count() by user_agent.original.keyword';
    const byErr = fail(byQ).errors[0];
    expect(byErr.construct).toBe('keyword-subfield');
    expect(byErr.reason).toBe(
      'write "user_agent.original" — TLSOC resolves keyword subfields automatically'
    );
    expect(byErr.offset).toBe(byQ.indexOf('user_agent'));

    expect(
      fail("source=x | where f.keyword = 'v' | stats count() by g").errors[0].construct
    ).toBe('keyword-subfield');
    expect(fail('source=x | stats dc(f.keyword) by g').errors[0].construct).toBe(
      'keyword-subfield'
    );
    expect(
      fail('source=x | stats count() by `user_agent.original.keyword`').errors[0].construct
    ).toBe('keyword-subfield');
  });

  it('comments are rejected by name', () => {
    expect(
      fail('source=x | where a=1 // comment | stats count()').errors[0].construct
    ).toBe('comment');
    expect(
      fail('source=x /* comment */ | stats count()').errors[0].construct
    ).toBe('comment');
  });

  it('subsearches are rejected', () => {
    expect(fail('source=x | [ search foo ] | stats count()').errors[0].construct).toBe(
      'subsearch'
    );
  });

  it('empty command between pipes is rejected', () => {
    expect(fail('source=x | | stats count()').errors[0].construct).toBe('empty-command');
  });

  it('a second stats command is rejected', () => {
    const { errors } = fail('source=x | stats count() by g | stats count() by h');
    expect(errors[0].construct).toBe('stats');
    expect(errors[0].reason).toContain('only one "stats"');
  });

  it('a second post-stats where (threshold) is rejected', () => {
    const { errors } = fail('source=x | stats count() as n by g | where n > 1 | where n < 9');
    expect(errors[0].construct).toBe('having');
  });

  it('queries over 8 KB are rejected (input guard)', () => {
    const big = `source=x | where f = '${'a'.repeat(9000)}' | stats count() by g`;
    const { errors } = fail(big);
    expect(errors[0].construct).toBe('input');
    expect(errors[0].reason).toContain('8 KB');
  });
});

describe('parsePpl — grammar-position errors carry offsets (R4 §5 error cases)', () => {
  it('case 23: an unknown command quotes the bad word at its offset', () => {
    const q = 'source=idx | wher x=1 | stats count()';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('command');
    expect(errors[0].reason).toContain('"wher"');
    expect(errors[0].offset).toBe(q.indexOf('wher'));
    expect(errors[0].length).toBe('wher'.length);
  });

  it('case 24: a dangling operator errors at the following pipe', () => {
    const q = 'source=idx | where s >= | stats count()';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('syntax');
    expect(errors[0].offset).toBe(q.indexOf('|', q.indexOf('>=')));
  });

  it('case 20: unaliased metric referenced in having → having-reference quoting the call', () => {
    const q = 'source=x | stats dc(f) by g | where dc(f) > 3';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('having-reference');
    expect(errors[0].reason).toBe(
      `metric "dc(f)" must be given a name with 'as' before it can be used in the threshold condition`
    );
    expect(errors[0].offset).toBe(q.lastIndexOf('dc(f)'));
    expect(errors[0].length).toBe('dc(f)'.length);
  });

  it('an unknown alias in having → having-reference naming the identifier', () => {
    const { errors } = fail('source=x | stats count() as n by g | where m > 3');
    expect(errors[0].construct).toBe('having-reference');
    expect(errors[0].reason).toContain('"m" does not name a metric');
  });

  it('case 34: stats with no aggregation errors with a position', () => {
    const q = 'source=x | stats by f';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('syntax');
    expect(errors[0].reason).toContain('at least one aggregation');
    expect(errors[0].offset).toBe(q.indexOf('by f'));
  });

  it('case 35: empty / whitespace-only queries are rejected', () => {
    expect(fail('').errors[0].reason).toContain('the query is empty');
    expect(fail('   ').errors[0].reason).toContain('the query is empty');
  });

  it('case 35b: a query with no stats is rejected — a rule must aggregate', () => {
    const q = 'source=x';
    const { errors } = fail(q);
    expect(errors[0].construct).toBe('stats');
    expect(errors[0].reason).toBe('a detection rule must aggregate — add "| stats …"');
    expect(errors[0].offset).toBe(q.length);
    expect(fail('source=x | where a=1').errors[0].construct).toBe('stats');
  });

  it('a comparison with the literal on the left is rejected', () => {
    const { errors } = fail('source=x | where 404 = f | stats count() by g');
    expect(errors[0].construct).toBe('syntax');
    expect(errors[0].reason).toContain('the field goes on the left');
  });

  it('reserved words cannot be bare field names', () => {
    const { errors } = fail('source=x | where stats = 1 | stats count() by g');
    expect(errors[0].construct).toBe('syntax');
    expect(errors[0].reason).toContain('reserved word');
  });

  it('unterminated strings and backticks are positioned errors', () => {
    expect(fail("source=x | where f = 'oops | stats count()").errors[0].reason).toContain(
      'unterminated string'
    );
    expect(fail('source=x | where `f = 1 | stats count()').errors[0].reason).toContain(
      'unterminated backtick'
    );
  });

  it('duplicate metric aliases are rejected', () => {
    const { errors } = fail('source=x | stats count() as n, dc(f) as n by g');
    expect(errors[0].construct).toBe('alias');
    expect(errors[0].reason).toContain('duplicate alias "n"');
  });

  it('aliases must be lowercase [a-z][a-z0-9_]* (they become monitor metric names)', () => {
    const { errors } = fail('source=x | stats count() as N by g');
    expect(errors[0].construct).toBe('alias');
    expect(errors[0].reason).toContain('"N"');
  });

  it('the threshold value must be a number', () => {
    const { errors } = fail("source=x | stats count() as n by g | where n > 'x'");
    expect(errors[0].construct).toBe('syntax');
    expect(errors[0].reason).toContain('to a number');
  });

  it('every failure carries offset within bounds and non-negative length', () => {
    const queries = [
      'source=x | sort - c',
      'source=idx | wher x=1 | stats count()',
      'source=x | where a=1 xor b=2 | stats count()',
      'source=x | stats dc(f) by g | where dc(f) > 3',
      'source=x',
    ];
    queries.forEach((q) => {
      const { errors } = fail(q);
      errors.forEach((e) => {
        expect(e.offset).toBeGreaterThanOrEqual(0);
        expect(e.offset).toBeLessThanOrEqual(q.length);
        expect(e.length).toBeGreaterThanOrEqual(0);
        expect(e.offset + e.length).toBeLessThanOrEqual(q.length);
      });
    });
  });
});

describe('buildPplPreviewQuery (R4 §6 — window injection + head cap)', () => {
  it('injects the window into the LAST pre-stats where, parenthesized, and appends head 100', () => {
    const out = buildPplPreviewQuery(SCANNER, '@timestamp', { value: 5, unit: 'MINUTES' });
    expect(out).toBe(
      'source = fosstlsoc-logs-moodle-* | ' +
        'where (http.response.status_code >= 400) and `@timestamp` >= date_sub(now(), interval 5 minute) | ' +
        'stats dc(url.path) as unique_paths, count() as errors by source.ip, user_agent.original | ' +
        'where unique_paths >= 40 and errors >= 50 | head 100'
    );
  });

  it('adds a new where before stats when the rule has no pre-stats filter', () => {
    const out = buildPplPreviewQuery('source=x | stats count() by g', 'ts', {
      value: 1,
      unit: 'HOURS',
    });
    expect(out).toBe(
      'source=x | where `ts` >= date_sub(now(), interval 1 hour) | stats count() by g | head 100'
    );
  });

  it('parenthesizing prevents or-rebinding of the injected conjunct', () => {
    const out = buildPplPreviewQuery(
      'source=x | where a=1 or b=2 | stats count() by g',
      'ts',
      { value: 7, unit: 'DAYS' }
    );
    expect(out).toContain('where (a=1 or b=2) and `ts` >= date_sub(now(), interval 7 day)');
  });

  it('injects into the last of several wheres, never into the having', () => {
    const out = buildPplPreviewQuery(
      'source=x | where a=1 | where b=2 | stats count() as n by g | where n > 5',
      'ts',
      { value: 5, unit: 'MINUTES' }
    );
    expect(out).toBe(
      'source=x | where a=1 | ' +
        'where (b=2) and `ts` >= date_sub(now(), interval 5 minute) | ' +
        'stats count() as n by g | where n > 5 | head 100'
    );
  });

  it('NEVER emits timestampadd (the R4 silent-zero trap)', () => {
    const out = buildPplPreviewQuery(SCANNER, '@timestamp', { value: 30, unit: 'DAYS' });
    expect(/timestampadd/i.test(out)).toBe(false);
    expect(out).toContain('date_sub(now(), interval 30 day)');
  });

  it('pipes inside string literals are not treated as command separators', () => {
    const out = buildPplPreviewQuery(
      "source=x | where f = 'a|b' | stats count() by g",
      'ts',
      { value: 5, unit: 'MINUTES' }
    );
    expect(out).toBe(
      "source=x | where (f = 'a|b') and `ts` >= date_sub(now(), interval 5 minute) | " +
        'stats count() by g | head 100'
    );
  });
});
