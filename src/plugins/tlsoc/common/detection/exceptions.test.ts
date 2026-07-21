/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  ExceptionEntry,
  MAX_EXCEPTION_ENTRIES,
  applyExceptionsToLucene,
  exceptionFieldNames,
  exceptionsToFilterClause,
  exceptionsToLucene,
  exceptionsToMustNot,
  isValidCidr,
  ruleHasExceptions,
  validateExceptions,
} from './exceptions';

const LABEL = 'Detection rule "X"';

describe('validateExceptions — reject-by-name discipline', () => {
  const ok = (entries: ExceptionEntry[]) =>
    expect(() => validateExceptions(entries, LABEL)).not.toThrow();
  const bad = (entries: unknown, message: string | RegExp) =>
    expect(() => validateExceptions(entries, LABEL)).toThrow(message);

  it('accepts an empty list (means "no exceptions")', () => ok([]));

  it('accepts one entry per operator', () =>
    ok([
      { field: 'user.name', op: 'equals', values: ['svc-backup'] },
      { field: 'user.name', op: 'is_one_of', values: ['a', 'b'] },
      { field: 'url.path', op: 'contains', values: ['/health'] },
      { field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] },
    ]));

  it('rejects a non-array', () => {
    bad(undefined, 'exceptions must be a list');
    bad({ field: 'a' }, 'exceptions must be a list');
    bad('nope', 'exceptions must be a list');
  });

  it(`rejects more than ${MAX_EXCEPTION_ENTRIES} entries, naming the cap`, () => {
    const entries = Array.from({ length: MAX_EXCEPTION_ENTRIES + 1 }, (_, i) => ({
      field: `f${i}`,
      op: 'equals' as const,
      values: ['v'],
    }));
    bad(entries, `${MAX_EXCEPTION_ENTRIES}-entry cap`);
  });

  it(`accepts exactly ${MAX_EXCEPTION_ENTRIES} entries`, () =>
    ok(
      Array.from({ length: MAX_EXCEPTION_ENTRIES }, (_, i) => ({
        field: `f${i}`,
        op: 'equals' as const,
        values: ['v'],
      }))
    ));

  it('rejects a malformed entry, naming its position', () => {
    bad([null], 'exception 1 is malformed');
    bad(['str'], 'exception 1 is malformed');
  });

  it('rejects a missing/empty field', () => {
    bad([{ op: 'equals', values: ['v'] }], 'exception 1: a field is required');
    bad([{ field: '  ', op: 'equals', values: ['v'] }], 'a field is required');
  });

  it('rejects an unknown operator by name, listing the supported set', () =>
    bad(
      [{ field: 'f', op: 'starts_with', values: ['v'] }],
      'unknown operator "starts_with". Supported: equals, is_one_of, contains, cidr.'
    ));

  it('rejects empty values (missing, empty list, empty string, non-string)', () => {
    bad([{ field: 'f', op: 'equals' }], 'must list at least one value');
    bad([{ field: 'f', op: 'equals', values: [] }], 'must list at least one value');
    bad([{ field: 'f', op: 'equals', values: [''] }], 'value 1 is empty');
    bad([{ field: 'f', op: 'equals', values: ['ok', '  '] }], 'value 2 is empty');
    bad([{ field: 'f', op: 'equals', values: [42] }], 'value 1 is empty');
  });

  it('rejects bad CIDR values for op cidr, naming the value', () => {
    bad([{ field: 'src', op: 'cidr', values: ['10.0.0.0'] }], '"10.0.0.0" is not a valid CIDR');
    bad([{ field: 'src', op: 'cidr', values: ['10.0.0.256/8'] }], 'not a valid CIDR');
    bad([{ field: 'src', op: 'cidr', values: ['10.0.0.0/33'] }], 'not a valid CIDR');
    bad([{ field: 'src', op: 'cidr', values: ['not-an-ip/8'] }], 'not a valid CIDR');
    bad([{ field: 'src', op: 'cidr', values: ['2001:db8::/129'] }], 'not a valid CIDR');
    bad([{ field: 'src', op: 'cidr', values: ['10.0.0.0/8/9'] }], 'not a valid CIDR');
  });

  it('does NOT cidr-check other operators (a slash value is a legal keyword)', () =>
    ok([{ field: 'url.path', op: 'equals', values: ['/etc/passwd'] }]));

  it('prefixes every message with the caller-supplied rule label', () =>
    bad([{ field: '', op: 'equals', values: ['v'] }], /^Detection rule "X": exception 1/));
});

describe('isValidCidr', () => {
  it.each(['10.0.0.0/8', '0.0.0.0/0', '255.255.255.255/32', '192.168.1.0/24'])(
    'accepts IPv4 %s',
    (v) => expect(isValidCidr(v)).toBe(true)
  );
  it.each(['2001:db8::/32', '::/0', 'fe80::1/128', '2001:db8:0:0:0:0:0:1/64'])(
    'accepts IPv6 %s',
    (v) => expect(isValidCidr(v)).toBe(true)
  );
  it.each([
    '10.0.0.0', // no prefix
    '10.0.0/8', // 3 octets
    '10.0.0.0.0/8', // 5 octets
    '256.0.0.0/8', // octet range
    '10.0.0.0/33', // v4 prefix range
    '10.0.0.0/-1', // negative prefix
    '10.0.0.0/x', // non-numeric prefix
    '2001:db8::/129', // v6 prefix range
    '2001:db8::1::2/64', // double '::' twice
    'g001:db8::/32', // non-hex group
    '1:2:3:4:5:6:7/64', // 7 groups without '::'
    '/8', // empty address
    '', // empty
  ])('rejects %s', (v) => expect(isValidCidr(v)).toBe(false));
});

describe('exceptionsToLucene — the doc-level ` AND NOT (…)` fragment', () => {
  it('returns "" for undefined/empty (the byte-identity contract)', () => {
    expect(exceptionsToLucene(undefined)).toBe('');
    expect(exceptionsToLucene([])).toBe('');
  });

  it('equals, one value → quoted phrase', () =>
    expect(exceptionsToLucene([{ field: 'user.name', op: 'equals', values: ['svc'] }])).toBe(
      ' AND NOT (user.name:"svc")'
    ));

  it('equals, multiple values → field-grouped OR (is_one_of shape)', () =>
    expect(exceptionsToLucene([{ field: 'u', op: 'equals', values: ['a', 'b'] }])).toBe(
      ' AND NOT ((u:"a" OR u:"b"))'
    ));

  it('is_one_of → field-grouped OR of quoted phrases', () =>
    expect(
      exceptionsToLucene([{ field: 'source.ip', op: 'is_one_of', values: ['10.0.0.1', '10.0.0.2'] }])
    ).toBe(' AND NOT ((source.ip:"10.0.0.1" OR source.ip:"10.0.0.2"))'));

  it('contains → escaped substring wildcard (lucene.ts escaping)', () =>
    expect(exceptionsToLucene([{ field: 'url.path', op: 'contains', values: ['/health'] }])).toBe(
      ' AND NOT (url.path:*\\/health*)'
    ));

  it('contains, multiple values → parenthesized OR of wildcards', () =>
    expect(exceptionsToLucene([{ field: 'p', op: 'contains', values: ['a b', 'c'] }])).toBe(
      ' AND NOT ((p:*a\\ b* OR p:*c*))'
    ));

  it('cidr → QUOTED phrase (the proven doc-level syntax; unquoted "/" starts a regex)', () =>
    expect(exceptionsToLucene([{ field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] }])).toBe(
      ' AND NOT (source.ip:"10.0.0.0/8")'
    ));

  it('cidr, multiple blocks → field-grouped OR of quoted phrases', () =>
    expect(
      exceptionsToLucene([{ field: 's', op: 'cidr', values: ['10.0.0.0/8', '2001:db8::/32'] }])
    ).toBe(' AND NOT ((s:"10.0.0.0/8" OR s:"2001:db8::/32"))'));

  it('multiple entries OR-join inside ONE NOT group', () =>
    expect(
      exceptionsToLucene([
        { field: 'user.name', op: 'equals', values: ['svc'] },
        { field: 'source.ip', op: 'cidr', values: ['10.0.0.0/8'] },
      ])
    ).toBe(' AND NOT (user.name:"svc" OR source.ip:"10.0.0.0/8")'));

  it('phrase escaping: quotes and backslashes escape exactly like lucene.ts', () =>
    expect(
      exceptionsToLucene([{ field: 'msg', op: 'equals', values: ['say "hi" \\ bye'] }])
    ).toBe(' AND NOT (msg:"say \\"hi\\" \\\\ bye")'));
});

describe('applyExceptionsToLucene', () => {
  it('returns the query UNTOUCHED without entries (byte identity)', () => {
    expect(applyExceptionsToLucene('a:1 OR b:2', undefined)).toBe('a:1 OR b:2');
    expect(applyExceptionsToLucene('a:1 OR b:2', [])).toBe('a:1 OR b:2');
  });

  it('parenthesizes the base query before appending (OR-precedence safety)', () =>
    expect(
      applyExceptionsToLucene('(a:1) OR (b:2)', [{ field: 'f', op: 'equals', values: ['v'] }])
    ).toBe('((a:1) OR (b:2)) AND NOT (f:"v")'));
});

describe('exceptionsToMustNot — the bucket-side structured clauses', () => {
  it('returns [] for undefined/empty', () => {
    expect(exceptionsToMustNot(undefined)).toEqual([]);
    expect(exceptionsToMustNot([])).toEqual([]);
  });

  it('equals, one value → term', () =>
    expect(exceptionsToMustNot([{ field: 'u', op: 'equals', values: ['svc'] }])).toEqual([
      { term: { u: 'svc' } },
    ]));

  it('equals, multiple values → terms', () =>
    expect(exceptionsToMustNot([{ field: 'u', op: 'equals', values: ['a', 'b'] }])).toEqual([
      { terms: { u: ['a', 'b'] } },
    ]));

  it('is_one_of → terms (even for one value)', () =>
    expect(exceptionsToMustNot([{ field: 'u', op: 'is_one_of', values: ['a'] }])).toEqual([
      { terms: { u: ['a'] } },
    ]));

  it('contains → one wildcard clause per value, specials escaped', () =>
    expect(
      exceptionsToMustNot([{ field: 'p', op: 'contains', values: ['/health', 'a*b?c\\d'] }])
    ).toEqual([
      { wildcard: { p: { value: '*/health*' } } },
      { wildcard: { p: { value: '*a\\*b\\?c\\\\d*' } } },
    ]));

  it('cidr → one term per block (ip fields resolve CIDR natively)', () =>
    expect(
      exceptionsToMustNot([{ field: 's', op: 'cidr', values: ['10.0.0.0/8', '2001:db8::/32'] }])
    ).toEqual([{ term: { s: '10.0.0.0/8' } }, { term: { s: '2001:db8::/32' } }]));

  it('multiple entries flatten into one clause list (must_not = exclude ANY match)', () =>
    expect(
      exceptionsToMustNot([
        { field: 'u', op: 'equals', values: ['svc'] },
        { field: 's', op: 'cidr', values: ['10.0.0.0/8'] },
      ])
    ).toEqual([{ term: { u: 'svc' } }, { term: { s: '10.0.0.0/8' } }]));
});

describe('exceptionsToFilterClause — the ready-to-append bool clause', () => {
  it('null for undefined/empty (callers append nothing)', () => {
    expect(exceptionsToFilterClause(undefined)).toBeNull();
    expect(exceptionsToFilterClause([])).toBeNull();
  });

  it('wraps the must_not clauses in ONE bool clause', () =>
    expect(
      exceptionsToFilterClause([{ field: 'u', op: 'equals', values: ['svc'] }])
    ).toEqual({ bool: { must_not: [{ term: { u: 'svc' } }] } }));
});

describe('ruleHasExceptions / exceptionFieldNames — the Sigma-export warning hooks', () => {
  it('false/[] for rules without exceptions', () => {
    expect(ruleHasExceptions({})).toBe(false);
    expect(ruleHasExceptions({ exceptions: [] })).toBe(false);
    expect(exceptionFieldNames({})).toEqual([]);
  });

  it('true + deduped field names with exceptions', () => {
    const rule = {
      exceptions: [
        { field: 'user.name', op: 'equals' as const, values: ['a'] },
        { field: 'user.name', op: 'contains' as const, values: ['b'] },
        { field: 'source.ip', op: 'cidr' as const, values: ['10.0.0.0/8'] },
      ],
    };
    expect(ruleHasExceptions(rule)).toBe(true);
    expect(exceptionFieldNames(rule)).toEqual(['user.name', 'source.ip']);
  });
});
