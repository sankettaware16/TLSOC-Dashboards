/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  DqlTranslationError,
  formatDqlTranslationErrors,
  translateDqlToLucene,
} from './dql_to_lucene';

/** Golden helper: assert a DQL expression translates to EXACTLY the pinned Lucene string. */
function expectLucene(dql: string, lucene: string) {
  const result = translateDqlToLucene(dql);
  if (!result.ok) {
    throw new Error(
      `expected "${dql}" to translate, got rejection:\n${formatDqlTranslationErrors(result.errors)}`
    );
  }
  expect(result.lucene).toBe(lucene);
}

/** Rejection helper: assert failure and return the named errors for pinning. */
function expectRejected(dql: string): DqlTranslationError[] {
  const result = translateDqlToLucene(dql);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error(`expected "${dql}" to be rejected`);
  expect(result.errors.length).toBeGreaterThan(0);
  return result.errors;
}

describe('translateDqlToLucene — terms and phrases', () => {
  it('unquoted single-token string → bare term', () =>
    expectLucene('event.outcome:failure', 'event.outcome:failure'));

  it('quoted value → quoted phrase', () =>
    expectLucene('event.outcome:"failure"', 'event.outcome:"failure"'));

  it('number value stays bare', () => expectLucene('status:400', 'status:400'));

  it('quoted number stays a phrase (the analyst asked for a string)', () =>
    expectLucene('status:"400"', 'status:"400"'));

  it('decimal shorthand is number-coerced by the DQL grammar (.5 → 0.5)', () =>
    expectLucene('ratio:.5', 'ratio:0.5'));

  it('negative number', () => expectLucene('temp:-5', 'temp:-5'));

  it('boolean values stay bare', () => {
    expectLucene('enabled:true', 'enabled:true');
    expectLucene('enabled:false', 'enabled:false');
  });

  it('beyond-MAX_SAFE_INTEGER values survive via the grammar’s BigInt coercion', () =>
    expectLucene('id:9007199254740993', 'id:9007199254740993'));

  it('spaces around the colon are cosmetic', () => expectLucene('f : v', 'f:v'));

  it('unicode passes through untouched', () => expectLucene('user.name:josé', 'user.name:josé'));

  it('IP-shaped values are strings (not numbers) and need no escaping', () =>
    expectLucene('src.ip:10.0.0.66', 'src.ip:10.0.0.66'));
});

describe('translateDqlToLucene — escaping discipline (the lucene.ts twin)', () => {
  it('phrase: only " and \\ are escaped, and they round-trip', () =>
    expectLucene('msg:"say \\"hi\\" \\\\ back"', 'msg:"say \\"hi\\" \\\\ back"'));

  it('phrase: a * inside quotes is literal, not a wildcard', () =>
    expectLucene('f:"admin*"', 'f:"admin*"'));

  it('term: DQL-escaped specials are re-escaped for Lucene (: and \\)', () =>
    expectLucene('path:C\\:\\\\Windows', 'path:C\\:\\\\Windows'));

  it('term: a DQL-escaped * is a literal char, escaped in the output', () =>
    expectLucene('f:foo\\*bar', 'f:foo\\*bar'));

  it('term: / is legal raw in DQL but reserved in Lucene → escaped', () =>
    expectLucene('url:/api/v1', 'url:\\/api\\/v1'));

  it('term: - is escaped (Lucene NOT-operator shorthand)', () =>
    expectLucene('host:web-01', 'host:web\\-01'));
});

describe('translateDqlToLucene — boolean structure', () => {
  it('AND chains flatten (the peg parses them right-nested)', () =>
    expectLucene('a:1 and b:2 and c:3', '(a:1) AND (b:2) AND (c:3)'));

  it('OR chains flatten', () => expectLucene('a:1 or b:2 or c:3', '(a:1) OR (b:2) OR (c:3)'));

  it('conjunction keywords are case-insensitive', () =>
    expectLucene('a:1 AND b:2', '(a:1) AND (b:2)'));

  it('explicit grouping is preserved: and over (or)', () =>
    expectLucene('a:1 and (b:2 or c:3)', '(a:1) AND ((b:2) OR (c:3))'));

  it('explicit grouping is preserved: (or) before and', () =>
    expectLucene('(a:1 or b:2) and c:3', '((a:1) OR (b:2)) AND (c:3)'));

  it('top-level not on a leaf needs no parens', () =>
    expectLucene('not status:200', 'NOT status:200'));

  it('NOT keyword is case-insensitive', () => expectLucene('NOT status:200', 'NOT status:200'));

  it('not inside a conjunction is parenthesized by the join discipline', () =>
    expectLucene('a:1 and not b:2', '(a:1) AND (NOT b:2)'));

  it('not over a group parenthesizes the group', () =>
    expectLucene('not (a:1 or b:2)', 'NOT ((a:1) OR (b:2))'));

  it('double negation via parens', () => expectLucene('not (not a:1)', 'NOT (NOT a:1)'));
});

describe('translateDqlToLucene — value lists field:(…)', () => {
  it('or-list distributes over the field', () =>
    expectLucene('src.ip:(10.0.0.1 or 10.0.0.2)', '(src.ip:10.0.0.1) OR (src.ip:10.0.0.2)'));

  it('three-way or-list flattens', () =>
    expectLucene('f:(a or b or c)', '(f:a) OR (f:b) OR (f:c)'));

  it('and + not inside a list', () =>
    expectLucene('tags:(a and not b)', '(tags:a) AND (NOT tags:b)'));

  it('quoted values inside a list stay phrases (phrase escaping touches only " and \\)', () =>
    expectLucene('ua:("sqlmap/1.7" or "nikto")', '(ua:"sqlmap/1.7") OR (ua:"nikto")'));
});

describe('translateDqlToLucene — wildcard values', () => {
  it('contains-style *value*', () => expectLucene('url:*admin*', 'url:*admin*'));

  it('prefix wildcard escapes the non-wildcard segment specials', () =>
    expectLucene('host:web-*', 'host:web\\-*'));

  it('interior wildcard', () => expectLucene('f:foo*bar', 'f:foo*bar'));

  it('wildcard value with a space escapes the space per segment', () =>
    expectLucene('title:*admin panel*', 'title:*admin\\ panel*'));
});

describe('translateDqlToLucene — exists (field:*)', () => {
  it('bare * value is exists, in the lucene.ts spelling', () =>
    expectLucene('ua:*', '_exists_:ua'));

  it('negated exists', () => expectLucene('not ua:*', 'NOT _exists_:ua'));
});

describe('translateDqlToLucene — ranges', () => {
  it('gte', () => expectLucene('status >= 400', 'status:>=400'));
  it('gt without spaces', () => expectLucene('status>400', 'status:>400'));
  it('lte', () => expectLucene('status <= 499', 'status:<=499'));
  it('lt', () => expectLucene('bytes < 1000', 'bytes:<1000'));
  it('decimal bound', () => expectLucene('price >= 10.5', 'price:>=10.5'));
  it('string (date) bound rides as a quoted phrase', () =>
    expectLucene('@timestamp < "2026-01-01"', '@timestamp:<"2026-01-01"'));
  it('ranges inside conjunctions', () =>
    expectLucene('status >= 400 and status < 500', '(status:>=400) AND (status:<500)'));
});

describe('translateDqlToLucene — reject-by-name (the PROB-22 discipline)', () => {
  it('nested field group is rejected naming the field, pointing at threshold rules', () => {
    const errors = expectRejected('user:{ first:"bob" and last:"smith" }');
    expect(errors).toHaveLength(1);
    expect(errors[0].construct).toBe('nested query "user:{ … }"');
    expect(errors[0].reason).toContain('no Lucene (doc-level) equivalent');
    expect(errors[0].reason).toContain('threshold rules');
  });

  it('wildcard field name is rejected naming the pattern', () => {
    const errors = expectRejected('machine*:web');
    expect(errors).toHaveLength(1);
    expect(errors[0].construct).toBe('wildcard field name "machine*"');
    expect(errors[0].reason).toContain('threshold rules');
  });

  it('*:* is a wildcard field name too (match-all is not a detection)', () => {
    const errors = expectRejected('*:*');
    expect(errors[0].construct).toBe('wildcard field name "*"');
  });

  it('field-less bare term is rejected naming the term', () => {
    const errors = expectRejected('sqlmap');
    expect(errors).toHaveLength(1);
    expect(errors[0].construct).toBe('field-less term "sqlmap"');
    expect(errors[0].reason).toContain('multi_match');
    expect(errors[0].reason).toContain('threshold rules');
  });

  it('field-less wildcard term is rejected with the * spelled out', () => {
    const errors = expectRejected('*sqlmap*');
    expect(errors[0].construct).toBe('field-less term "*sqlmap*"');
  });

  it('unquoted multi-word value is rejected with both faithful rewrites offered', () => {
    const errors = expectRejected('message:null pointer');
    expect(errors).toHaveLength(1);
    expect(errors[0].construct).toBe('unquoted multi-word value "null pointer"');
    expect(errors[0].reason).toContain('"null pointer"');
    expect(errors[0].reason).toContain('field:(word or word)');
  });

  it('null value is rejected with the missing-field rewrite', () => {
    const errors = expectRejected('f:null');
    expect(errors[0].construct).toBe('value null on "f"');
    expect(errors[0].reason).toContain('not f:*');
  });

  it('empty and whitespace-only queries are rejected by name', () => {
    expect(expectRejected('')[0].construct).toBe('empty query');
    expect(expectRejected('   ')[0].construct).toBe('empty query');
  });

  it('a syntax error is surfaced as one named error with the parser message', () => {
    const errors = expectRejected('status:');
    expect(errors).toHaveLength(1);
    expect(errors[0].construct).toBe('DQL syntax error');
    expect(errors[0].reason).toContain('Expected');
  });

  it('an unbalanced paren is a syntax error', () => {
    expect(expectRejected('(a:1')[0].construct).toBe('DQL syntax error');
  });

  it('ALL unsupported constructs in one query are collected, in walk order', () => {
    const errors = expectRejected('machine*:web or user:{ a:1 }');
    expect(errors.map((e) => e.construct)).toEqual([
      'wildcard field name "machine*"',
      'nested query "user:{ … }"',
    ]);
  });
});

describe('formatDqlTranslationErrors', () => {
  it('joins construct: reason lines — the verbatim compile-throw format', () => {
    expect(
      formatDqlTranslationErrors([
        { construct: 'a', reason: 'b.' },
        { construct: 'c', reason: 'd.' },
      ])
    ).toBe('a: b.\nc: d.');
  });

  it('round-trips a real rejection', () => {
    const result = translateDqlToLucene('sqlmap');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const msg = formatDqlTranslationErrors(result.errors);
    expect(msg).toContain('field-less term "sqlmap": ');
  });
});

describe('translateDqlToLucene — realistic SOC compositions (goldens)', () => {
  it('scanner probe: phrase + wildcard + range', () =>
    expectLucene(
      'source.ip:"10.0.0.66" and user_agent.original:*sqlmap* and http.response.status_code >= 400',
      '(source.ip:"10.0.0.66") AND (user_agent.original:*sqlmap*) AND (http.response.status_code:>=400)'
    ));

  it('admin-probe hunt: wildcard + negation + list', () =>
    expectLucene(
      'url.path:*admin* and not http.response.status_code:200 and src.ip:(10.0.0.1 or 10.0.0.2)',
      '(url.path:*admin*) AND (NOT http.response.status_code:200) AND ((src.ip:10.0.0.1) OR (src.ip:10.0.0.2))'
    ));

  it('exists-guarded phrase match', () =>
    expectLucene(
      'user.name:* and event.action:"logon-failed"',
      '(_exists_:user.name) AND (event.action:"logon-failed")'
    ));
});
