/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { conditionGroupToLucene, conditionToLucene } from './lucene';
import { Condition } from './types';

const single = (condition: Condition) => conditionToLucene(condition);

describe('conditionToLucene — per operator', () => {
  it('equals (string) → quoted phrase', () => {
    expect(single({ field: 'event.module', operator: 'equals', value: 'ssh' })).toBe(
      'event.module:"ssh"'
    );
  });
  it('equals (number) → bare value', () => {
    expect(single({ field: 'http.response.status_code', operator: 'equals', value: 200 })).toBe(
      'http.response.status_code:200'
    );
  });
  it('not_equals → NOT + quoted', () => {
    expect(single({ field: 'event.module', operator: 'not_equals', value: 'ssh' })).toBe(
      'NOT event.module:"ssh"'
    );
  });
  it('contains → wildcards', () => {
    expect(single({ field: 'url.path', operator: 'contains', value: 'admin' })).toBe(
      'url.path:*admin*'
    );
  });
  it('contains escapes spaces in the term', () => {
    expect(single({ field: 'url.query', operator: 'contains', value: 'union select' })).toBe(
      'url.query:*union\\ select*'
    );
  });
  it('not_contains → NOT + wildcards', () => {
    expect(single({ field: 'url.path', operator: 'not_contains', value: 'health' })).toBe(
      'NOT url.path:*health*'
    );
  });

  describe('contains / not_contains — fieldType-aware compile (PROB-4)', () => {
    it('contains on an analyzed text field (match_only_text) → quoted phrase, multi-word intact', () => {
      expect(
        single({
          field: 'url.query',
          operator: 'contains',
          value: 'union select',
          fieldType: 'match_only_text',
        })
      ).toBe('url.query:"union select"');
    });
    it('contains on a plain "text" field → quoted phrase too (in ANALYZED_TEXT_TYPES)', () => {
      expect(
        single({
          field: 'event.original',
          operator: 'contains',
          value: 'union select',
          fieldType: 'text',
        })
      ).toBe('event.original:"union select"');
    });
    it('not_contains on an analyzed text field → NOT + quoted phrase', () => {
      expect(
        single({
          field: 'url.query',
          operator: 'not_contains',
          value: 'union select',
          fieldType: 'match_only_text',
        })
      ).toBe('NOT url.query:"union select"');
    });
    it('contains on a keyword field → unchanged wildcard (would regress substring matches if quoted)', () => {
      expect(
        single({
          field: 'url.query',
          operator: 'contains',
          value: 'union select',
          fieldType: 'keyword',
        })
      ).toBe('url.query:*union\\ select*');
    });
    it('contains with NO fieldType (legacy rule) → unchanged wildcard', () => {
      expect(single({ field: 'url.query', operator: 'contains', value: 'union select' })).toBe(
        'url.query:*union\\ select*'
      );
    });
    it('not_contains with NO fieldType (legacy rule) → unchanged wildcard', () => {
      expect(single({ field: 'url.path', operator: 'not_contains', value: 'health' })).toBe(
        'NOT url.path:*health*'
      );
    });
    it('contains on an analyzed text field escapes a double-quote and backslash in the value', () => {
      expect(
        single({
          field: 'url.query',
          operator: 'contains',
          value: 'say "hi" \\ bye',
          fieldType: 'match_only_text',
        })
      ).toBe('url.query:"say \\"hi\\" \\\\ bye"');
    });
  });
  it('starts_with escapes the slash in the term', () => {
    expect(single({ field: 'url.path', operator: 'starts_with', value: '/admin' })).toBe(
      'url.path:\\/admin*'
    );
  });
  it('ends_with', () => {
    expect(single({ field: 'url.path', operator: 'ends_with', value: '.php' })).toBe(
      'url.path:*.php'
    );
  });
  it('is_one_of → parenthesised OR group', () => {
    expect(
      single({ field: 'source.ip', operator: 'is_one_of', values: ['10.0.0.5', '10.0.0.6'] })
    ).toBe('(source.ip:"10.0.0.5" OR source.ip:"10.0.0.6")');
  });
  it('is_not_one_of → NOT of the OR group', () => {
    expect(
      single({ field: 'source.ip', operator: 'is_not_one_of', values: ['10.0.0.5', '10.0.0.6'] })
    ).toBe('NOT (source.ip:"10.0.0.5" OR source.ip:"10.0.0.6")');
  });
  it('exists', () => {
    expect(single({ field: 'user.name', operator: 'exists' })).toBe('_exists_:user.name');
  });
  it('not_exists', () => {
    expect(single({ field: 'user.name', operator: 'not_exists' })).toBe('NOT _exists_:user.name');
  });
  it('numeric ranges gt / gte / lt / lte', () => {
    expect(single({ field: 'http.response.status_code', operator: 'gt', value: 500 })).toBe(
      'http.response.status_code:>500'
    );
    expect(single({ field: 'http.response.status_code', operator: 'gte', value: 500 })).toBe(
      'http.response.status_code:>=500'
    );
    expect(single({ field: 'event.severity', operator: 'lt', value: 3 })).toBe(
      'event.severity:<3'
    );
    expect(single({ field: 'event.severity', operator: 'lte', value: 3 })).toBe(
      'event.severity:<=3'
    );
  });
  it('matches_regex escapes the slash so the value sits inside /…/', () => {
    expect(single({ field: 'url.original', operator: 'matches_regex', value: '(?i)etc/passwd' })).toBe(
      'url.original:/(?i)etc\\/passwd/'
    );
  });
});

describe('conditionGroupToLucene — grouping', () => {
  const a: Condition = { field: 'event.outcome', operator: 'equals', value: 'failure' };
  const b: Condition = { field: 'event.module', operator: 'equals', value: 'ssh' };

  it('single condition → no surrounding parens', () => {
    expect(conditionGroupToLucene({ logic: 'AND', conditions: [a] })).toBe(
      'event.outcome:"failure"'
    );
  });
  it('AND wraps each clause in parens', () => {
    expect(conditionGroupToLucene({ logic: 'AND', conditions: [a, b] })).toBe(
      '(event.outcome:"failure") AND (event.module:"ssh")'
    );
  });
  it('OR wraps each clause in parens', () => {
    expect(conditionGroupToLucene({ logic: 'OR', conditions: [a, b] })).toBe(
      '(event.outcome:"failure") OR (event.module:"ssh")'
    );
  });
});
