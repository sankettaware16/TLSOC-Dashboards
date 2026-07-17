/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Condition, ConditionGroup } from './types';

/**
 * Compile the detection IR to an OpenSearch `query_string` (Lucene syntax). This is the per-document
 * match used inside the doc-level Alerting monitor that actually executes the rule (decision D-008).
 */

/** Escape the two characters that are special inside a quoted phrase. */
function escapePhrase(value: string): string {
  return value.replace(/([\\"])/g, '\\$1');
}

/**
 * Escape Lucene query_string specials (and spaces) in an UNQUOTED wildcard term. We add our own '*'
 * wildcards around the result, so the value's own specials — including '*' and '?' — are escaped.
 */
function escapeTerm(value: string | number): string {
  return String(value).replace(/[+\-&|!(){}[\]^"~*?:\\/ ]/g, '\\$&');
}

/** Escape '/' so a value can sit inside a Lucene `/regex/` literal. */
function escapeRegex(value: string | number): string {
  return String(value).replace(/\//g, '\\/');
}

/** A scalar value: numbers are bare, strings are quoted phrases. */
function luceneValue(value: string | number): string {
  return typeof value === 'number' ? String(value) : `"${escapePhrase(value)}"`;
}

/** Quote a string value as a Lucene phrase, e.g. `union select` → `"union select"`. */
function quotePhrase(value: string | number): string {
  return `"${escapePhrase(String(value))}"`;
}

/**
 * OpenSearch mapping types whose values are analyzed (tokenized) rather than indexed verbatim. A
 * `contains`/`not_contains` on one of these must compile to a quoted phrase (analyzed by the
 * field's analyzer at query time → correct substring/word matching) instead of a `*wildcard*`
 * (which silently matches nothing across analyzer-inserted token boundaries for multi-word values,
 * PROB-4). On keyword/other non-analyzed types the wildcard is kept EXACTLY as before — a phrase
 * there is exact-term equality and would regress today's working substring semantics.
 */
export const ANALYZED_TEXT_TYPES = new Set(['text', 'match_only_text', 'annotated_text']);

/** True when `contains`/`not_contains` on this condition should compile to a quoted phrase. */
function isAnalyzedText(condition: Condition): boolean {
  return !!condition.fieldType && ANALYZED_TEXT_TYPES.has(condition.fieldType);
}

/** Compile a single predicate to a Lucene clause (already including NOT where the operator negates). */
export function conditionToLucene(condition: Condition): string {
  const { field, operator, value, values } = condition;
  switch (operator) {
    case 'equals':
      return `${field}:${luceneValue(value!)}`;
    case 'not_equals':
      return `NOT ${field}:${luceneValue(value!)}`;
    case 'contains':
      return isAnalyzedText(condition)
        ? `${field}:${quotePhrase(value!)}`
        : `${field}:*${escapeTerm(value!)}*`;
    case 'not_contains':
      return isAnalyzedText(condition)
        ? `NOT ${field}:${quotePhrase(value!)}`
        : `NOT ${field}:*${escapeTerm(value!)}*`;
    case 'starts_with':
      return `${field}:${escapeTerm(value!)}*`;
    case 'ends_with':
      return `${field}:*${escapeTerm(value!)}`;
    case 'is_one_of':
      return `(${values!.map((v) => `${field}:${luceneValue(v)}`).join(' OR ')})`;
    case 'is_not_one_of':
      return `NOT (${values!.map((v) => `${field}:${luceneValue(v)}`).join(' OR ')})`;
    case 'exists':
      return `_exists_:${field}`;
    case 'not_exists':
      return `NOT _exists_:${field}`;
    case 'gt':
      return `${field}:>${value!}`;
    case 'gte':
      return `${field}:>=${value!}`;
    case 'lt':
      return `${field}:<${value!}`;
    case 'lte':
      return `${field}:<=${value!}`;
    case 'matches_regex':
      return `${field}:/${escapeRegex(value!)}/`;
    default:
      // A new operator must be handled in BOTH compilers (the D-008 sync requirement).
      throw new Error(`Unsupported detection operator: ${(condition as Condition).operator}`);
  }
}

/** True when the clause is already a single pair of parens enclosing the whole expression. */
function isFullyParenthesized(clause: string): boolean {
  if (!clause.startsWith('(') || !clause.endsWith(')')) {
    return false;
  }
  let depth = 0;
  for (let i = 0; i < clause.length; i++) {
    if (clause[i] === '(') {
      depth++;
    } else if (clause[i] === ')') {
      depth--;
      // The opening paren closed before the end → not a single enclosing group.
      if (depth === 0 && i < clause.length - 1) {
        return false;
      }
    }
  }
  return depth === 0;
}

/** Compile a flat condition group to a single Lucene query_string. */
export function conditionGroupToLucene(group: ConditionGroup): string {
  const clauses = group.conditions.map(conditionToLucene);
  if (clauses.length === 1) {
    return clauses[0];
  }
  const joiner = group.logic === 'AND' ? ' AND ' : ' OR ';
  // Parenthesise each clause for precedence safety, but don't double-wrap one that already is
  // (e.g. an is_one_of clause is emitted as "(a OR b)").
  return clauses
    .map((clause) => (isFullyParenthesized(clause) ? clause : `(${clause})`))
    .join(joiner);
}
