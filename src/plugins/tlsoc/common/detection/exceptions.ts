/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Condition } from './types';
import { conditionToLucene } from './lucene';

/**
 * The D9 exception-list module (v1.2.3 W4b) — the ONE place a rule's exceptions ("never alert
 * when …") are validated and compiled. Exceptions live on `RuleMetadataFields.exceptions`, so
 * EVERY rule type carries them (additive, unmapped SO `rule` attribute — zero migration), and
 * every compiler applies them through exactly one of the TWO pure emitters here:
 *
 * - {@link exceptionsToLucene} / {@link applyExceptionsToLucene} — a ` AND NOT (…)` fragment for
 *   the DOC-level compilers (stateless, custom_query, indicator_match inline). Value escaping is
 *   delegated to lucene.ts's conditionToLucene, so exception clauses escape byte-identically to
 *   condition clauses. CIDR blocks ride as QUOTED phrases (`src:"10.0.0.0/8"`) — the doc-level
 *   syntax proven live against ip fields (research_r5 §4.3); unquoted, the '/' would start a
 *   Lucene regex literal.
 *
 * - {@link exceptionsToMustNot} / {@link exceptionsToFilterClause} — structured `bool.must_not`
 *   clauses for the BUCKET compilers (stateful legacy + aggregation, ppl, new_terms,
 *   indicator_match lookup, and the D9 doc→bucket suppression conversions). Emitted as ONE
 *   `{bool: {must_not: […]}}` clause appended to the input's `bool.filter` array — semantically
 *   identical to a top-level `must_not`, and uniform across all five bucket paths (one emitted
 *   shape, one test surface).
 *
 * Semantics (both emitters, identical by construction): an event matching ANY exception entry is
 * excluded. Within one entry, ANY of its `values` matches (an exception list is an OR of ORs).
 *
 * BYTE-IDENTITY CONTRACT: for a rule with `exceptions` absent OR `[]`, every helper here is a
 * no-op (`''` / `null` / query returned untouched) — rules without exceptions compile
 * byte-identically to pre-D9 output (the goldens' guarantee; pinned per compiler).
 */

/** The exception operator set. Deliberately small — each op has ONE proven compile shape per
 * target. `cidr` requires ip-mapped fields (a CIDR against keyword matches nothing — the editor
 * says so; the value itself is validated here). */
export type ExceptionOp = 'equals' | 'is_one_of' | 'contains' | 'cidr';

/** One "never alert when …" predicate. `values` is ALWAYS a list — for every op the exception
 * matches when the field matches ANY of the values. */
export interface ExceptionEntry {
  field: string;
  op: ExceptionOp;
  values: string[];
}

/** Runtime mirror of the {@link ExceptionOp} union, for reject-by-name validation. */
const EXCEPTION_OPS: ReadonlySet<string> = new Set(['equals', 'is_one_of', 'contains', 'cidr']);

/**
 * Hard cap on exception entries per rule. Every entry becomes a query clause on every run; past
 * ~50 the rule is a value list wearing a trench coat — use an indicator-match exclusion list
 * instead (and doc-level queries hit the engine's silent 1024-clause cliff eventually).
 */
export const MAX_EXCEPTION_ENTRIES = 50;

/** Is `addr` a textual IPv6 address (RFC 4291 forms; no embedded-IPv4 mixing)? */
function isValidIpv6Address(addr: string): boolean {
  if (addr === '::') return true;
  const halves = addr.split('::');
  if (halves.length > 2) return false;
  const groupsOf = (s: string): string[] => (s === '' ? [] : s.split(':'));
  const groups = [...groupsOf(halves[0]), ...(halves.length === 2 ? groupsOf(halves[1]) : [])];
  if (groups.length === 0) return false;
  if (!groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  // '::' stands for at least one zero group; without it all eight must be spelled out.
  return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
}

/** Is `value` a valid CIDR block — IPv4 `a.b.c.d/0-32` or IPv6 `…::…/0-128`? */
export function isValidCidr(value: string): boolean {
  const parts = value.split('/');
  if (parts.length !== 2) return false;
  const [addr, prefixStr] = parts;
  if (!/^\d{1,3}$/.test(prefixStr)) return false;
  const prefix = Number(prefixStr);
  if (addr.includes(':')) {
    return prefix <= 128 && isValidIpv6Address(addr);
  }
  if (prefix > 32) return false;
  const octets = addr.split('.');
  return (
    octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)
  );
}

/**
 * Validate an exceptions list before compiling; throws with a clear, user-facing message
 * (reject-by-name — the release-wide discipline). `ruleLabel` is the caller's own rule prefix
 * (e.g. `Detection rule "X"`), so every validator's exception errors read identically.
 * An EMPTY array is valid (it means "no exceptions" and compiles as a no-op).
 */
export function validateExceptions(exceptions: unknown, ruleLabel: string): void {
  if (!Array.isArray(exceptions)) {
    throw new Error(`${ruleLabel}: exceptions must be a list of exception entries.`);
  }
  if (exceptions.length > MAX_EXCEPTION_ENTRIES) {
    throw new Error(
      `${ruleLabel}: ${exceptions.length} exception entries — over the ` +
        `${MAX_EXCEPTION_ENTRIES}-entry cap. Consolidate values into one "is one of" entry, ` +
        'or use an indicator-match value list for large exclusion sets.'
    );
  }
  exceptions.forEach((entry: ExceptionEntry, i: number) => {
    const where = `${ruleLabel}: exception ${i + 1}`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`${where} is malformed — each exception needs a field, an operator, and values.`);
    }
    if (typeof entry.field !== 'string' || entry.field.trim() === '') {
      throw new Error(`${where}: a field is required.`);
    }
    if (!EXCEPTION_OPS.has(entry.op)) {
      throw new Error(
        `${where} ("${entry.field}") has unknown operator "${String(entry.op)}". ` +
          'Supported: equals, is_one_of, contains, cidr.'
      );
    }
    if (!Array.isArray(entry.values) || entry.values.length === 0) {
      throw new Error(
        `${where} ("${entry.field}") must list at least one value — an empty exception can ` +
          'never match anything.'
      );
    }
    entry.values.forEach((value, j) => {
      if (typeof value !== 'string' || value.trim() === '') {
        throw new Error(`${where} ("${entry.field}"): value ${j + 1} is empty.`);
      }
      if (entry.op === 'cidr' && !isValidCidr(value)) {
        throw new Error(
          `${where} ("${entry.field}"): "${value}" is not a valid CIDR block ` +
            '(expected e.g. 10.0.0.0/8 or 2001:db8::/32).'
        );
      }
    });
  });
}

/** Build the lucene.ts Condition(s) equivalent of one exception entry (escaping delegation). */
function entryToLuceneClause(entry: ExceptionEntry): string {
  const asCondition = (operator: Condition['operator'], value?: string): Condition =>
    value === undefined
      ? { field: entry.field, operator, values: entry.values }
      : { field: entry.field, operator, value };
  switch (entry.op) {
    case 'equals':
    case 'cidr':
      // Both compile to quoted phrases (strings quote via luceneValue) — the proven CIDR form.
      return entry.values.length === 1
        ? conditionToLucene(asCondition('equals', entry.values[0]))
        : conditionToLucene(asCondition('is_one_of'));
    case 'is_one_of':
      return conditionToLucene(asCondition('is_one_of'));
    case 'contains': {
      // No fieldType is carried on exceptions, so `contains` compiles to the substring wildcard
      // (the legacy pre-fieldType behavior) — correct for keyword fields, and the editor's copy
      // steers analyzed-text exclusions toward `equals`.
      const clauses = entry.values.map((value) =>
        conditionToLucene(asCondition('contains', value))
      );
      return clauses.length === 1 ? clauses[0] : `(${clauses.join(' OR ')})`;
    }
  }
}

/**
 * The doc-level fragment: ` AND NOT (exc1 OR exc2 …)` — appended to a (parenthesized) query
 * string by {@link applyExceptionsToLucene}. `''` for no entries (the byte-identity contract).
 */
export function exceptionsToLucene(entries: ExceptionEntry[] | undefined): string {
  if (!entries || entries.length === 0) {
    return '';
  }
  return ` AND NOT (${entries.map(entryToLuceneClause).join(' OR ')})`;
}

/**
 * Apply exceptions to a compiled doc-level query string. WITHOUT entries the query is returned
 * UNTOUCHED (byte identity); WITH entries the base query is parenthesized first — it may contain
 * a top-level OR, and Lucene's AND binds tighter, so `a OR b AND NOT exc` would silently rebind.
 */
export function applyExceptionsToLucene(
  query: string,
  entries: ExceptionEntry[] | undefined
): string {
  const fragment = exceptionsToLucene(entries);
  return fragment === '' ? query : `(${query})${fragment}`;
}

/** Escape a value for use inside a Query-DSL `wildcard` pattern (its `*`/`?`/`\` are literal). */
function escapeDslWildcard(value: string): string {
  return value.replace(/([\\*?])/g, '\\$1');
}

/**
 * The bucket-side emission: one must_not clause per entry (per value for `contains`/`cidr`).
 * A doc matching ANY clause in a `must_not` list is excluded — exactly the exception semantics.
 * Shapes: term (equals, single) / terms (equals multi, is_one_of) / wildcard (contains) /
 * cidr-term (a term query with the CIDR string — ip fields resolve CIDR blocks natively, the
 * same engine behavior the terms-lookup probes rode; research_r5 §4.3).
 */
export function exceptionsToMustNot(
  entries: ExceptionEntry[] | undefined
): Array<Record<string, unknown>> {
  if (!entries || entries.length === 0) {
    return [];
  }
  const clauses: Array<Record<string, unknown>> = [];
  for (const entry of entries) {
    switch (entry.op) {
      case 'equals':
      case 'is_one_of':
        clauses.push(
          entry.values.length === 1 && entry.op === 'equals'
            ? { term: { [entry.field]: entry.values[0] } }
            : { terms: { [entry.field]: [...entry.values] } }
        );
        break;
      case 'contains':
        entry.values.forEach((value) =>
          clauses.push({
            wildcard: { [entry.field]: { value: `*${escapeDslWildcard(value)}*` } },
          })
        );
        break;
      case 'cidr':
        // One term per block: `terms` with CIDR strings is unproven; per-block `term` is the
        // engine-native ip-range form.
        entry.values.forEach((value) => clauses.push({ term: { [entry.field]: value } }));
        break;
    }
  }
  return clauses;
}

/**
 * The must_not clauses wrapped as ONE ready-to-append bool.filter clause:
 * `{bool: {must_not: […]}}` — what every bucket compiler pushes onto its filter array.
 * `null` for no entries (callers append nothing — the byte-identity contract).
 */
export function exceptionsToFilterClause(
  entries: ExceptionEntry[] | undefined
): Record<string, unknown> | null {
  const mustNot = exceptionsToMustNot(entries);
  return mustNot.length === 0 ? null : { bool: { must_not: mustNot } };
}

/** Does this rule carry any exceptions? The Sigma-export warning hook (exceptions are OMITTED
 * from Sigma output — exporting curated FP-kills as portable detection logic would silently
 * change the rule's meaning; the export surfaces a named warning instead). */
export function ruleHasExceptions(rule: { exceptions?: ExceptionEntry[] }): boolean {
  return Array.isArray(rule.exceptions) && rule.exceptions.length > 0;
}

/** The distinct excepted field names, for naming them in the Sigma-export warning. */
export function exceptionFieldNames(rule: { exceptions?: ExceptionEntry[] }): string[] {
  return [...new Set((rule.exceptions ?? []).map((e) => e.field))];
}
