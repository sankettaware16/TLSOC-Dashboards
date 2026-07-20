/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * TLSOC value lists (v1.2.3 D6) — the pure model + validators for indicator lists.
 *
 * A value list is ONE document in the TLSOC-owned cluster index {@link VALUE_LISTS_INDEX}
 * (`_id` = {@link valueListIdFromName}(name), `values` a keyword array) so the document itself is
 * directly usable as an OpenSearch terms-LOOKUP target `{index, id, path: 'values'}` — the shape
 * live-proven for query/bucket monitors (research_r5 §4.1/§4.2). A saved object can never play
 * that role: engine monitors would have to read `.kibana*`, which is contract-forbidden and would
 * force analyst roles to hold `.kibana` read (research_r5 §3.4 — storage decision is final).
 *
 * Everything in this file is side-effect-free and cluster-agnostic: the CRUD routes
 * (server/routes/value_lists.ts), the Threat Intel manager UI, and the indicator-match compilers
 * all validate through THESE functions so a bad list is rejected with the same named reason
 * everywhere.
 */

export type ValueListType = 'keyword' | 'ip';

/** All list types, in canonical order — the reject-by-name source for routes and UI. */
export const VALUE_LIST_TYPES: readonly ValueListType[] = ['keyword', 'ip'];

export function isValidValueListType(type: string): type is ValueListType {
  return (VALUE_LIST_TYPES as readonly string[]).includes(type);
}

/** A value list as the API serves it (the stored doc uses `updated_at`; routes map the casing). */
export interface ValueList {
  /** The list's id — the slug of its name, and the `_id` of its doc (the terms-lookup target id). */
  id: string;
  name: string;
  type: ValueListType;
  values: string[];
  /** ISO-8601 timestamp of the last write. */
  updatedAt: string;
}

/**
 * The TLSOC-owned cluster index value lists live in. Collision-checked against every shipped
 * index-template pattern (`fosstlsoc-logs-*`, `all-logs-*`, `soc-*`) and the ISM delete policy
 * scope (`fosstlsoc-logs-*`) — `tlsoc-` matches none of them (research_r5 §2). NOT a dot-index:
 * the engine executes monitors under the RULE AUTHOR's security context, so rule-author roles
 * must be able to read this index for terms-lookup to resolve at run time (research_r5 §5).
 */
export const VALUE_LISTS_INDEX = 'tlsoc-value-lists';

/**
 * The inline-compile ceiling. A doc-level monitor query is a Lucene `query_string`, and the
 * engine's `indices.query.bool.max_clause_count` (cluster default 1024) caps its OR clauses —
 * with a SILENT failure mode, live-proven on OpenSearch 3.7 (research_r5 §4.2 / RISKS): at
 * exactly 1024 values the query matches; at 1025 it matches NOTHING, with `error: null`
 * everywhere and the run reporting success. A list drifting past the cliff would turn its rule
 * dark with zero signal. So inline mode is hard-capped at 900 (a deliberate safety margin under
 * 1024 — the rule's optional pre-filter and field prefix consume clauses/bytes too), and the
 * compiler REFUSES over-cap input by name rather than truncating: a silently partial indicator
 * list is exactly the class of lie this release bans. Larger lists compile to the bucket-level
 * terms-lookup shape instead (no clause expansion — one lookup clause regardless of size).
 */
export const VALUE_LIST_INLINE_MAX_VALUES = 900;

/**
 * The absolute per-list ceiling: `index.max_terms_count` (engine default 65536) bounds how many
 * values a terms/terms-lookup query may carry — enforced against the DATA index and applied to
 * lookup-fetched values, failing the monitor run LOUDLY when exceeded (research_r5 §3.1). Lists
 * are refused at this size rather than letting every future run of every rule on them error.
 */
export const VALUE_LIST_MAX_VALUES = 65536;

/** Display-name length cap (the id/slug derives from the name; keep both sane). */
export const VALUE_LIST_MAX_NAME_LENGTH = 100;

/** Per-value length cap — far under Lucene's term-size limit, generous for any real indicator. */
export const VALUE_LIST_MAX_VALUE_LENGTH = 1024;

/**
 * Derive the list id (= its doc `_id`) from the display name: lowercase [a-z0-9_], same character
 * discipline as the detection compilers' `slugify` (common/detection/internal.ts) but WITHOUT its
 * non-empty fallback — a name with no alphanumerics must be rejected by name, not silently mapped
 * to a shared catch-all id.
 */
export function valueListIdFromName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

/** Validate a list name; throws with a user-facing message. */
export function assertValidValueListName(name: string): void {
  if (typeof name !== 'string' || name.trim() === '') {
    throw new Error('Value list must have a non-empty name.');
  }
  if (name.trim().length > VALUE_LIST_MAX_NAME_LENGTH) {
    throw new Error(
      `Value list name is too long (${name.trim().length} characters; max ` +
        `${VALUE_LIST_MAX_NAME_LENGTH}).`
    );
  }
  if (valueListIdFromName(name) === '') {
    throw new Error(
      `Value list name "${name.trim()}" must contain at least one letter or digit — the name ` +
        'derives the list id.'
    );
  }
}

/** One IPv4 address, strict: 4 dot-separated decimal octets 0-255, no leading zeros. */
function isValidIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every(
    (part) =>
      /^\d{1,3}$/.test(part) && Number(part) <= 255 && (part.length === 1 || part[0] !== '0')
  );
}

/**
 * One IPv6 address: 8 hex groups of 1-4 digits, at most one `::` compression (which must stand
 * for at least one zero group), optional embedded IPv4 tail (`::ffff:10.0.0.1`) counting as two
 * groups.
 */
function isValidIpv6(value: string): boolean {
  if (value === '::') return true;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const compressed = halves.length === 2;
  const head = halves[0] === '' ? [] : halves[0].split(':');
  const tail = compressed && halves[1] !== '' ? halves[1].split(':') : [];
  const groups = compressed ? [...head, ...tail] : head;
  if (groups.length === 0 && !compressed) return false;
  let groupCount = 0;
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i];
    if (i === groups.length - 1 && group.includes('.')) {
      if (!isValidIpv4(group)) return false;
      groupCount += 2;
      continue;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return false;
    groupCount += 1;
  }
  return compressed ? groupCount < 8 : groupCount === 8;
}

/**
 * Is `value` a single IP address or CIDR block (v4 or v6)? CIDR values are FULLY supported at
 * execution: `term`/`terms`/terms-LOOKUP against an `ip`-mapped field all match CIDR strings
 * correctly, and the doc-level Lucene path matches them QUOTED — every case live-proven
 * (research_r5 §4.3). The complementary requirement — that the rule's event field really is
 * ip-mapped — is the save route's field_caps gate, not this syntax check.
 */
export function isValidIpOrCidr(value: string): boolean {
  const slash = value.indexOf('/');
  if (slash === -1) return isValidIpv4(value) || isValidIpv6(value);
  const ip = value.slice(0, slash);
  const prefixPart = value.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixPart)) return false;
  const prefix = Number(prefixPart);
  if (isValidIpv4(ip)) return prefix <= 32;
  if (isValidIpv6(ip)) return prefix <= 128;
  return false;
}

/** One rejected value, positionally addressed so the UI can mark the exact line. */
export interface ValueListValueError {
  /** 0-based index into the values array (line number − 1 in the editor textarea). */
  index: number;
  value: string;
  reason: string;
}

/**
 * Validate every value of a list against its type. Returns ALL errors (empty array = valid) so
 * the editor can flag every bad line at once; {@link assertValidValueListInput} turns the first
 * few into a thrown message for the routes.
 */
export function validateValueListValues(
  type: ValueListType,
  values: string[]
): ValueListValueError[] {
  const errors: ValueListValueError[] = [];
  const seen = new Set<string>();
  values.forEach((value, index) => {
    if (typeof value !== 'string' || value.trim() === '') {
      errors.push({ index, value: String(value), reason: 'empty values are not allowed' });
      return;
    }
    if (value !== value.trim()) {
      errors.push({ index, value, reason: 'leading/trailing whitespace is not allowed' });
      return;
    }
    if (value.length > VALUE_LIST_MAX_VALUE_LENGTH) {
      errors.push({
        index,
        value: `${value.slice(0, 40)}…`,
        reason: `value is too long (${value.length} characters; max ${VALUE_LIST_MAX_VALUE_LENGTH})`,
      });
      return;
    }
    if (seen.has(value)) {
      errors.push({ index, value, reason: 'duplicate value' });
      return;
    }
    seen.add(value);
    if (type === 'ip' && !isValidIpOrCidr(value)) {
      errors.push({ index, value, reason: 'not a valid IP address or CIDR block' });
    }
  });
  return errors;
}

/** How many per-value errors a thrown message names before eliding the rest. */
const THROWN_ERROR_LINES = 5;

/**
 * Validate a complete create/update input; throws with a user-facing message naming what is
 * wrong (never a partial acceptance — the routes reject the whole write).
 */
export function assertValidValueListInput(input: {
  name: string;
  type: ValueListType;
  values: string[];
}): void {
  assertValidValueListName(input.name);
  if (!isValidValueListType(input.type)) {
    throw new Error(
      `Unknown value list type "${String(input.type)}". Supported: ${VALUE_LIST_TYPES.join(', ')}.`
    );
  }
  if (!Array.isArray(input.values) || input.values.length === 0) {
    throw new Error('Value list must contain at least one value.');
  }
  if (input.values.length > VALUE_LIST_MAX_VALUES) {
    throw new Error(
      `Value list has ${input.values.length} values — the maximum is ${VALUE_LIST_MAX_VALUES} ` +
        '(the engine refuses larger terms lookups at every monitor run).'
    );
  }
  const errors = validateValueListValues(input.type, input.values);
  if (errors.length > 0) {
    const shown = errors
      .slice(0, THROWN_ERROR_LINES)
      .map((e) => `line ${e.index + 1} ("${e.value}"): ${e.reason}`);
    const more = errors.length > THROWN_ERROR_LINES ? `; and ${errors.length - THROWN_ERROR_LINES} more` : '';
    throw new Error(`Value list has invalid values — ${shown.join('; ')}${more}.`);
  }
}

/**
 * Parse raw textarea/file text into a values array: one value per line, trimmed, empty lines
 * dropped, duplicates removed (first occurrence wins) — so a pasted feed export never trips the
 * duplicate validator. The editors call this before validating/submitting.
 */
export function parseValueLines(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const value = line.trim();
    if (value === '' || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}
