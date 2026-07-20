/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { KueryNode, fromKueryExpression, nodeTypes } from '../../../data/common';

/**
 * DQL (kuery) → Lucene `query_string` translator for D2 custom-query rules (v1.2.3).
 *
 * WHY THIS EXISTS: a custom-query rule executes as a DOC-LEVEL Alerting monitor (the only monitor
 * kind that yields findings + related_doc_ids + per-event alerts — the whole PROB-1/PROB-17
 * enrichment lifecycle), and doc-level `queries[].query` is a Lucene STRING. DQL therefore has to
 * be translated. We walk the KueryNode AST from the in-repo (Apache-2.0) `fromKueryExpression`
 * parser — NEVER the compiled DSL from `toOpenSearchQuery`, which is index-pattern-aware (field
 * wildcard expansion, date-equality → range, scripted fields, auto-nesting) and has no faithful
 * Lucene string form (research_r3 §2 + RISKS).
 *
 * SUPPORTED SUBSET (research_r3 §2): `and`/`or`/`not`, `field:value` (term + quoted phrase),
 * `field:(value lists)`, wildcard VALUES, ranges (`>` `>=` `<` `<=`), and `field:*` exists.
 * Everything else is REJECTED BY NAME (the PROB-22 Sigma-importer discipline) — a silently
 * mangled detection rule is worse than a rejected one. The reject messages note that full DQL is
 * available in threshold rules, where DQL compiles natively to bool DSL with zero translation.
 *
 * DELIBERATE DECISION — unquoted multi-word values are REJECTED, not phrased: DQL's unquoted
 * `field:null pointer` is a `match` (tokens independently, any order, on analyzed text) while a
 * translated Lucene phrase `field:"null pointer"` silently REQUIRES adjacency and order. Whether
 * they diverge depends on the field's mapping, which a pure translator cannot see — so we refuse
 * and tell the analyst the two faithful spellings (quote it, or split into a value list). See the
 * research_r3 RISKS entry on analyzed-text semantics.
 *
 * Escaping replicates common/detection/lucene.ts (the proven no-code compiler twin) — its helpers
 * are module-private, so they are mirrored here with pointers back at the originals.
 */

/** One rejected construct — always NAMED exactly, never a vague failure. */
export interface DqlTranslationError {
  construct: string;
  reason: string;
}

export type DqlToLuceneResult =
  | { ok: true; lucene: string }
  | { ok: false; errors: DqlTranslationError[] };

/**
 * The canonical one-string form of a translation failure — thrown VERBATIM by
 * `compileCustomQueryToMonitor` and returned as the `_validate` route's `reason`, so the compile
 * error, the save-path 400, and the editor's inline message can never drift apart.
 */
export function formatDqlTranslationErrors(errors: DqlTranslationError[]): string {
  return errors.map((e) => `${e.construct}: ${e.reason}`).join('\n');
}

/** The note appended to rejects that DO have a home elsewhere in TLSOC (research_r3 option c). */
const THRESHOLD_NOTE = 'Full DQL is available in threshold rules.';

// ----------------------------------------------------------------------------------------------
// Escaping — mirrors common/detection/lucene.ts (escapePhrase / escapeTerm are private there).
// ----------------------------------------------------------------------------------------------

/** Twin of lucene.ts `escapePhrase`: the two characters special inside a quoted phrase. */
function escapePhrase(value: string): string {
  return value.replace(/([\\"])/g, '\\$1');
}

/** Twin of lucene.ts `escapeTerm`: Lucene query_string specials (and spaces) in an unquoted term. */
function escapeTerm(value: string | number | bigint | boolean): string {
  return String(value).replace(/[+\-&|!(){}[\]^"~*?:\\/ ]/g, '\\$&');
}

/** Twin of lucene.ts `isFullyParenthesized`: one pair of parens enclosing the whole expression. */
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
      if (depth === 0 && i < clause.length - 1) {
        return false;
      }
    }
  }
  return depth === 0;
}

/** Wrap an emitted clause in parens unless it already is one enclosed group (lucene.ts idiom). */
function parenthesize(clause: string): string {
  return isFullyParenthesized(clause) ? clause : `(${clause})`;
}

// ----------------------------------------------------------------------------------------------
// AST access — the node shapes produced by kuery.peg (see the grammar for each rule).
// ----------------------------------------------------------------------------------------------

/** The parser's internal wildcard marker (node_types/wildcard.ts) — segments are joined by it. */
const WILDCARD_SYMBOL = nodeTypes.wildcard.wildcardSymbol;

interface LiteralNode {
  type: 'literal';
  value: null | boolean | number | bigint | string;
}
interface WildcardNode {
  type: 'wildcard';
  value: string;
}

function isLiteral(node: KueryNode | undefined): node is KueryNode & LiteralNode {
  return !!node && node.type === 'literal';
}
function isWildcard(node: KueryNode | undefined): node is KueryNode & WildcardNode {
  return !!node && node.type === 'wildcard';
}

/** A wildcard node's user-facing text (segments re-joined with '*'), for messages. */
function wildcardText(node: WildcardNode): string {
  return node.value.split(WILDCARD_SYMBOL).join('*');
}

/** A wildcard node as an ESCAPED Lucene wildcard term: specials escaped per segment, '*' kept. */
function wildcardToLucene(node: WildcardNode): string {
  return node.value.split(WILDCARD_SYMBOL).map(escapeTerm).join('*');
}

/** True when a wildcard VALUE is exactly one bare '*' — DQL's exists idiom (is.ts:111). */
function isBareWildcard(node: WildcardNode): boolean {
  return node.value === WILDCARD_SYMBOL;
}

// ----------------------------------------------------------------------------------------------
// The walker.
// ----------------------------------------------------------------------------------------------

class Rejections {
  errors: DqlTranslationError[] = [];
  add(construct: string, reason: string): string {
    this.errors.push({ construct, reason });
    return ''; // placeholder — the caller discards the whole result when errors exist
  }
}

/** Flatten right-nested binary and/or chains (the peg emits `a and b and c` as and(a, and(b,c))). */
function flattenSameOp(op: string, node: KueryNode): KueryNode[] {
  const args: KueryNode[] = node.arguments ?? [];
  return args.reduce<KueryNode[]>((acc, child) => {
    if (child?.type === 'function' && child.function === op) {
      return [...acc, ...flattenSameOp(op, child)];
    }
    return [...acc, child];
  }, []);
}

function emitField(fieldArg: KueryNode, rej: Rejections): string | null {
  if (isWildcard(fieldArg)) {
    const pattern = wildcardText(fieldArg);
    rej.add(
      `wildcard field name "${pattern}"`,
      'a wildcard in the FIELD position expands against a data view’s field list and has no ' +
        `single Lucene translation — name one concrete field. ${THRESHOLD_NOTE}`
    );
    return null;
  }
  if (isLiteral(fieldArg) && fieldArg.value !== null) {
    return escapeTerm(fieldArg.value as string | number | bigint | boolean);
  }
  return null; // literal null = field-less — the caller rejects with the value text
}

function emitIs(node: KueryNode, rej: Rejections): string {
  const [fieldArg, valueArg] = node.arguments ?? [];
  const isPhrase = isLiteral(node.arguments?.[2]) && node.arguments[2].value === true;

  // Field-less bare term (`sqlmap`) — DQL compiles it to multi_match over every field.
  if (isLiteral(fieldArg) && fieldArg.value === null) {
    const text = isWildcard(valueArg)
      ? wildcardText(valueArg)
      : String(isLiteral(valueArg) ? valueArg.value : valueArg);
    return rej.add(
      `field-less term "${text}"`,
      'a bare term searches every field (multi_match), which has no faithful Lucene twin — ' +
        `qualify it with a field, e.g. some.field:${text}. ${THRESHOLD_NOTE}`
    );
  }

  const field = emitField(fieldArg, rej);
  if (field === null) return '';

  if (isWildcard(valueArg)) {
    // `field:*` is DQL's exists — emit lucene.ts's exists spelling for twin consistency.
    if (isBareWildcard(valueArg)) return `_exists_:${field}`;
    return `${field}:${wildcardToLucene(valueArg)}`;
  }

  if (!isLiteral(valueArg)) {
    return rej.add(
      'non-literal value',
      'only literal, quoted-phrase, and wildcard values are supported in custom-query rules.'
    );
  }

  const { value } = valueArg;
  if (value === null) {
    return rej.add(
      `value null on "${field}"`,
      `"null" has no Lucene form — use "not ${field}:*" to match documents missing the field.`
    );
  }
  if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean') {
    return `${field}:${String(value)}`;
  }
  if (isPhrase) {
    return `${field}:"${escapePhrase(value)}"`;
  }
  // Unquoted string. Multi-word ones are match (OR-of-tokens) in DQL — refuse to silently tighten
  // them into a phrase (see the file docblock for the full reasoning).
  if (/\s/.test(value)) {
    return rej.add(
      `unquoted multi-word value "${value}"`,
      'DQL matches the words of an unquoted value independently, but a translated Lucene phrase ' +
        `would silently require them adjacent and in order — quote it ("${value}") for an ` +
        'exact phrase, or split it into field:(word or word) to match any word.'
    );
  }
  return `${field}:${escapeTerm(value)}`;
}

function emitRange(node: KueryNode, rej: Rejections): string {
  const [fieldArg, ...args] = node.arguments ?? [];
  const field = emitField(fieldArg, rej);
  if (field === null) {
    if (isLiteral(fieldArg) && fieldArg.value === null) {
      rej.add('field-less range', 'a range comparison needs a field on its left side.');
    }
    return '';
  }

  const OP_TEXT: Record<string, string> = { gt: '>', gte: '>=', lt: '<', lte: '<=' };
  const named = args.find((a: KueryNode) => a?.type === 'namedArg' && OP_TEXT[a.name]);
  if (!named) {
    return rej.add('range', 'unrecognized range operator (only > >= < <= are supported).');
  }
  const valueNode = named.value as KueryNode;
  const value = isLiteral(valueNode) ? valueNode.value : undefined;
  if (typeof value === 'number' || typeof value === 'bigint') {
    return `${field}:${OP_TEXT[named.name]}${String(value)}`;
  }
  if (typeof value === 'string') {
    // Dates and other string bounds ride as a quoted phrase after the operator.
    return `${field}:${OP_TEXT[named.name]}"${escapePhrase(value)}"`;
  }
  return rej.add(
    `range value on "${field}"`,
    'range comparisons support number and string (date) bounds only.'
  );
}

function emit(node: KueryNode, rej: Rejections): string {
  if (!node || node.type !== 'function') {
    rej.add('DQL construct', 'unrecognized query fragment — not in the supported subset.');
    return '';
  }
  switch (node.function) {
    case 'and':
    case 'or': {
      const joiner = node.function === 'and' ? ' AND ' : ' OR ';
      return flattenSameOp(node.function, node)
        .map((child) => parenthesize(emit(child, rej)))
        .join(joiner);
    }
    case 'not': {
      const child: KueryNode = node.arguments?.[0];
      const inner = emit(child, rej);
      const composite =
        child?.type === 'function' &&
        (child.function === 'and' || child.function === 'or' || child.function === 'not');
      return composite ? `NOT (${inner})` : `NOT ${inner}`;
    }
    case 'is':
      return emitIs(node, rej);
    case 'range':
      return emitRange(node, rej);
    case 'exists': {
      // Unreachable from typed DQL (exists is `field:*`), but a programmatic node is well-defined.
      const field = emitField(node.arguments?.[0], rej);
      return field === null ? '' : `_exists_:${field}`;
    }
    case 'nested': {
      const fieldArg = node.arguments?.[0];
      const fieldText = isLiteral(fieldArg)
        ? String(fieldArg.value)
        : isWildcard(fieldArg)
        ? wildcardText(fieldArg)
        : 'field';
      return rej.add(
        `nested query "${fieldText}:{ … }"`,
        'nested field groups have no Lucene (doc-level) equivalent. ' +
          `${THRESHOLD_NOTE.replace('Full DQL', 'Full DQL, including nested queries,')}`
      );
    }
    case 'geoBoundingBox':
    case 'geoPolygon':
      return rej.add(
        `geo query "${node.function}"`,
        'geo queries are not supported in custom-query rules.'
      );
    default:
      return rej.add(
        `DQL construct "${String(node.function)}"`,
        'not in the supported subset (and/or/not, field:value, field:(value lists), ' +
          'wildcard values, ranges, field:* exists).'
      );
  }
}

/**
 * Translate a DQL (kuery) expression to a Lucene `query_string` string, or reject — BY NAME — any
 * construct outside the supported subset. Pure and cluster-free: syntax errors come from the
 * in-repo PEG parser, subset rejections from the AST walk. Never throws.
 */
export function translateDqlToLucene(queryText: string): DqlToLuceneResult {
  if (typeof queryText !== 'string' || queryText.trim() === '') {
    return {
      ok: false,
      errors: [{ construct: 'empty query', reason: 'type a DQL query first.' }],
    };
  }

  let root: KueryNode;
  try {
    root = fromKueryExpression(queryText);
  } catch (err) {
    return {
      ok: false,
      errors: [
        {
          construct: 'DQL syntax error',
          reason: (err as Error).message ?? String(err),
        },
      ],
    };
  }

  const rej = new Rejections();
  const lucene = emit(root, rej);
  if (rej.errors.length > 0) {
    return { ok: false, errors: rej.errors };
  }
  return { ok: true, lucene };
}
