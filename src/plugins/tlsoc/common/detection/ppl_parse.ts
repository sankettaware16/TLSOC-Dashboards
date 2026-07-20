/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TimeWindow } from './types';

/**
 * TLSOC PPL-subset parser (v1.2.3 D3) — a clean-room modal lexer + recursive-descent parser for
 * the ONLY rule shape the detection subset accepts:
 *
 *   ['search'] source = <index>[, <index>…] (| where <expr>)* | stats <aggs> [by <fields>] [| where <thresholds>]
 *
 * The grammar is research_r4.md §3 EXACTLY (engine-verified against OpenSearch 3.7 Calcite PPL);
 * everything outside it is REJECTED BY NAME (§4) with a position — never silently dropped or
 * approximated — following the sigma_import.ts result discipline: a silently-mangled detection
 * rule is worse than a rejected one. The engine's own parse errors carry no numeric offsets, so
 * THIS parser owns error positions for the editor.
 *
 * Notable subset decisions (all from R4, engine-verified):
 * - The lexer is MODAL: right after `source =` it lexes INDEX_IDENTs (`-`, `*`, `.`, digits
 *   anywhere are index-legal but field-illegal — mirrors the real grammar's tableIdent split).
 * - `==` normalizes to `=`; `c`/`count`/`c()` normalize to count(); `distinct_count` to `dc`.
 * - Multiple pre-stats `where`s fold with AND. `xor` is rejected (undocumented precedence tier).
 * - Post-stats `where` (the HAVING) may reference metrics ONLY through their `as` aliases —
 *   the engine parse-fails on bare `count()` there too.
 * - `.keyword` suffixes are pre-rejected with a helpful message (the engine's own failure is a
 *   bare AssertionError); TLSOC resolves keyword subfields itself at compile (ppl_rule.ts).
 */

// ---------------------------------------------------------------------------------------------
// Result types (research_r4.md §3.3 — the AST contract the lowering consumes).
// ---------------------------------------------------------------------------------------------

export interface PplParseError {
  construct: string;
  reason: string;
  offset: number;
  length: number;
}

export interface PplParseSuccess {
  ok: true;
  rule: PplRuleAst;
  warnings: string[];
}

export interface PplParseFailure {
  ok: false;
  errors: PplParseError[];
}

export type PplParseResult = PplParseSuccess | PplParseFailure;

/** A field reference with its source span [start, end) — offsets into the original query text. */
export interface FieldRef {
  name: string;
  span: [number, number];
}

export type WhereExpr =
  | { kind: 'and' | 'or'; operands: WhereExpr[] }
  | { kind: 'not'; operand: WhereExpr }
  | {
      kind: 'cmp';
      field: FieldRef;
      op: '=' | '!=' | '>' | '>=' | '<' | '<=';
      value: string | number | boolean;
    }
  | { kind: 'like'; field: FieldRef; pattern: string }
  | { kind: 'in'; field: FieldRef; values: Array<string | number> };

export interface MetricAgg {
  /** distinct_count normalized to 'dc'; c/bare-count normalized to 'count'. */
  fn: 'count' | 'dc' | 'sum' | 'avg' | 'min' | 'max';
  /** null only when fn === 'count' with no argument (the bare doc count). */
  field: string | null;
  /** Required (validator-enforced) for any metric referenced in the threshold condition. */
  alias: string | null;
}

/**
 * The parse-level threshold tree. Named Ppl- to avoid colliding with the FROZEN compile-level
 * HavingExpr in agg_types.ts (which uses gt/gte/… ops and buckets_path aliases).
 */
export type PplHavingExpr =
  | { kind: 'and' | 'or'; operands: PplHavingExpr[] }
  | { kind: 'cmp'; metricAlias: string; op: '>' | '>=' | '<' | '<=' | '=' | '!='; value: number };

export interface PplRuleAst {
  /** Raw index patterns from `source =`, order preserved. */
  indices: string[];
  /** Folded AND of all pre-stats wheres; null when the rule has no event filter. */
  where: WhereExpr | null;
  /** At least one (grammar-enforced). */
  metrics: MetricAgg[];
  /** May be empty at PARSE level (single-bucket query); the lowering requires >= 1. */
  by: FieldRef[];
  having: PplHavingExpr | null;
}

// ---------------------------------------------------------------------------------------------
// Reject-by-name vocabulary (research_r4.md §4 — harvested from the 3.7 engine's own grammar).
// ---------------------------------------------------------------------------------------------

/** Input guard mirroring sigma_import.ts MAX_INPUT_CHARS discipline (8 KB is generous for one rule). */
const MAX_PPL_CHARS = 8 * 1024;

/** The full 3.7 PPL command vocabulary outside the subset — each rejected quoting its own name. */
const REJECTED_COMMANDS = new Set([
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
]);

/** Aggregations the engine supports but the subset does not — rejected quoting their own name. */
const REJECTED_AGGS = new Set([
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
]);

/** Reserved words that cannot be bare field names (backtick them to use them as fields). */
const KEYWORDS = new Set([
  'search',
  'source',
  'where',
  'stats',
  'by',
  'as',
  'and',
  'or',
  'not',
  'xor',
  'like',
  'in',
  'true',
  'false',
]);

// ---------------------------------------------------------------------------------------------
// Lexer (modal: 'default' for the command language, 'index' right after `source =`).
// ---------------------------------------------------------------------------------------------

type TokenType =
  | 'pipe'
  | 'comma'
  | 'lparen'
  | 'rparen'
  | 'lbracket'
  | 'rbracket'
  | 'colon'
  | 'op'
  | 'arith'
  | 'word'
  | 'index'
  | 'backtick'
  | 'string'
  | 'number'
  | 'eof';

interface Token {
  type: TokenType;
  /** The raw source text of the token (backtick/string tokens include their delimiters). */
  text: string;
  /** Lower-cased text, for case-insensitive keyword matching. */
  lower: string;
  offset: number;
  length: number;
  /** Parsed numeric value ('number' tokens). */
  num?: number;
  /** Unquoted/unescaped content ('string' and 'backtick' tokens). */
  str?: string;
}

/** Internal parse failure — thrown, caught once at the top, surfaced as PplParseFailure. */
function problem(construct: string, reason: string, offset: number, length: number): Error {
  const err = new Error(`${construct}: ${reason}`);
  (err as { pplProblem?: PplParseError }).pplProblem = { construct, reason, offset, length };
  return err;
}

function problemAt(construct: string, reason: string, tok: Token): Error {
  return problem(construct, reason, tok.offset, tok.length);
}

const isAlpha = (c: string | undefined): boolean => !!c && /[A-Za-z]/.test(c);
const isDigit = (c: string | undefined): boolean => !!c && /[0-9]/.test(c);
const isIdentChar = (c: string | undefined): boolean => !!c && /[A-Za-z0-9_]/.test(c);
const isIndexChar = (c: string | undefined): boolean => !!c && /[A-Za-z0-9_.\-*@]/.test(c);

class Lexer {
  private pos = 0;
  private buf: Token | null = null;
  private mode: 'default' | 'index' = 'default';

  constructor(private readonly input: string) {}

  /** Switch lexing mode. Only legal with an empty lookahead buffer (internal invariant). */
  setMode(mode: 'default' | 'index'): void {
    if (this.buf !== null) {
      throw new Error('ppl_parse internal error: setMode with a buffered token');
    }
    this.mode = mode;
  }

  peek(): Token {
    if (this.buf === null) {
      this.buf = this.lexNext();
    }
    return this.buf;
  }

  next(): Token {
    const t = this.peek();
    this.buf = null;
    return t;
  }

  private lexNext(): Token {
    const s = this.input;
    while (this.pos < s.length && /\s/.test(s[this.pos])) {
      this.pos += 1;
    }
    if (this.pos >= s.length) {
      return { type: 'eof', text: '', lower: '', offset: s.length, length: 0 };
    }
    if (this.mode === 'index') {
      return this.lexIndexMode();
    }
    return this.lexDefault();
  }

  private lexIndexMode(): Token {
    const s = this.input;
    const c = s[this.pos];
    if (c === ',') {
      return this.single('comma');
    }
    if (c === '|') {
      this.mode = 'default';
      return this.single('pipe');
    }
    if (c === ':') {
      return this.single('colon');
    }
    if (c === '`') {
      return this.lexBacktick();
    }
    if (isIndexChar(c)) {
      const start = this.pos;
      while (this.pos < s.length && isIndexChar(s[this.pos])) {
        this.pos += 1;
      }
      const text = s.slice(start, this.pos);
      return { type: 'index', text, lower: text.toLowerCase(), offset: start, length: text.length };
    }
    // Anything index-illegal ends the source list; fall back to the command language.
    this.mode = 'default';
    return this.lexDefault();
  }

  private lexDefault(): Token {
    const s = this.input;
    const c = s[this.pos];
    switch (c) {
      case '|':
        return this.single('pipe');
      case ',':
        return this.single('comma');
      case '(':
        return this.single('lparen');
      case ')':
        return this.single('rparen');
      case '[':
        return this.single('lbracket');
      case ']':
        return this.single('rbracket');
      case ':':
        return this.single('colon');
      case '`':
        return this.lexBacktick();
      case "'":
      case '"':
        return this.lexString();
      case '+':
      case '*':
      case '%':
        return this.single('arith');
      case '/': {
        const nxt = s[this.pos + 1];
        if (nxt === '/' || nxt === '*') {
          throw problem(
            'comment',
            'comments ("//", "/* */") are not supported in detection rules',
            this.pos,
            2
          );
        }
        return this.single('arith');
      }
      default:
        break;
    }
    if (c === '=' || c === '!' || c === '>' || c === '<') {
      return this.lexOp();
    }
    if (isDigit(c) || (c === '-' && isDigit(s[this.pos + 1]))) {
      return this.lexNumber();
    }
    if (c === '-') {
      return this.single('arith');
    }
    if (c === '@' || isAlpha(c)) {
      return this.lexWord();
    }
    throw problem('syntax', `unexpected character "${c}"`, this.pos, 1);
  }

  private single(type: TokenType): Token {
    const text = this.input[this.pos];
    const tok: Token = { type, text, lower: text, offset: this.pos, length: 1 };
    this.pos += 1;
    return tok;
  }

  private lexOp(): Token {
    const s = this.input;
    const start = this.pos;
    const two = s.slice(start, start + 2);
    if (two === '==' || two === '!=' || two === '>=' || two === '<=') {
      this.pos += 2;
      return { type: 'op', text: two, lower: two, offset: start, length: 2 };
    }
    const one = s[start];
    if (one === '>' || one === '<' || one === '=') {
      this.pos += 1;
      return { type: 'op', text: one, lower: one, offset: start, length: 1 };
    }
    throw problem('syntax', `unexpected character "${one}"`, start, 1);
  }

  private lexNumber(): Token {
    const s = this.input;
    const start = this.pos;
    const m = /^-?[0-9]+(\.[0-9]+)?/.exec(s.slice(start));
    const text = m ? m[0] : s[start];
    this.pos = start + text.length;
    return {
      type: 'number',
      text,
      lower: text,
      offset: start,
      length: text.length,
      num: parseFloat(text),
    };
  }

  private lexString(): Token {
    const s = this.input;
    const start = this.pos;
    const quote = s[start];
    let i = start + 1;
    let out = '';
    while (i < s.length) {
      if (s[i] === quote) {
        if (s[i + 1] === quote) {
          // Doubled-quote self-escape ('it''s' / "say ""hi""").
          out += quote;
          i += 2;
          continue;
        }
        i += 1;
        this.pos = i;
        return {
          type: 'string',
          text: s.slice(start, i),
          lower: '',
          str: out,
          offset: start,
          length: i - start,
        };
      }
      out += s[i];
      i += 1;
    }
    throw problem('syntax', 'unterminated string literal', start, s.length - start);
  }

  private lexBacktick(): Token {
    const s = this.input;
    const start = this.pos;
    const end = s.indexOf('`', start + 1);
    if (end === -1) {
      throw problem('syntax', 'unterminated backtick identifier', start, s.length - start);
    }
    const inner = s.slice(start + 1, end);
    if (inner === '') {
      throw problem('syntax', 'empty backtick identifier', start, 2);
    }
    this.pos = end + 1;
    return {
      type: 'backtick',
      text: s.slice(start, end + 1),
      lower: inner.toLowerCase(),
      str: inner,
      offset: start,
      length: end + 1 - start,
    };
  }

  private lexWord(): Token {
    const s = this.input;
    const start = this.pos;
    let i = start;
    if (s[i] === '@') {
      i += 1;
    }
    if (!isAlpha(s[i])) {
      throw problem('syntax', `unexpected character "${s[start]}"`, start, 1);
    }
    while (i < s.length && isIdentChar(s[i])) {
      i += 1;
    }
    // Dotted path segments (struct selectors): source.ip, http.response.status_code, f.keyword.
    while (s[i] === '.' && isAlpha(s[i + 1])) {
      i += 1;
      while (i < s.length && isIdentChar(s[i])) {
        i += 1;
      }
    }
    const text = s.slice(start, i);
    this.pos = i;
    return { type: 'word', text, lower: text.toLowerCase(), offset: start, length: text.length };
  }
}

// ---------------------------------------------------------------------------------------------
// Parser.
// ---------------------------------------------------------------------------------------------

const COMMAND_REJECT_TEMPLATE = (name: string): string =>
  `the "${name}" command is not supported in detection rules — only ` +
  `'source = <index> | where … | stats … by … [| where …]' is accepted`;

/** Parse a PPL detection-subset query. Never throws — every failure is a named, positioned error. */
export function parsePpl(input: string): PplParseResult {
  if (typeof (input as unknown) !== 'string' || input.trim() === '') {
    return {
      ok: false,
      errors: [
        {
          construct: 'syntax',
          reason:
            'the query is empty — a detection rule looks like: ' +
            'source = <index> | where <filters> | stats <metrics> by <fields> [| where <thresholds>]',
          offset: 0,
          length: 0,
        },
      ],
    };
  }
  if (input.length > MAX_PPL_CHARS) {
    return {
      ok: false,
      errors: [
        {
          construct: 'input',
          reason: 'query exceeds the 8 KB limit for a detection rule',
          offset: MAX_PPL_CHARS,
          length: input.length - MAX_PPL_CHARS,
        },
      ],
    };
  }
  try {
    return runParse(input);
  } catch (e) {
    const p = (e as { pplProblem?: PplParseError })?.pplProblem;
    if (p) {
      return { ok: false, errors: [p] };
    }
    throw e;
  }
}

function runParse(input: string): PplParseSuccess {
  const lx = new Lexer(input);
  const warnings: string[] = [];

  // ['search'] source = <index>[, <index>…]
  if (lx.peek().type === 'word' && lx.peek().lower === 'search') {
    lx.next();
  }
  const sourceTok = lx.next();
  if (!(sourceTok.type === 'word' && sourceTok.lower === 'source')) {
    throw problemAt('source', `a detection rule must start with 'source = <index>'`, sourceTok);
  }
  const eqTok = lx.next();
  if (!(eqTok.type === 'op' && eqTok.text === '=')) {
    throw problemAt('source', `expected '=' after 'source'`, eqTok);
  }
  lx.setMode('index');
  const indices: string[] = [];
  let spacedList = false;
  for (;;) {
    const idxTok = lx.next();
    if (idxTok.type === 'index') {
      indices.push(idxTok.text);
    } else if (idxTok.type === 'backtick') {
      indices.push(idxTok.str as string);
    } else {
      throw problemAt('source', `expected an index name after 'source ='`, idxTok);
    }
    if (lx.peek().type === 'colon') {
      throw problemAt(
        'cross-cluster-source',
        'cross-cluster sources ("cluster:index") are not supported in detection rules',
        lx.peek()
      );
    }
    const sep = lx.peek();
    if (sep.type === 'comma') {
      if (sep.offset !== idxTok.offset + idxTok.length) {
        spacedList = true;
      }
      lx.next();
      const following = lx.peek();
      if (following.offset !== sep.offset + 1) {
        spacedList = true;
      }
      continue;
    }
    break;
  }
  if (spacedList) {
    warnings.push(
      'spaces in the multi-index list were removed — PPL expects "source=a,b" with no spaces'
    );
  }

  // Nothing but '|' (or the end) may follow the source list.
  const afterSource = lx.peek();
  if (afterSource.type !== 'pipe' && afterSource.type !== 'eof') {
    if (afterSource.lower === 'earliest' || afterSource.lower === 'latest') {
      const snippetMatch = /^\S+/.exec(input.slice(afterSource.offset));
      const snippet = snippetMatch ? snippetMatch[0] : afterSource.text;
      throw problemAt(
        afterSource.lower,
        `the detection window comes from the rule schedule — remove "${snippet}"`,
        afterSource
      );
    }
    throw problemAt(
      'search-expression',
      'filters must be written in a "| where" clause — bare search expressions after the source are not supported',
      afterSource
    );
  }

  // Command pipeline: (| where)* | stats [| where].
  const wheres: WhereExpr[] = [];
  let stats: { metrics: MetricAgg[]; by: FieldRef[] } | null = null;
  let having: PplHavingExpr | null = null;

  while (lx.peek().type === 'pipe') {
    lx.next();
    const cmd = lx.peek();
    if (cmd.type === 'pipe' || cmd.type === 'eof') {
      throw problemAt('empty-command', 'empty command between pipes', cmd);
    }
    if (cmd.type === 'lbracket') {
      throw problemAt('subsearch', 'subsearches ("[ … ]") are not supported in detection rules', cmd);
    }
    if (cmd.type !== 'word') {
      throw problemAt('command', `expected a command ("where" or "stats") after "|"`, cmd);
    }
    lx.next();
    const name = cmd.lower;
    if (name === 'where') {
      if (stats === null) {
        wheres.push(parseOrExpr(lx));
      } else {
        if (having !== null) {
          throw problemAt('having', 'only one "| where" threshold clause may follow "stats"', cmd);
        }
        having = parseHaving(lx, input, stats.metrics);
      }
    } else if (name === 'stats') {
      if (stats !== null) {
        throw problemAt('stats', 'only one "stats" command is supported in a detection rule', cmd);
      }
      stats = parseStats(lx);
    } else if (REJECTED_COMMANDS.has(name)) {
      throw problemAt(name, COMMAND_REJECT_TEMPLATE(name), cmd);
    } else {
      throw problemAt(
        'command',
        `"${cmd.text}" is not a valid command here — expected "where" or "stats"`,
        cmd
      );
    }
  }

  const trailing = lx.peek();
  if (trailing.type !== 'eof') {
    throw problemAt('syntax', `unexpected "${trailing.text}" after the end of the query`, trailing);
  }
  if (stats === null) {
    throw problem('stats', 'a detection rule must aggregate — add "| stats …"', input.length, 0);
  }
  if (having === null) {
    warnings.push(
      'no threshold "| where" after "stats" — the rule will fire for every group with at least one matching event'
    );
  }

  const where: WhereExpr | null =
    wheres.length === 0 ? null : wheres.length === 1 ? wheres[0] : { kind: 'and', operands: wheres };

  return {
    ok: true,
    rule: { indices, where, metrics: stats.metrics, by: stats.by, having },
    warnings,
  };
}

// ---- where-expression parsing (precedence: not > and > or; live-verified R4 §1) ----

function parseOrExpr(lx: Lexer): WhereExpr {
  const operands: WhereExpr[] = [parseAndExpr(lx)];
  for (;;) {
    const p = lx.peek();
    if (p.type === 'word' && p.lower === 'or') {
      lx.next();
      operands.push(parseAndExpr(lx));
    } else if (p.type === 'word' && p.lower === 'xor') {
      throw problemAt(
        'xor',
        '"xor" is not supported in detection rules — use "and"/"or" with parentheses',
        p
      );
    } else {
      break;
    }
  }
  return operands.length === 1 ? operands[0] : { kind: 'or', operands };
}

function parseAndExpr(lx: Lexer): WhereExpr {
  const operands: WhereExpr[] = [parseNotExpr(lx)];
  for (;;) {
    const p = lx.peek();
    if (p.type === 'word' && p.lower === 'and') {
      lx.next();
      operands.push(parseNotExpr(lx));
    } else if (p.type === 'word' && p.lower === 'xor') {
      throw problemAt(
        'xor',
        '"xor" is not supported in detection rules — use "and"/"or" with parentheses',
        p
      );
    } else {
      break;
    }
  }
  return operands.length === 1 ? operands[0] : { kind: 'and', operands };
}

function parseNotExpr(lx: Lexer): WhereExpr {
  const p = lx.peek();
  if (p.type === 'word' && p.lower === 'not') {
    lx.next();
    return { kind: 'not', operand: parseNotExpr(lx) };
  }
  return parsePrimary(lx);
}

function parsePrimary(lx: Lexer): WhereExpr {
  const t = lx.peek();
  if (t.type === 'lparen') {
    lx.next();
    const inner = parseOrExpr(lx);
    const close = lx.next();
    if (close.type !== 'rparen') {
      throw problemAt('syntax', `expected ")" but found "${close.text || 'end of query'}"`, close);
    }
    return inner;
  }
  if (t.type === 'word' && t.lower === 'like') {
    // Function form: like(field, 'pattern').
    lx.next();
    const open = lx.next();
    if (open.type !== 'lparen') {
      throw problemAt('syntax', `expected "(" after "like"`, open);
    }
    const field = toFieldRef(lx.next());
    const comma = lx.next();
    if (comma.type !== 'comma') {
      throw problemAt('syntax', `expected "," after the like() field`, comma);
    }
    const pat = lx.next();
    if (pat.type !== 'string') {
      throw problemAt('syntax', `like() requires a quoted pattern, e.g. like(field, '%value%')`, pat);
    }
    const close = lx.next();
    if (close.type !== 'rparen') {
      throw problemAt('syntax', `expected ")" to close like(…)`, close);
    }
    return { kind: 'like', field, pattern: pat.str as string };
  }
  if (t.type === 'number' || t.type === 'string') {
    throw problemAt(
      'syntax',
      `a comparison must start with a field name (found ${t.text}) — the field goes on the left`,
      t
    );
  }
  if (t.type !== 'word' && t.type !== 'backtick') {
    throw problemAt('syntax', `expected a field name (found "${t.text || 'end of query'}")`, t);
  }

  const fieldTok = lx.next();
  // Unsupported function call: bare ident directly followed by "(" (like() was handled above).
  if (fieldTok.type === 'word' && !fieldTok.text.includes('.') && lx.peek().type === 'lparen') {
    throw problemAt(
      `${fieldTok.text}()`,
      `function "${fieldTok.text}()" is not supported in the detection subset`,
      fieldTok
    );
  }
  const field = toFieldRef(fieldTok);

  const nxt = lx.peek();
  if (nxt.type === 'op') {
    const opTok = lx.next();
    const op = (opTok.text === '==' ? '=' : opTok.text) as '=' | '!=' | '>' | '>=' | '<' | '<=';
    const value = parseLiteral(lx, opTok.text);
    if (lx.peek().type === 'arith') {
      throw problemAt(
        'arithmetic',
        'arithmetic in predicates is not supported in the detection subset',
        lx.peek()
      );
    }
    return { kind: 'cmp', field, op, value };
  }
  if (nxt.type === 'word' && nxt.lower === 'like') {
    lx.next();
    const pat = lx.next();
    if (pat.type !== 'string') {
      throw problemAt('syntax', `"like" requires a quoted pattern, e.g. field like '%value%'`, pat);
    }
    return { kind: 'like', field, pattern: pat.str as string };
  }
  if (nxt.type === 'word' && nxt.lower === 'in') {
    lx.next();
    const open = lx.next();
    if (open.type !== 'lparen') {
      throw problemAt('syntax', `expected "(" after "in"`, open);
    }
    const values: Array<string | number> = [];
    for (;;) {
      const v = lx.next();
      if (v.type === 'number') {
        values.push(v.num as number);
      } else if (v.type === 'string') {
        values.push(v.str as string);
      } else {
        throw problemAt('syntax', `expected a number or string in the "in" list`, v);
      }
      const sep = lx.next();
      if (sep.type === 'comma') {
        continue;
      }
      if (sep.type === 'rparen') {
        break;
      }
      throw problemAt('syntax', `expected "," or ")" in the "in" list`, sep);
    }
    return { kind: 'in', field, values };
  }
  if (nxt.type === 'word' && nxt.lower === 'is') {
    throw problemAt(
      'is-null',
      '"IS NULL" / "IS NOT NULL" are not supported in the detection subset',
      nxt
    );
  }
  if (nxt.type === 'word' && nxt.lower === 'between') {
    throw problemAt('between', '"between" is not supported — write two comparisons joined by "and"', nxt);
  }
  if (nxt.type === 'word' && nxt.lower === 'not') {
    throw problemAt(
      'not-in',
      `postfix "not in" is not supported — write: not (${field.name} in (…))`,
      nxt
    );
  }
  if (nxt.type === 'arith') {
    throw problemAt(
      'arithmetic',
      'arithmetic in predicates is not supported in the detection subset',
      nxt
    );
  }
  throw problemAt('syntax', `expected a comparison after field "${field.name}"`, nxt);
}

function parseLiteral(lx: Lexer, afterOp: string): string | number | boolean {
  const t = lx.next();
  if (t.type === 'number') {
    return t.num as number;
  }
  if (t.type === 'string') {
    return t.str as string;
  }
  if (t.type === 'word' && (t.lower === 'true' || t.lower === 'false')) {
    return t.lower === 'true';
  }
  throw problemAt('syntax', `expected a value after "${afterOp}"`, t);
}

/** Convert a word/backtick token to a FieldRef, enforcing the .keyword and reserved-word rules. */
function toFieldRef(tok: Token): FieldRef {
  let name: string;
  if (tok.type === 'word') {
    if (KEYWORDS.has(tok.lower)) {
      throw problemAt(
        'syntax',
        `"${tok.text}" is a reserved word — backtick it to use it as a field name`,
        tok
      );
    }
    name = tok.text;
  } else if (tok.type === 'backtick') {
    name = tok.str as string;
  } else {
    throw problemAt('syntax', `expected a field name (found "${tok.text || 'end of query'}")`, tok);
  }
  if (name.endsWith('.keyword')) {
    throw problemAt(
      'keyword-subfield',
      `write "${name.slice(0, -'.keyword'.length)}" — TLSOC resolves keyword subfields automatically`,
      tok
    );
  }
  return { name, span: [tok.offset, tok.offset + tok.length] };
}

// ---- stats parsing ----

const AGG_REJECT_REASON = (name: string): string =>
  `aggregation "${name}" is not supported in detection rules — use count()/c(), ` +
  `dc()/distinct_count(), sum(), avg(), min(), max()`;

function parseStats(lx: Lexer): { metrics: MetricAgg[]; by: FieldRef[] } {
  const first = lx.peek();
  if (first.type === 'word' && first.lower === 'bucket_nullable') {
    throw problemAt('bucket_nullable', '"bucket_nullable" is not supported in detection rules', first);
  }

  const metrics: MetricAgg[] = [];
  const aliasTokens: Token[] = [];
  for (;;) {
    metrics.push(parseAgg(lx, aliasTokens));
    if (lx.peek().type === 'comma') {
      lx.next();
      continue;
    }
    break;
  }

  // Duplicate-alias check (aliases become buckets_path keys — they must be unique).
  const seen = new Set<string>();
  for (let i = 0, a = 0; i < metrics.length; i++) {
    const alias = metrics[i].alias;
    if (alias !== null) {
      const tok = aliasTokens[a];
      a += 1;
      if (seen.has(alias)) {
        throw problemAt('alias', `duplicate alias "${alias}"`, tok);
      }
      seen.add(alias);
    }
  }

  const by: FieldRef[] = [];
  const byTok = lx.peek();
  if (byTok.type === 'word' && byTok.lower === 'by') {
    lx.next();
    for (;;) {
      const ft = lx.next();
      if (ft.type === 'word' && ft.lower === 'span' && lx.peek().type === 'lparen') {
        throw problemAt(
          'span()',
          'time bucketing is not supported — the rule window is the time bucket',
          ft
        );
      }
      by.push(toFieldRef(ft));
      if (lx.peek().type === 'comma') {
        lx.next();
        continue;
      }
      break;
    }
  }
  return { metrics, by };
}

function parseAgg(lx: Lexer, aliasTokens: Token[]): MetricAgg {
  const t = lx.next();
  if (t.type !== 'word') {
    throw problemAt('syntax', 'expected an aggregation (count, dc, sum, avg, min, max)', t);
  }
  const name = t.lower;
  if (name === 'by') {
    throw problemAt('syntax', `"stats" needs at least one aggregation before "by"`, t);
  }
  if (REJECTED_AGGS.has(name) || /^(?:p|perc)\d+$/.test(name)) {
    throw problemAt(t.text, AGG_REJECT_REASON(t.text), t);
  }

  let fn: MetricAgg['fn'];
  let field: string | null = null;

  if (name === 'count' || name === 'c') {
    fn = 'count';
    if (lx.peek().type === 'lparen') {
      lx.next();
      if (lx.peek().type === 'rparen') {
        lx.next();
      } else {
        const ft = lx.next();
        if (ft.type === 'word' && ft.lower === 'eval' && lx.peek().type === 'lparen') {
          throw problemAt(
            'count(eval())',
            'count(eval(…)) is not supported in detection rules — use a "| where" filter instead',
            ft
          );
        }
        field = toFieldRef(ft).name;
        expectRparen(lx, `${t.text}(…)`);
      }
    }
    // Bare `count` / `c` (no parens) is the engine-documented shorthand for count().
  } else if (name === 'dc' || name === 'distinct_count') {
    fn = 'dc';
    field = parseAggFieldArg(lx, t.text);
  } else if (name === 'sum' || name === 'avg' || name === 'min' || name === 'max') {
    fn = name;
    field = parseAggFieldArg(lx, t.text);
  } else {
    throw problemAt(t.text, AGG_REJECT_REASON(t.text), t);
  }

  let alias: string | null = null;
  const asTok = lx.peek();
  if (asTok.type === 'word' && asTok.lower === 'as') {
    lx.next();
    const at = lx.next();
    if (at.type !== 'word') {
      throw problemAt('alias', 'expected an alias name after "as"', at);
    }
    if (!/^[a-z][a-z0-9_]*$/.test(at.text)) {
      throw problemAt(
        'alias',
        `alias "${at.text}" must be lowercase letters, digits, and underscores ` +
          '(it becomes the monitor metric name)',
        at
      );
    }
    alias = at.text;
    aliasTokens.push(at);
  }
  return { fn, field, alias };
}

function parseAggFieldArg(lx: Lexer, aggName: string): string {
  const open = lx.next();
  if (open.type !== 'lparen') {
    throw problemAt('syntax', `"${aggName}" requires a field: ${aggName}(<field>)`, open);
  }
  const field = toFieldRef(lx.next()).name;
  expectRparen(lx, `${aggName}(…)`);
  return field;
}

function expectRparen(lx: Lexer, what: string): void {
  const close = lx.next();
  if (close.type !== 'rparen') {
    throw problemAt('syntax', `expected ")" to close ${what}`, close);
  }
}

// ---- having (post-stats where) parsing ----

function parseHaving(lx: Lexer, input: string, metrics: MetricAgg[]): PplHavingExpr {
  const aliases = new Set<string>();
  metrics.forEach((m) => {
    if (m.alias !== null) {
      aliases.add(m.alias);
    }
  });
  return parseHavingOr(lx, input, metrics, aliases);
}

function parseHavingOr(
  lx: Lexer,
  input: string,
  metrics: MetricAgg[],
  aliases: Set<string>
): PplHavingExpr {
  const operands: PplHavingExpr[] = [parseHavingAnd(lx, input, metrics, aliases)];
  for (;;) {
    const p = lx.peek();
    if (p.type === 'word' && p.lower === 'or') {
      lx.next();
      operands.push(parseHavingAnd(lx, input, metrics, aliases));
    } else if (p.type === 'word' && p.lower === 'xor') {
      throw problemAt(
        'xor',
        '"xor" is not supported in detection rules — use "and"/"or" with parentheses',
        p
      );
    } else {
      break;
    }
  }
  return operands.length === 1 ? operands[0] : { kind: 'or', operands };
}

function parseHavingAnd(
  lx: Lexer,
  input: string,
  metrics: MetricAgg[],
  aliases: Set<string>
): PplHavingExpr {
  const operands: PplHavingExpr[] = [parseHavingPrimary(lx, input, metrics, aliases)];
  for (;;) {
    const p = lx.peek();
    if (p.type === 'word' && p.lower === 'and') {
      lx.next();
      operands.push(parseHavingPrimary(lx, input, metrics, aliases));
    } else if (p.type === 'word' && p.lower === 'xor') {
      throw problemAt(
        'xor',
        '"xor" is not supported in detection rules — use "and"/"or" with parentheses',
        p
      );
    } else {
      break;
    }
  }
  return operands.length === 1 ? operands[0] : { kind: 'and', operands };
}

function parseHavingPrimary(
  lx: Lexer,
  input: string,
  metrics: MetricAgg[],
  aliases: Set<string>
): PplHavingExpr {
  const t = lx.peek();
  if (t.type === 'lparen') {
    lx.next();
    const inner = parseHavingOr(lx, input, metrics, aliases);
    const close = lx.next();
    if (close.type !== 'rparen') {
      throw problemAt('syntax', `expected ")" in the threshold condition`, close);
    }
    return inner;
  }
  if (t.type !== 'word') {
    throw problemAt(
      'syntax',
      `expected a metric alias or "(" in the threshold condition (found "${t.text || 'end of query'}")`,
      t
    );
  }
  lx.next();
  if (t.lower === 'not') {
    throw problemAt('syntax', '"not" is not supported in the threshold condition', t);
  }
  if (lx.peek().type === 'lparen') {
    // A metric CALL in the having position: quote the raw call text — the engine parse-fails
    // on this too; the fix (name the metric with 'as') is the same for both.
    const call = sliceCall(input, t.offset);
    throw problem(
      'having-reference',
      `metric "${call}" must be given a name with 'as' before it can be used in the threshold condition`,
      t.offset,
      call.length
    );
  }
  if (!aliases.has(t.text)) {
    throw problemAt(
      'having-reference',
      `"${t.text}" does not name a metric — give the metric a name with 'as ${t.text}' ` +
        'in the stats command to reference it here',
      t
    );
  }
  const opTok = lx.next();
  if (opTok.type !== 'op') {
    throw problemAt('syntax', `expected a comparison operator after "${t.text}"`, opTok);
  }
  const op = (opTok.text === '==' ? '=' : opTok.text) as '>' | '>=' | '<' | '<=' | '=' | '!=';
  const valTok = lx.next();
  if (valTok.type !== 'number') {
    throw problemAt('syntax', `the threshold condition must compare "${t.text}" to a number`, valTok);
  }
  return { kind: 'cmp', metricAlias: t.text, op, value: valTok.num as number };
}

/** Slice the raw text of a call like `dc(url.path)` starting at `start` (for error messages). */
function sliceCall(input: string, start: number): string {
  const open = input.indexOf('(', start);
  if (open === -1) {
    return input.slice(start).trim();
  }
  let depth = 0;
  for (let i = open; i < input.length; i++) {
    if (input[i] === '(') {
      depth += 1;
    } else if (input[i] === ')') {
      depth -= 1;
      if (depth === 0) {
        return input.slice(start, i + 1);
      }
    }
  }
  return input.slice(start);
}

// ---------------------------------------------------------------------------------------------
// Preview-text generation (research_r4.md §6).
// ---------------------------------------------------------------------------------------------

/** date_sub interval unit per TimeWindow unit — lowercase singular is live-verified safe. */
const INTERVAL_UNIT: Record<TimeWindow['unit'], string> = {
  MINUTES: 'minute',
  HOURS: 'hour',
  DAYS: 'day',
};

/**
 * Build the GENERATED preview query the server sends to `POST /_plugins/_ppl`: the user's query
 * with the rule window injected as a time-field conjunct into the last pre-stats `where` (or a
 * new `where` when there is none), plus a trailing `| head 100` for display.
 *
 * - The window uses `date_sub(now(), interval <n> <unit>)` — NEVER `timestampadd`: with a
 *   lowercase unit the 3.7 engine silently constant-folds the filter to FALSE (zero rows, no
 *   error) — the R4 silent-zero trap.
 * - The injected conjunct parenthesizes the existing expression, so `a or b` cannot rebind as
 *   `a or (b and window)`.
 * - The caller MUST have validated `pplText` with {@link parsePpl} first; this function throws
 *   on structurally impossible input (no stats command).
 */
export function buildPplPreviewQuery(
  pplText: string,
  timeField: string,
  window: TimeWindow
): string {
  const segments = splitTopLevelPipes(pplText).map((s) => s.trim());
  let statsIdx = -1;
  for (let i = 0; i < segments.length; i++) {
    if (/^stats\b/i.test(segments[i])) {
      statsIdx = i;
      break;
    }
  }
  if (statsIdx === -1) {
    throw new Error('buildPplPreviewQuery requires a parsed rule with a "stats" command');
  }
  const windowClause = `\`${timeField}\` >= date_sub(now(), interval ${window.value} ${
    INTERVAL_UNIT[window.unit]
  })`;
  const out = segments.slice();
  const lastWhereIdx = statsIdx - 1;
  if (lastWhereIdx >= 1 && /^where\b/i.test(out[lastWhereIdx])) {
    const expr = out[lastWhereIdx].replace(/^where\b/i, '').trim();
    out[lastWhereIdx] = `where (${expr}) and ${windowClause}`;
  } else {
    out.splice(statsIdx, 0, `where ${windowClause}`);
  }
  out.push('head 100');
  return out.join(' | ');
}

/** Split on top-level '|' only — pipes inside string literals or backticks are content. */
function splitTopLevelPipes(text: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote !== null) {
      if (c === quote) {
        if (quote !== '`' && text[i + 1] === quote) {
          i += 1; // doubled-quote escape stays inside the literal
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      quote = c;
      continue;
    }
    if (c === '|') {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(text.slice(start));
  return parts;
}
