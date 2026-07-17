/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { loadAll } from 'js-yaml';
import {
  Condition,
  ConditionGroup,
  CountThreshold,
  DetectionOperator,
  LogSource,
  RuleDefinition,
  Severity,
  ThreatEntry,
  ThreatTechnique,
  ThresholdRuleDefinition,
  TimeWindow,
} from './types';
import { assertValidRule, assertValidThresholdRule } from './internal';

/**
 * Sigma YAML → TLSOC IR importer (WS-22, PROB-22).
 *
 * A clean-room reverse parser of {@link ./sigma.ts} / {@link ./sigma_correlation.ts}, implementing
 * ONLY the subset of the (public-domain) Sigma specification our two compilers emit. Every
 * construct outside that subset is REJECTED BY NAME — never silently dropped or approximated —
 * because a silently-mangled detection rule is worse than a rejected import. Designed from the
 * public sigma-specification only; pySigma was never read (clean-room, per the WS-22 brief).
 *
 * Round-trip contract: `parseSigmaImport(compileToSigma(rule))` (and the correlation equivalent)
 * must recover `rule` losslessly for every shape the two compilers can emit — see sigma_import.test.ts.
 */

/** A successfully parsed import: the recovered IR plus any lossy-but-safe heuristic warnings. */
export interface SigmaImportSuccess {
  ok: true;
  mode: 'stateless' | 'stateful';
  rule: RuleDefinition | ThresholdRuleDefinition;
  warnings: string[];
}

/** A rejected import. Every entry names the exact unsupported construct — never a vague failure. */
export interface SigmaImportFailure {
  ok: false;
  errors: Array<{ construct: string; reason: string }>;
}

/**
 * A structural slice of the bundled MITRE ATT&CK catalog (common/mitre, owned by a sibling task).
 * Deliberately NOT imported statically — the caller injects it (or omits it; the parser degrades
 * gracefully to unresolved-tag warnings without one, per the brief).
 */
export interface MitreCatalogLookup {
  tactics: Array<{ id: string; name: string; shortname: string }>;
  techniques: Array<{
    id: string;
    name: string;
    tactics: string[];
    sub: Array<{ id: string; name: string }>;
  }>;
}

/** 1 MB import guard (approximated in UTF-16 code units — close enough to reject pathological input). */
const MAX_INPUT_CHARS = 1024 * 1024;

/** Sigma value modifiers our compilers emit and this importer therefore understands. */
const SUPPORTED_MODIFIERS: Record<string, DetectionOperator> = {
  contains: 'contains',
  startswith: 'starts_with',
  endswith: 'ends_with',
  re: 'matches_regex',
  gt: 'gt',
  gte: 'gte',
  lt: 'lt',
  lte: 'lte',
};

/** The rest of the spec's modifier vocabulary — named explicitly so rejections are never vague. */
const KNOWN_UNSUPPORTED_MODIFIERS = new Set([
  'all',
  'cased',
  'neq',
  'windash',
  'base64',
  'base64offset',
  'utf16le',
  'utf16be',
  'utf16',
  'wide',
  'cidr',
  'expand',
  'fieldref',
  'minute',
  'hour',
  'day',
  'week',
  'month',
  'year',
]);

function reject(construct: string, reason: string): SigmaImportFailure {
  return { ok: false, errors: [{ construct, reason }] };
}

// ---------------------------------------------------------------------------------------------
// Wildcard / escape analysis for unmodified field values (Sigma value-wildcard rules).
// ---------------------------------------------------------------------------------------------

interface WildcardResult {
  ok: true;
  operator: 'equals' | 'contains' | 'starts_with' | 'ends_with';
  value: string;
  warning?: string;
}

/**
 * Unescape `\*`, `\?`, `\\` and classify the remaining unescaped `*` / `?`. Interior wildcards and
 * ANY unescaped `?` are rejected — only leading/trailing `*` is a supported heuristic mapping.
 */
function analyzeWildcard(raw: string): WildcardResult | SigmaImportFailure {
  let out = '';
  const marks: boolean[] = [];
  let i = 0;
  while (i < raw.length) {
    const c = raw[i];
    if (c === '\\' && i + 1 < raw.length && '*?\\'.includes(raw[i + 1])) {
      out += raw[i + 1];
      marks.push(false);
      i += 2;
      continue;
    }
    out += c;
    marks.push(c === '*' || c === '?');
    i += 1;
  }

  if (marks.some((m, idx) => m && out[idx] === '?')) {
    return reject('wildcard', `unescaped "?" in value "${raw}" is not supported`);
  }

  const starIdxs: number[] = [];
  marks.forEach((m, idx) => {
    if (m && out[idx] === '*') starIdxs.push(idx);
  });
  if (starIdxs.length === 0) {
    return { ok: true, operator: 'equals', value: out };
  }

  if (out.length === 1) {
    // A lone unescaped '*' — both leading and trailing at once.
    return {
      ok: true,
      operator: 'contains',
      value: '',
      warning: `value "${raw}" (a bare wildcard) mapped to contains "" — heuristic wildcard mapping`,
    };
  }

  const last = out.length - 1;
  const nonBoundary = starIdxs.some((idx) => idx !== 0 && idx !== last);
  if (nonBoundary) {
    return reject(
      'wildcard',
      `interior wildcard in value "${raw}" is not supported (wildcards are only supported at the start and/or end of a value)`
    );
  }

  const isLead = starIdxs.includes(0);
  const isTrail = starIdxs.includes(last);
  let stripped = out;
  if (isTrail) stripped = stripped.slice(0, stripped.length - 1);
  if (isLead) stripped = stripped.slice(1);

  if (isLead && isTrail) {
    return {
      ok: true,
      operator: 'contains',
      value: stripped,
      warning: `value "${raw}" mapped to contains "${stripped}" — heuristic wildcard mapping (leading+trailing "*")`,
    };
  }
  if (isLead) {
    return {
      ok: true,
      operator: 'ends_with',
      value: stripped,
      warning: `value "${raw}" mapped to ends_with "${stripped}" — heuristic wildcard mapping (leading "*")`,
    };
  }
  return {
    ok: true,
    operator: 'starts_with',
    value: stripped,
    warning: `value "${raw}" mapped to starts_with "${stripped}" — heuristic wildcard mapping (trailing "*")`,
  };
}

// ---------------------------------------------------------------------------------------------
// detection: block parsing (selections + condition string) — shared by stateless and the
// stateful base-rule's `filter`.
// ---------------------------------------------------------------------------------------------

interface FieldParseSuccess {
  ok: true;
  condition: Condition;
}

function parseFieldEntry(
  fieldKey: string,
  val: unknown,
  warnings: string[]
): FieldParseSuccess | SigmaImportFailure {
  const parts = fieldKey.split('|');
  const field = parts[0];
  const modifiers = parts.slice(1);
  if (!field) {
    return reject('detection', `empty field name in key "${fieldKey}"`);
  }

  if (modifiers.length > 1) {
    return reject(
      'modifier',
      `chained modifier "${modifiers.join('|')}" on field "${field}" is not supported`
    );
  }

  if (modifiers.length === 1) {
    const mod = modifiers[0];
    if (mod === 'exists') {
      if (typeof val !== 'boolean') {
        return reject(
          'modifier',
          `modifier "exists" on field "${field}" requires a boolean value (true/false)`
        );
      }
      return { ok: true, condition: { field, operator: val ? 'exists' : 'not_exists' } };
    }
    if (mod in SUPPORTED_MODIFIERS) {
      if (Array.isArray(val)) {
        return reject(
          'modifier',
          `modifier "${mod}" combined with a list value on field "${field}" is not supported`
        );
      }
      if (val === null || val === undefined) {
        return reject('null', `field "${field}|${mod}" has a null value`);
      }
      return {
        ok: true,
        condition: { field, operator: SUPPORTED_MODIFIERS[mod], value: val as string | number },
      };
    }
    if (KNOWN_UNSUPPORTED_MODIFIERS.has(mod)) {
      return reject('modifier', `modifier "${mod}" is not supported`);
    }
    return reject('modifier', `modifier "${mod}" is not recognized`);
  }

  // No modifier — a plain value.
  if (Array.isArray(val)) {
    if (val.length === 0) {
      return reject('detection', `field "${field}" has an empty value list`);
    }
    return {
      ok: true,
      condition: { field, operator: 'is_one_of', values: val as Array<string | number> },
    };
  }
  if (val === null) {
    return reject('null', `field "${field}" has a null value`);
  }
  if (typeof val === 'boolean') {
    return reject(
      'unsupported-value',
      `field "${field}": a boolean value is only supported with the "exists" modifier`
    );
  }
  if (typeof val === 'number') {
    return { ok: true, condition: { field, operator: 'equals', value: val } };
  }
  if (typeof val !== 'string') {
    return reject('detection', `field "${field}" has an unsupported value type`);
  }
  if (val === '') {
    return reject('empty-value', `field "${field}" has an empty string value`);
  }
  const wc = analyzeWildcard(val);
  if (!wc.ok) return wc;
  if (wc.warning) warnings.push(wc.warning);
  return { ok: true, condition: { field, operator: wc.operator, value: wc.value } };
}

interface SelectionParseSuccess {
  ok: true;
  conditions: Condition[];
}

function parseSelection(
  name: string,
  val: unknown,
  warnings: string[]
): SelectionParseSuccess | SigmaImportFailure {
  if (Array.isArray(val)) {
    if (val.length === 0) {
      return reject('detection', `selection "${name}" is empty`);
    }
    if (val.every((v) => typeof v === 'string')) {
      return reject('keywords', 'field-less full-text selections are not supported');
    }
    if (val.every((v) => v !== null && typeof v === 'object' && !Array.isArray(v))) {
      return reject('or-of-ands', 'nested OR-of-AND selections are not supported');
    }
    return reject('detection', `selection "${name}" has an unsupported list shape`);
  }
  if (val === null || typeof val !== 'object') {
    return reject('detection', `selection "${name}" must be a mapping of field to value`);
  }
  const conditions: Condition[] = [];
  for (const [fieldKey, fieldVal] of Object.entries(val as Record<string, unknown>)) {
    const parsed = parseFieldEntry(fieldKey, fieldVal, warnings);
    if (!parsed.ok) return parsed;
    conditions.push(parsed.condition);
  }
  if (conditions.length === 0) {
    return reject('detection', `selection "${name}" has no fields`);
  }
  return { ok: true, conditions };
}

interface ConditionExpr {
  ok: true;
  logic: 'AND' | 'OR';
  terms: Array<{ name: string; negate: boolean }>;
  quantifier: boolean;
}

function parseConditionExpr(raw: string, selectionNames: string[]): ConditionExpr | SigmaImportFailure {
  if (raw.includes('(') || raw.includes(')')) {
    return reject('parentheses', 'parenthesized conditions are not supported');
  }

  const quantifierMatch = raw.match(/^(all|\d+)\s+of\s+(them|[A-Za-z_][A-Za-z0-9_]*\*?)$/i);
  if (quantifierMatch) {
    const countPart = quantifierMatch[1].toLowerCase();
    const targetPart = quantifierMatch[2];
    if (countPart !== 'all' && Number(countPart) !== 1) {
      return reject(
        'quantifier',
        `only "1 of ..." and "all of ..." quantifiers are supported (got "${quantifierMatch[1]} of ${targetPart}")`
      );
    }
    const logic: 'AND' | 'OR' = countPart === 'all' ? 'AND' : 'OR';
    let matched: string[];
    if (targetPart.toLowerCase() === 'them') {
      matched = selectionNames;
    } else if (targetPart.endsWith('*')) {
      const prefix = targetPart.slice(0, -1);
      matched = selectionNames.filter((n) => n.startsWith(prefix));
    } else {
      matched = selectionNames.filter((n) => n === targetPart);
    }
    if (matched.length === 0) {
      return reject('quantifier', `no selections match "${targetPart}"`);
    }
    return { ok: true, logic, terms: matched.map((name) => ({ name, negate: false })), quantifier: true };
  }

  const tokens = raw.split(/\s+/).filter(Boolean);
  const terms: Array<{ name: string; negate: boolean }> = [];
  let joiner: 'and' | 'or' | null = null;
  let i = 0;
  while (i < tokens.length) {
    let negate = false;
    if (tokens[i].toLowerCase() === 'not') {
      negate = true;
      i += 1;
    }
    if (i >= tokens.length || ['and', 'or', 'not'].includes(tokens[i].toLowerCase())) {
      return reject('condition', `malformed condition expression "${raw}"`);
    }
    const name = tokens[i];
    i += 1;
    if (!selectionNames.includes(name)) {
      return reject('condition', `condition references unknown selection "${name}"`);
    }
    terms.push({ name, negate });
    if (i < tokens.length) {
      const j = tokens[i].toLowerCase();
      if (j !== 'and' && j !== 'or') {
        return reject('condition', `unexpected token "${tokens[i]}" in condition "${raw}"`);
      }
      if (joiner === null) joiner = j as 'and' | 'or';
      else if (joiner !== j) {
        return reject('mixed-logic', 'mixing "and" and "or" in one condition expression is not supported');
      }
      i += 1;
    }
  }
  if (terms.length === 0) {
    return reject('condition', 'empty condition expression');
  }
  const logic: 'AND' | 'OR' = joiner === 'or' ? 'OR' : 'AND';
  return { ok: true, logic, terms, quantifier: false };
}

/** Negate a Condition's operator to its IR opposite; null when the operator has no negated form. */
function negateCondition(c: Condition): Condition | null {
  switch (c.operator) {
    case 'equals':
      return { ...c, operator: 'not_equals' };
    case 'contains':
      return { ...c, operator: 'not_contains' };
    case 'is_one_of':
      return { ...c, operator: 'is_not_one_of' };
    case 'exists':
      return { ...c, operator: 'not_exists' };
    default:
      return null;
  }
}

function compileConditionExpr(
  expr: ConditionExpr,
  selectionsMap: Map<string, Condition[]>
): { ok: true; group: ConditionGroup } | SigmaImportFailure {
  if (expr.quantifier || expr.logic === 'OR') {
    const conditions: Condition[] = [];
    for (const term of expr.terms) {
      const conds = selectionsMap.get(term.name)!;
      if (conds.length !== 1) {
        return reject(
          'quantifier',
          `selection "${term.name}" must have exactly one field to be combined with OR`
        );
      }
      if (term.negate) {
        const negated = negateCondition(conds[0]);
        if (!negated) {
          return reject('negation', `operator "${conds[0].operator}" cannot be negated`);
        }
        conditions.push(negated);
      } else {
        conditions.push(conds[0]);
      }
    }
    return { ok: true, group: { logic: expr.logic, conditions } };
  }

  // Uniform AND — a referenced selection may itself be an AND-of-fields and flattens cleanly.
  const conditions: Condition[] = [];
  for (const term of expr.terms) {
    const conds = selectionsMap.get(term.name)!;
    if (term.negate) {
      if (conds.length !== 1) {
        return reject(
          'negation',
          `negating selection "${term.name}" with more than one field is not supported`
        );
      }
      const negated = negateCondition(conds[0]);
      if (!negated) {
        return reject('negation', `operator "${conds[0].operator}" cannot be negated`);
      }
      conditions.push(negated);
    } else {
      conditions.push(...conds);
    }
  }
  return { ok: true, group: { logic: 'AND', conditions } };
}

interface DetectionParseSuccess {
  ok: true;
  group: ConditionGroup;
  warnings: string[];
}

function parseDetectionBlock(doc: Record<string, unknown>): DetectionParseSuccess | SigmaImportFailure {
  const detection = doc.detection;
  if (!detection || typeof detection !== 'object' || Array.isArray(detection)) {
    return reject('detection', 'the rule must have a "detection" block');
  }
  const det = detection as Record<string, unknown>;
  const warnings: string[] = [];
  const selectionNames: string[] = [];
  const selectionsMap = new Map<string, Condition[]>();

  for (const [key, val] of Object.entries(det)) {
    if (key === 'condition') continue;
    selectionNames.push(key);
    const parsed = parseSelection(key, val, warnings);
    if (!parsed.ok) return parsed;
    selectionsMap.set(key, parsed.conditions);
  }
  if (selectionNames.length === 0) {
    return reject('detection', 'the detection block has no selections');
  }

  const rawCondition = det.condition;
  if (Array.isArray(rawCondition)) {
    return reject('multi-condition', 'a list of condition expressions is not supported');
  }
  if (typeof rawCondition !== 'string' || rawCondition.trim() === '') {
    return reject('condition', 'the detection "condition" must be a non-empty string');
  }

  const expr = parseConditionExpr(rawCondition.trim(), selectionNames);
  if (!expr.ok) return expr;

  const compiled = compileConditionExpr(expr, selectionsMap);
  if (!compiled.ok) return compiled;

  return { ok: true, group: compiled.group, warnings };
}

// ---------------------------------------------------------------------------------------------
// MITRE ATT&CK tag resolution (rule.threat).
// ---------------------------------------------------------------------------------------------

function findTactic(catalog: MitreCatalogLookup | undefined, slug: string) {
  if (!catalog) return undefined;
  const target = slug.toLowerCase();
  return catalog.tactics.find((t) => t.name.toLowerCase().replace(/\s+/g, '_') === target);
}

function findTechnique(catalog: MitreCatalogLookup | undefined, techId: string) {
  if (!catalog) return undefined;
  return catalog.techniques.find((t) => t.id.toUpperCase() === techId.toUpperCase());
}

function findSub(catalog: MitreCatalogLookup | undefined, techId: string, subId: string) {
  const tech = findTechnique(catalog, techId);
  if (!tech) return undefined;
  return tech.sub.find((s) => s.id.toUpperCase() === subId.toUpperCase());
}

interface TechAccum {
  id: string;
  name: string;
  subtechnique: Array<{ id: string; name: string; reference: string }>;
}

interface EntryAccum {
  tactic?: { id: string; name: string; reference: string };
  shortname?: string;
  technique: TechAccum[];
}

/**
 * Derive `rule.threat` from Sigma `tags`. Unresolvable tags are WARNINGS, never hard rejects —
 * MITRE tagging is best-effort triage metadata, not a structural part of the detection logic.
 */
function buildThreat(
  tags: unknown,
  catalog: MitreCatalogLookup | undefined,
  warnings: string[]
): ThreatEntry[] | undefined {
  if (!Array.isArray(tags) || tags.length === 0) return undefined;

  const techTagRe = /^attack\.t(\d{4})(?:\.(\d{3}))?$/i;
  const tacticTagRe = /^attack\.(.+)$/i;

  const entries: EntryAccum[] = [];
  const techMap = new Map<string, TechAccum>();
  const techOrder: string[] = [];
  let unassigned: EntryAccum | undefined;

  for (const tag of tags) {
    if (typeof tag !== 'string') continue;
    if (!tag.toLowerCase().startsWith('attack.')) {
      warnings.push(`tag "${tag}" is not an ATT&CK tag — ignored`);
      continue;
    }

    const techMatch = tag.match(techTagRe);
    if (techMatch) {
      const techId = `T${techMatch[1]}`;
      const subNum = techMatch[2];
      if (!techMap.has(techId)) {
        const catTech = findTechnique(catalog, techId);
        techMap.set(techId, { id: techId, name: catTech ? catTech.name : techId, subtechnique: [] });
        techOrder.push(techId);
      }
      if (subNum) {
        const subId = `${techId}.${subNum}`;
        const parent = techMap.get(techId)!;
        const catSub = findSub(catalog, techId, subId);
        parent.subtechnique.push({
          id: subId,
          name: catSub ? catSub.name : subId,
          reference: `https://attack.mitre.org/techniques/${techId}/${subNum}/`,
        });
      }
      continue;
    }

    const tacticMatch = tag.match(tacticTagRe);
    if (tacticMatch) {
      const slug = tacticMatch[1];
      const catTactic = findTactic(catalog, slug);
      if (!catTactic) {
        warnings.push(
          catalog
            ? `tactic tag "${tag}" left unresolved — no matching tactic in the catalog`
            : `tactic tag "${tag}" left unresolved — no catalog`
        );
        continue;
      }
      entries.push({
        tactic: {
          id: catTactic.id,
          name: catTactic.name,
          reference: `https://attack.mitre.org/tactics/${catTactic.id}/`,
        },
        shortname: catTactic.shortname,
        technique: [],
      });
      continue;
    }

    warnings.push(`tag "${tag}" is not a recognized ATT&CK tag — ignored`);
  }

  for (const techId of techOrder) {
    const accum = techMap.get(techId)!;
    const catTech = findTechnique(catalog, techId);
    let target: EntryAccum | undefined;
    if (catTech && catTech.tactics.length > 0) {
      target = entries.find((e) => e.shortname !== undefined && catTech.tactics.includes(e.shortname));
    }
    if (!target) target = entries[0];
    if (!target) {
      if (!unassigned) {
        unassigned = { technique: [] };
        entries.push(unassigned);
      }
      target = unassigned;
    }
    target.technique.push(accum);
  }

  if (entries.length === 0) return undefined;

  return entries.map((e) => {
    const out: ThreatEntry = { framework: 'MITRE ATT&CK' };
    if (e.tactic) out.tactic = e.tactic;
    if (e.technique.length > 0) {
      out.technique = e.technique.map((t) => {
        const techOut: ThreatTechnique = {
          id: t.id,
          name: t.name,
          reference: `https://attack.mitre.org/techniques/${t.id}/`,
        };
        if (t.subtechnique.length > 0) techOut.subtechnique = t.subtechnique;
        return techOut;
      });
    }
    return out;
  });
}

// ---------------------------------------------------------------------------------------------
// Shared rule-envelope metadata (title/id/description/author/date/references/falsepositives/
// level/logsource/tags) — used by both the stateless doc and the stateful correlation doc.
// ---------------------------------------------------------------------------------------------

interface RuleMetadata {
  name: string;
  id?: string;
  description?: string;
  author?: string;
  date?: string;
  references?: string[];
  falsePositives?: string[];
  severity: Severity;
  logSource?: LogSource;
  index: string;
  threat?: ThreatEntry[];
  warnings: string[];
}

/**
 * Derive `index` / `logSource` from a doc's `logsource` block. Split out from {@link buildMetadata}
 * because the stateful correlation doc structurally never carries a `logsource` (per the SigmaHQ
 * correlation-rules spec and our own {@link ./sigma_correlation.ts}: only the *base* rule doc does)
 * — the stateful caller therefore invokes this against the base doc while every other metadata
 * field is read from the correlation doc.
 */
function deriveIndexAndLogSource(
  doc: Record<string, unknown>,
  warnings: string[]
): { index: string; logSource?: LogSource } {
  // The exporter has exactly one shape with no OpenSearch index available (buildLogSource in
  // sigma.ts falls back to `logsource.product = rule.index` when the rule carries no logSource at
  // all) — recovering THAT shape as an index hint, rather than as a semantic logSource, is what
  // makes our own exports round-trip losslessly. Any other logsource shape carries no index
  // pattern by construction (Sigma has no such concept), so the user must still choose a data view
  // in the builder; we seed `index` best-effort from the logsource so the rule can pass validation
  // as a *draft* pending that choice, and always warn either way.
  let logSource: LogSource | undefined;
  let index = '';
  const ls = doc.logsource;
  if (ls && typeof ls === 'object' && !Array.isArray(ls)) {
    const lsObj = ls as Record<string, unknown>;
    const category = typeof lsObj.category === 'string' ? lsObj.category : undefined;
    const product = typeof lsObj.product === 'string' ? lsObj.product : undefined;
    const service = typeof lsObj.service === 'string' ? lsObj.service : undefined;
    if (category === undefined && service === undefined && product !== undefined) {
      index = product;
      warnings.push(
        `logsource "product: ${product}" was used as the index hint — choose a data view in the builder to confirm it`
      );
    } else if (category !== undefined || product !== undefined || service !== undefined) {
      logSource = {};
      if (category !== undefined) logSource.category = category;
      if (product !== undefined) logSource.product = product;
      if (service !== undefined) logSource.service = service;
      index = product ?? category ?? service ?? '';
      warnings.push(
        'choose a data view in the builder (index seeded from the Sigma logsource — verify it)'
      );
    }
  }
  if (index === '') {
    warnings.push('choose a data view in the builder');
  }
  return { index, logSource };
}

function buildMetadata(
  doc: Record<string, unknown>,
  logsourceDoc: Record<string, unknown>,
  catalog: MitreCatalogLookup | undefined
): RuleMetadata {
  const warnings: string[] = [];

  let name: string;
  if (typeof doc.title === 'string' && doc.title.trim() !== '') {
    name = doc.title;
  } else {
    name = 'Untitled Sigma import';
    warnings.push('missing "title" — defaulted to "Untitled Sigma import"');
  }

  const id = typeof doc.id === 'string' ? doc.id : undefined;
  const description = typeof doc.description === 'string' ? doc.description : undefined;
  const author = typeof doc.author === 'string' ? doc.author : undefined;

  let date: string | undefined;
  if (typeof doc.date === 'string') {
    date = doc.date;
  } else if (doc.date instanceof Date) {
    // Defensive: a non-slash date scalar could be auto-parsed by js-yaml's timestamp type.
    const d = doc.date;
    const pad = (n: number) => String(n).padStart(2, '0');
    date = `${d.getUTCFullYear()}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}`;
  }

  const references = Array.isArray(doc.references)
    ? doc.references.filter((r): r is string => typeof r === 'string')
    : undefined;
  const falsePositives = Array.isArray(doc.falsepositives)
    ? doc.falsepositives.filter((r): r is string => typeof r === 'string')
    : undefined;

  let severity: Severity;
  const level = doc.level;
  if (level === undefined) {
    severity = 'medium';
    warnings.push('missing "level" — defaulted to severity "medium"');
  } else if (level === 'informational') {
    severity = 'low';
    warnings.push('level "informational" clamped to low');
  } else if (level === 'low' || level === 'medium' || level === 'high' || level === 'critical') {
    severity = level;
  } else {
    severity = 'medium';
    warnings.push(`unrecognized level "${String(level)}" — defaulted to severity "medium"`);
  }

  const { index, logSource } = deriveIndexAndLogSource(logsourceDoc, warnings);

  const threat = buildThreat(doc.tags, catalog, warnings);

  return {
    name,
    id,
    description,
    author,
    date,
    references,
    falsePositives,
    severity,
    logSource,
    index,
    threat,
    warnings,
  };
}

// ---------------------------------------------------------------------------------------------
// Stateless / stateful assembly.
// ---------------------------------------------------------------------------------------------

function parseStatelessDoc(
  doc: Record<string, unknown>,
  catalog: MitreCatalogLookup | undefined
): SigmaImportSuccess | SigmaImportFailure {
  const detectionResult = parseDetectionBlock(doc);
  if (!detectionResult.ok) return detectionResult;

  const meta = buildMetadata(doc, doc, catalog);
  const rule: RuleDefinition = {
    name: meta.name,
    severity: meta.severity,
    index: meta.index,
    group: detectionResult.group,
  };
  if (meta.id !== undefined) rule.id = meta.id;
  if (meta.description !== undefined) rule.description = meta.description;
  if (meta.logSource !== undefined) rule.logSource = meta.logSource;
  if (meta.references !== undefined) rule.references = meta.references;
  if (meta.author !== undefined) rule.author = meta.author;
  if (meta.date !== undefined) rule.date = meta.date;
  if (meta.falsePositives !== undefined) rule.falsePositives = meta.falsePositives;
  if (meta.threat !== undefined) rule.threat = meta.threat;

  try {
    assertValidRule(rule);
  } catch (e) {
    return reject('validation', (e as Error).message);
  }

  return {
    ok: true,
    mode: 'stateless',
    rule,
    warnings: [...detectionResult.warnings, ...meta.warnings],
  };
}

function parseStatefulDoc(
  correlationDoc: Record<string, unknown>,
  baseDoc: Record<string, unknown>,
  catalog: MitreCatalogLookup | undefined
): SigmaImportSuccess | SigmaImportFailure {
  const corrRaw = correlationDoc.correlation;
  if (!corrRaw || typeof corrRaw !== 'object' || Array.isArray(corrRaw)) {
    return reject('correlation', 'malformed "correlation" block');
  }
  const corr = corrRaw as Record<string, unknown>;

  if (corr.type !== 'event_count') {
    return reject(
      'correlation-type',
      `correlation type "${String(corr.type)}" is not supported (only "event_count")`
    );
  }

  const rulesRef = corr.rules;
  if (!Array.isArray(rulesRef) || rulesRef.length !== 1 || typeof rulesRef[0] !== 'string') {
    return reject('correlation-rules', 'correlation "rules" must reference exactly one base rule');
  }

  const groupByRaw = corr['group-by'];
  if (!Array.isArray(groupByRaw) || groupByRaw.length === 0 || !groupByRaw.every((g) => typeof g === 'string')) {
    return reject('group-by', 'correlation "group-by" must be a non-empty list of field names');
  }
  const groupBy = groupByRaw as string[];

  const timespanRaw = corr.timespan;
  if (typeof timespanRaw !== 'string') {
    return reject('timespan-format', 'correlation "timespan" must be a string');
  }
  const tsMatch = timespanRaw.match(/^(\d+)([smhd])$/i);
  if (!tsMatch) {
    return reject('timespan-format', `timespan "${timespanRaw}" is not a recognized format`);
  }
  const tsUnit = tsMatch[2].toLowerCase();
  if (tsUnit === 's') {
    return reject(
      'timespan-seconds',
      "seconds are below TLSOC's 1-minute floor; silent rounding would change the rule's meaning"
    );
  }
  const UNIT_MAP: Record<string, TimeWindow['unit']> = { m: 'MINUTES', h: 'HOURS', d: 'DAYS' };
  const window: TimeWindow = { value: Number(tsMatch[1]), unit: UNIT_MAP[tsUnit] };

  const condRaw = corr.condition;
  if (!condRaw || typeof condRaw !== 'object' || Array.isArray(condRaw)) {
    return reject('threshold-operator', 'correlation "condition" must be a single operator/value mapping');
  }
  const condKeys = Object.keys(condRaw as Record<string, unknown>);
  if (condKeys.length !== 1 || !['gt', 'gte', 'lt', 'lte'].includes(condKeys[0])) {
    return reject(
      'threshold-operator',
      `correlation "condition" must have exactly one of gt/gte/lt/lte (got ${condKeys.join(', ') || 'none'})`
    );
  }
  const threshold: CountThreshold = {
    operator: condKeys[0] as CountThreshold['operator'],
    value: Number((condRaw as Record<string, unknown>)[condKeys[0]]),
  };

  const detectionResult = parseDetectionBlock(baseDoc);
  if (!detectionResult.ok) return detectionResult;

  // The correlation doc's metadata wins — matches our exporter, which mirrors it there and
  // ignores the base doc's own metadata (compileToSigmaCorrelation in sigma_correlation.ts).
  // EXCEPTION: index/logSource. The correlation doc structurally never carries a `logsource`
  // (only the base rule does, per the SigmaHQ spec and sigma_correlation.ts) — sourcing it from
  // the correlation doc would leave `index` empty for every stateful import and fail the final
  // assertValidThresholdRule gate. We read it from the base doc instead; every other field still
  // comes from the correlation doc.
  const meta = buildMetadata(correlationDoc, baseDoc, catalog);
  const rule: ThresholdRuleDefinition = {
    name: meta.name,
    severity: meta.severity,
    index: meta.index,
    filter: detectionResult.group,
    groupBy,
    window,
    threshold,
  };
  if (meta.id !== undefined) rule.id = meta.id;
  if (meta.description !== undefined) rule.description = meta.description;
  if (meta.logSource !== undefined) rule.logSource = meta.logSource;
  if (meta.references !== undefined) rule.references = meta.references;
  if (meta.author !== undefined) rule.author = meta.author;
  if (meta.date !== undefined) rule.date = meta.date;
  if (meta.falsePositives !== undefined) rule.falsePositives = meta.falsePositives;
  if (meta.threat !== undefined) rule.threat = meta.threat;

  try {
    assertValidThresholdRule(rule);
  } catch (e) {
    return reject('validation', (e as Error).message);
  }

  return {
    ok: true,
    mode: 'stateful',
    rule,
    warnings: [...detectionResult.warnings, ...meta.warnings],
  };
}

/** Parse a Sigma YAML rule (stateless, or a 2-document stateful correlation export) into the TLSOC IR. */
export function parseSigmaImport(
  yamlText: string,
  opts?: { catalog?: MitreCatalogLookup }
): SigmaImportSuccess | SigmaImportFailure {
  const catalog = opts?.catalog;

  if (typeof yamlText !== 'string') {
    return reject('input', 'input must be a YAML string');
  }
  if (yamlText.length > MAX_INPUT_CHARS) {
    return reject('input', 'input exceeds the 1 MB import limit');
  }

  let rawDocs: unknown[];
  try {
    rawDocs = loadAll(yamlText) as unknown[];
  } catch (e) {
    return reject('yaml', `invalid YAML: ${(e as Error).message}`);
  }
  const docs = rawDocs.filter((d) => d !== null && d !== undefined);
  if (docs.length === 0) {
    return reject('yaml', 'no YAML documents found');
  }
  if (docs.length > 2) {
    return reject('documents', 'at most 2 YAML documents are supported');
  }
  if (!docs.every((d) => d !== null && typeof d === 'object' && !Array.isArray(d))) {
    return reject('yaml', 'each YAML document must be a mapping');
  }
  const typedDocs = docs as Array<Record<string, unknown>>;

  const correlationDocs = typedDocs.filter((d) => d.correlation !== undefined);
  if (correlationDocs.length > 1) {
    return reject('documents', 'exactly one document may contain a "correlation" block');
  }

  if (correlationDocs.length === 1) {
    if (typedDocs.length !== 2) {
      return reject(
        'documents',
        'a stateful correlation import requires exactly 2 documents (correlation + base rule)'
      );
    }
    const correlationDoc = correlationDocs[0];
    const otherDoc = typedDocs.find((d) => d !== correlationDoc)!;
    const corr = correlationDoc.correlation as Record<string, unknown> | undefined;
    const rulesRef = corr && Array.isArray(corr.rules) ? corr.rules : undefined;
    const targetName = rulesRef && typeof rulesRef[0] === 'string' ? rulesRef[0] : undefined;

    const nameWarnings: string[] = [];
    if (targetName === undefined || otherDoc.name !== targetName) {
      nameWarnings.push('could not match the base rule by name — used the other document positionally');
    }

    const result = parseStatefulDoc(correlationDoc, otherDoc, catalog);
    if (!result.ok) return result;
    return { ...result, warnings: [...nameWarnings, ...result.warnings] };
  }

  if (typedDocs.length !== 1) {
    return reject('documents', 'multiple documents are only supported for stateful correlation imports');
  }
  return parseStatelessDoc(typedDocs[0], catalog);
}
