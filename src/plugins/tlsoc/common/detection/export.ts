/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * TLSOC-native detection-rule export/import envelope (v1.2.3 D8).
 *
 * The envelope is EXACTLY the `SaveBody` the create route accepts (`{mode, rule}` — see
 * server/routes/monitors.ts) plus self-identification, so an export is re-importable by
 * construction, for EVERY registered rule type (native JSON is type-agnostic; Sigma is not).
 *
 * The blessed import path is the TLSOC create route ONLY: the `tlsoc-detection-rule` SO type is
 * `importableAndExportable` in saved-objects management, but an NDJSON SO import there re-creates
 * the rule SO with a DANGLING monitorId and no monitor — documented unsupported (research_r6 A5).
 */

import { DetectionMode, getType, isValidMode, unknownTypeMessage } from './registry';

export const NATIVE_EXPORT_VERSION = '1';
export const NATIVE_EXPORT_KIND = 'tlsoc-detection-rule';

/** One exported rule: self-identifying, and shaped exactly like the create route's body. */
export interface NativeRuleEnvelope {
  version: typeof NATIVE_EXPORT_VERSION;
  kind: typeof NATIVE_EXPORT_KIND;
  mode: DetectionMode;
  rule: Record<string, unknown>;
}

/** Build the single-rule export envelope. */
export function buildNativeEnvelope(
  mode: DetectionMode,
  rule: Record<string, unknown>
): NativeRuleEnvelope {
  return { version: NATIVE_EXPORT_VERSION, kind: NATIVE_EXPORT_KIND, mode, rule };
}

/** Build the bulk export: a plain JSON ARRAY of envelopes (one per selected rule). */
export function buildNativeBulkExport(
  rows: Array<{ mode: DetectionMode; rule: Record<string, unknown> }>
): NativeRuleEnvelope[] {
  return rows.map((r) => buildNativeEnvelope(r.mode, r.rule));
}

/**
 * WHY a rule cannot be exported as Sigma, as a named user-facing reason — or null when it can.
 * The rejected-by-name discipline in reverse (research_r6 A5): the Sigma menu item is only
 * offered when the round-trip is honest.
 *
 * - Types without a registry `toSigma` compiler (ppl, custom_query, new_terms, indicator_match)
 *   cannot be expressed in Sigma at all.
 * - A stateful rule WITH `advanced` metrics exceeds Sigma's `event_count` correlation — exporting
 *   only the base filter would silently drop the multi-metric condition.
 * - A rule WITH `exceptions` (v1.2.3 D9) would either leak curated FP-kills into portable logic
 *   or silently lose them — per-row export refuses instead (the builder's Sigma accordion is the
 *   place for the omit-with-warning flow).
 * - A rule WITH `suppression` (v1.2.3 D9) actually runs as a GROUPED bucket monitor — a Sigma
 *   export of the ungrouped doc-level form would silently misrepresent it (re-import creates an
 *   unsuppressed rule).
 */
export function sigmaExportUnavailableReason(mode: string, rule: unknown): string | null {
  if (!isValidMode(mode)) {
    return unknownTypeMessage(mode);
  }
  if (!getType(mode).toSigma) {
    return `"${mode}" rules are not Sigma-exportable — Sigma cannot express this rule type. Use the native JSON export.`;
  }
  const r = rule as any;
  if (r && typeof r === 'object' && r.advanced) {
    return (
      'This threshold rule uses advanced metrics, which Sigma event_count correlations cannot ' +
      'express — export it as native JSON instead.'
    );
  }
  if (r && typeof r === 'object' && Array.isArray(r.exceptions) && r.exceptions.length > 0) {
    return (
      'This rule carries TLSOC exceptions, which a Sigma export would silently drop — export it ' +
      'as native JSON instead.'
    );
  }
  if (r && typeof r === 'object' && r.suppression) {
    return (
      'This rule uses alert suppression and runs as a grouped monitor — a Sigma export would ' +
      'silently lose the grouping. Export it as native JSON instead.'
    );
  }
  return null;
}

/** Can this rule be exported as Sigma? (See {@link sigmaExportUnavailableReason} for the whys.) */
export function canExportSigma(mode: string, rule: unknown): boolean {
  return sigmaExportUnavailableReason(mode, rule) === null;
}

export type NativeImportResult =
  | { ok: true; envelopes: NativeRuleEnvelope[] }
  | { ok: false; errors: string[] };

/** Best-effort display name for an entry (for error messages). */
function entryName(entry: any, index: number): string {
  const name = entry?.rule?.name;
  return typeof name === 'string' && name !== '' ? `"${name}"` : `entry ${index + 1}`;
}

/**
 * Parse pasted/uploaded text as native TLSOC export JSON — a single envelope or a bulk array.
 * Reject-by-name discipline throughout (the sigma_import.ts template): every failure names the
 * exact foreign/unknown construct; nothing is silently reinterpreted. Each rule is validated
 * against the type registry (`getType(mode).validate`) so a mangled rule fails HERE, not as a
 * silently-dead monitor later.
 */
export function parseNativeImport(text: string): NativeImportResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    return { ok: false, errors: [`Not valid JSON: ${(err as Error).message}`] };
  }

  const entries = Array.isArray(parsed) ? parsed : [parsed];
  if (entries.length === 0) {
    return { ok: false, errors: ['The file contains an empty array — nothing to import.'] };
  }

  const errors: string[] = [];
  const envelopes: NativeRuleEnvelope[] = [];
  entries.forEach((entry: any, i) => {
    const label = entryName(entry, i);
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push(`Entry ${i + 1} is not an object — expected a TLSOC export envelope.`);
      return;
    }
    if (entry.kind !== NATIVE_EXPORT_KIND) {
      errors.push(
        `${label}: kind "${String(entry.kind)}" is not a TLSOC detection-rule export ` +
          `(expected "${NATIVE_EXPORT_KIND}").`
      );
      return;
    }
    // Tolerate a numeric 1 (hand-edited files) but reject any OTHER version by name.
    if (String(entry.version) !== NATIVE_EXPORT_VERSION) {
      errors.push(
        `${label}: export version "${String(entry.version)}" is not supported ` +
          `(this TLSOC reads version ${NATIVE_EXPORT_VERSION}).`
      );
      return;
    }
    if (typeof entry.mode !== 'string' || !isValidMode(entry.mode)) {
      errors.push(`${label}: ${unknownTypeMessage(String(entry.mode))}`);
      return;
    }
    if (!entry.rule || typeof entry.rule !== 'object' || Array.isArray(entry.rule)) {
      errors.push(`${label}: the envelope carries no rule object.`);
      return;
    }
    try {
      getType(entry.mode).validate(entry.rule);
    } catch (err) {
      errors.push(`${label}: ${(err as Error).message}`);
      return;
    }
    envelopes.push(buildNativeEnvelope(entry.mode, entry.rule));
  });

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, envelopes };
}
