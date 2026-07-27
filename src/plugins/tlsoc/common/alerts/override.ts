/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { AlertOverrideAttributes, AlertState, TlsocAlert } from './types';

/**
 * PROB-29 — the pure merge core for the honest reopen display-override.
 *
 * Given a normalized alert and the `tlsoc-alert-override` (if any) keyed on its id, decide how the
 * override affects DISPLAY. The engine's real `state` is never mutated — the override only ATTACHES
 * an additive `reopenedFromCase` signal, and only when the engine still reports the alert
 * ACKNOWLEDGED (the exact state a reopen must reactivate).
 *
 * ENGINE-COMPLETE-WINS: if the engine has since moved the alert on (COMPLETED/DELETED/ACTIVE/ERROR),
 * the override is irrelevant — we show the engine state and flag the override `stale` so the caller
 * can lazily delete it. A missing/undefined override is a no-op.
 */
export interface OverrideMergeResult {
  /** The alert to display — either unchanged, or with `reopenedFromCase` attached. */
  alert: TlsocAlert;
  /** True when a present override no longer matches an ACKNOWLEDGED engine state (lazily deletable). */
  stale: boolean;
}

export function applyAlertOverride(
  alert: TlsocAlert,
  override: AlertOverrideAttributes | null | undefined
): OverrideMergeResult {
  if (!override) return { alert, stale: false };
  if (alert.state === 'ACKNOWLEDGED') {
    return {
      alert: {
        ...alert,
        reopenedFromCase: {
          caseId: override.caseId,
          caseName: override.caseName,
          reopenedAt: override.reopenedAt,
        },
      },
      stale: false,
    };
  }
  // Engine no longer ACKNOWLEDGED — engine wins, the override is dead weight.
  return { alert, stale: true };
}

/**
 * The EFFECTIVE state the UI treats the alert as (PROB-29). A reopened-but-still-ACKNOWLEDGED alert
 * reads as ACTIVE (reactivated); every other alert reads as its honest engine state. Keeps the Active
 * filter and any state-bucketing in ONE testable place so the real `state` field is never faked.
 */
export function effectiveAlertState(alert: TlsocAlert): AlertState {
  if (alert.reopenedFromCase && alert.state === 'ACKNOWLEDGED') return 'ACTIVE';
  return alert.state;
}

/**
 * PROB-30 BACK-COMPAT SHIM — resolve an override's ownership SET, tolerating legacy docs.
 *
 * Ownership moved from a single `caseId` (last-reopener-wins) to an `owners[]` set of case ids so a
 * shared alert reopened by two cases survives one of them re-closing. This is zero-migration: an OLD
 * override doc written before PROB-30 has no `owners[]`. EVERY reader of ownership (the reopen union
 * and the remove-from-set delete path) MUST go through this helper so a legacy doc reads as
 * `[caseId]` — its lone owner. A doc with a non-empty `owners[]` returns it verbatim; a doc missing
 * both (should never happen) returns `[]`.
 */
export function overrideOwners(
  override: Pick<AlertOverrideAttributes, 'owners' | 'caseId'>
): string[] {
  if (override.owners && override.owners.length > 0) return override.owners;
  return override.caseId ? [override.caseId] : [];
}
