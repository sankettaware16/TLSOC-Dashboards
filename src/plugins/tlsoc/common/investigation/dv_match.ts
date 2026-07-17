/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * PROB-2 fix (Investigate hardening): resolving a case's `scope.index` to a data view used to be
 * an EXACT title match only (`views.find(d => d.title === scope.index)`), which fails whenever the
 * case's index came from a rule whose configured index is itself a glob (e.g. a rule scoped to
 * `fosstlsoc-logs-mailnile-*`) that doesn't exactly equal any data view's title, even though a
 * broader view (`fosstlsoc-logs-*`) — or a more specific one — plainly covers it.
 *
 * `findDataViewForIndex` is pure: exact title match wins outright; otherwise every view whose
 * title, read as a glob, fully subsumes `index` (as a literal string — `index` may itself contain
 * `*`, which is matched textually against the glob, not re-interpreted) is a candidate, and the
 * LONGEST (most specific) title wins ties.
 */

export interface DataViewIdTitle {
  id: string;
  title: string;
}

/** Escape every regex metacharacter EXCEPT `*`, which the caller handles by splitting on it. */
function escapeRegExpLiteral(segment: string): string {
  return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Convert a data-view title (a glob: `*` = wildcard, everything else literal) to an anchored RegExp. */
function titleToRegExp(title: string): RegExp {
  const pattern = title.split('*').map(escapeRegExpLiteral).join('.*');
  return new RegExp(`^${pattern}$`);
}

/**
 * True when `title`, interpreted as a glob, fully matches `index` (`index` is compared as a plain
 * string — any `*` characters it contains are matched literally by the title's `.*`, not expanded).
 */
function titleSubsumesIndex(title: string, index: string): boolean {
  try {
    return titleToRegExp(title).test(index);
  } catch {
    return false;
  }
}

/**
 * Resolve the data view that best matches `index`: exact title match first; else the longest
 * (most specific) title among those whose glob fully subsumes `index`; `undefined` if none match.
 */
export function findDataViewForIndex(
  views: DataViewIdTitle[],
  index: string
): DataViewIdTitle | undefined {
  const exact = views.find((v) => v.title === index);
  if (exact) return exact;

  let best: DataViewIdTitle | undefined;
  for (const v of views) {
    if (!titleSubsumesIndex(v.title, index)) continue;
    if (!best || v.title.length > best.title.length) {
      best = v;
    }
  }
  return best;
}

/**
 * PROB-2 WORKSPACE-FLOW fix: a pure predicate identifying data-view TITLES that TLSOC's own
 * `_ensure` route (`server/routes/data_views.ts`) owns — the base all-logs view
 * (`fosstlsoc-logs-*`) and any per-endpoint view it derives (`fosstlsoc-logs-<slug>-*`).
 * Deliberately does NOT match the other conventions `overview.logIndexPattern` tolerates
 * (`all-logs-*`, `soc-*`) or any foreign title — those were never created by this route, so the
 * startup orphan cleanup (`server/plugin.ts`) must never delete them even if it finds them
 * workspace-less. Also used to scope the route's own per-endpoint bookkeeping.
 */
export function isOwnedTlsocDataViewTitle(title: string): boolean {
  return title === 'fosstlsoc-logs-*' || /^fosstlsoc-logs-.+-\*$/.test(title);
}
