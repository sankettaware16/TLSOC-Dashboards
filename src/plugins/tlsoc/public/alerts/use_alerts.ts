/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useCallback, useEffect, useRef, useState } from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { TlsocAlert, resolveDateMathRange } from '../../common/alerts';

export interface UseAlertsOptions {
  /** Datemath strings from the EuiSuperDatePicker (e.g. 'now-24h' / 'now'). Both optional. */
  start?: string;
  end?: string;
  /** Auto-refresh interval in ms; 0/undefined disables polling (mirrors use_overview.ts). */
  refreshMs?: number;
}

/**
 * Loads the Alerts list, optionally scoped to a `start`/`end` datemath range (WS-3, PROB-3), with
 * setInterval-based auto-refresh + an inFlight guard — mirrors the `useOverview` idiom
 * (`public/overview/use_overview.ts`). `start`/`end` are resolved to epoch ms via
 * {@link resolveDateMathRange} FRESH on every fetch (mount, each poll tick, or a manual `reload()`)
 * — never memoized ahead of time — so a relative range like `'now-24h'..'now'` rolls forward on
 * every auto-refresh instead of freezing at whatever instant the picker was last touched.
 */
export function useAlerts(core: CoreStart, options: UseAlertsOptions = {}) {
  const { start, end, refreshMs = 0 } = options;
  const [alerts, setAlerts] = useState<TlsocAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const loadedOnce = useRef(false);

  const load = useCallback(async () => {
    if (inFlight.current) return; // debounce overlapping polls (mirrors use_overview.ts)
    inFlight.current = true;
    if (!loadedOnce.current) setLoading(true); // no full-panel flash on background auto-refresh
    setError(null);
    try {
      // Resolved fresh at fetch time (see the function doc above) — the point of NOT precomputing
      // this once in the caller.
      const { from, to } = resolveDateMathRange(start, end);
      const query: Record<string, any> = {};
      if (from !== undefined) query.from = from;
      if (to !== undefined) query.to = to;
      const resp = (await core.http.get('/api/tlsoc/alerts', { query })) as any;
      setAlerts(resp?.alerts ?? []);
    } catch (e) {
      const err = e as any;
      setError(err?.body?.message ?? err?.message ?? 'Could not load alerts');
    } finally {
      inFlight.current = false;
      loadedOnce.current = true;
      setLoading(false);
    }
  }, [core, start, end]);

  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh — mirrors use_overview.ts's setInterval + inFlight-guard idiom; cleared on
  // unmount and whenever refreshMs or the effective query (via `load`'s own start/end deps) change.
  useEffect(() => {
    if (!refreshMs) return undefined;
    const id = setInterval(load, refreshMs);
    return () => clearInterval(id);
  }, [refreshMs, load]);

  const acknowledge = useCallback(
    async (monitorId: string, alertIds: string[]) => {
      try {
        await core.http.post('/api/tlsoc/alerts/_acknowledge', {
          body: JSON.stringify({ monitorId, alertIds }),
        });
        core.notifications.toasts.addSuccess('Alert acknowledged');
        await load();
      } catch (e) {
        const err = e as any;
        core.notifications.toasts.addDanger({
          title: 'Could not acknowledge',
          text: err?.body?.message ?? err?.message ?? 'Failed',
        });
      }
    },
    [core, load]
  );

  // Bulk acknowledge (PROB-25): one _acknowledge POST per monitor group (the Alerting API is
  // per-monitor). Per-group failures don't abort the rest; ONE summary toast + ONE reload at the
  // end — not a toast/reload storm per group.
  const acknowledgeBulk = useCallback(
    async (targets: Array<{ monitorId: string; alertIds: string[] }>) => {
      if (!targets.length) return;
      let acked = 0;
      const failures: string[] = [];
      for (const t of targets) {
        try {
          await core.http.post('/api/tlsoc/alerts/_acknowledge', {
            body: JSON.stringify({ monitorId: t.monitorId, alertIds: t.alertIds }),
          });
          acked += t.alertIds.length;
        } catch (e) {
          const err = e as any;
          failures.push(err?.body?.message ?? err?.message ?? 'Failed');
        }
      }
      if (acked > 0) {
        core.notifications.toasts.addSuccess(
          acked === 1 ? 'Acknowledged 1 alert' : `Acknowledged ${acked} alerts`
        );
      }
      if (failures.length > 0) {
        core.notifications.toasts.addDanger({
          title: 'Some alerts could not be acknowledged',
          text: failures[0],
        });
      }
      await load();
    },
    [core, load]
  );

  return { alerts, loading, error, reload: load, acknowledge, acknowledgeBulk };
}
