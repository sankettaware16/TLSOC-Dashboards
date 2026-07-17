/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { CoreStart } from '../../../../core/public';
import { OverviewViewModel } from '../../common/overview/types';
import { OverviewFilterState } from './components/filter_bar';

interface UseOverviewResult {
  vm: OverviewViewModel | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
  refreshing: boolean;
}

/**
 * Loads the cockpit view-model for a window + filter set. Polls on `refreshMs` when > 0 (live
 * cockpit), and always polls every 12s while pristine so onboarding auto-flips when data lands.
 */
export function useOverview(
  core: CoreStart,
  window: string,
  filters: OverviewFilterState,
  refreshMs: number
): UseOverviewResult {
  const [vm, setVm] = useState<OverviewViewModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadedOnce = useRef(false);
  const inFlight = useRef(false);

  const query = {
    window,
    org: filters.org,
    dept: filters.dept,
    env: filters.env,
    endpoint: filters.endpoint,
    logSource: filters.logSource,
  };
  const queryKey = JSON.stringify(query);

  const reload = useCallback(async () => {
    if (inFlight.current) return; // debounce overlapping polls
    inFlight.current = true;
    if (loadedOnce.current) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const resp = (await core.http.get('/api/tlsoc/overview', { query })) as OverviewViewModel;
      setVm(resp);
    } catch (e) {
      const err = e as { body?: { message?: string }; message?: string };
      setError(err?.body?.message ?? err?.message ?? 'Could not load overview');
    } finally {
      inFlight.current = false;
      loadedOnce.current = true;
      setLoading(false);
      setRefreshing(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [core, queryKey]);

  useEffect(() => {
    reload();
  }, [reload]);

  // Auto-refresh: while pristine poll every 12s (onboarding auto-flip); otherwise honor refreshMs.
  useEffect(() => {
    const pristine = !vm || vm.state === 'pristine';
    const interval = pristine ? 12000 : refreshMs;
    if (!interval) return undefined;
    const id = setInterval(reload, interval);
    return () => clearInterval(id);
  }, [vm, refreshMs, reload]);

  return { vm, loading, error, reload, refreshing };
}
