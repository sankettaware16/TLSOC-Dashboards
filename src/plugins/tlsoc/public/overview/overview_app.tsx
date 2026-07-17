/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  EuiPage,
  EuiPageBody,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiButtonGroup,
  EuiLoadingSpinner,
  EuiCallOut,
  EuiHealth,
  EuiHorizontalRule,
  EuiSelect,
  EuiButtonIcon,
  EuiToolTip,
  EuiButton,
  EuiFlyout,
  EuiFlyoutHeader,
  EuiFlyoutBody,
} from '@elastic/eui';
import { CoreStart } from '../../../../core/public';
import { OVERVIEW_WINDOWS, DEFAULT_OVERVIEW_WINDOW } from '../../common/overview/types';
import { useOverview } from './use_overview';
import { PristineState } from './components/pristine_state';
import { SeedingState } from './components/seeding_state';
import { LiveDashboard } from './components/live_dashboard';
import { FilterBar, OverviewFilterState, EMPTY_FILTERS } from './components/filter_bar';
import { OnboardingGuide } from './components/onboarding_guide';
import { freshnessColor } from './format';

interface OverviewAppProps {
  core: CoreStart;
}

const REFRESH_OPTIONS = [
  { value: '0', text: 'Off' },
  { value: '10000', text: '10s' },
  { value: '30000', text: '30s' },
  { value: '60000', text: '60s' },
];

export const OverviewApp: React.FC<OverviewAppProps> = ({ core }) => {
  const [window, setWindow] = useState<string>(DEFAULT_OVERVIEW_WINDOW);
  const [filters, setFilters] = useState<OverviewFilterState>(EMPTY_FILTERS);
  const [refreshMs, setRefreshMs] = useState<number>(30000);
  const [showGuide, setShowGuide] = useState<boolean>(false);
  const { vm, loading, error, reload, refreshing } = useOverview(core, window, filters, refreshMs);
  const darkMode = Boolean(core.uiSettings.get('theme:darkMode'));
  const nowMs = Date.now();

  // PROB-2 WORKSPACE-FLOW fix: track the mount-time seed of the agentless pipeline's data view(s)
  // to completion instead of firing-and-forgetting it, so the branded SeedingState interstitial
  // below can hold the page briefly rather than racing the analyst into a load that has nothing to
  // resolve against yet. The client-side workspace-entry hook (`public/plugin.ts`) is the PRIMARY
  // fix — it fires before this component even mounts — this is defense in depth + user feedback.
  // Bounded retry (3 attempts, ~4s apart) covers a transient failure (e.g. a cold cluster) without
  // ever trapping the user: `dataViewsReady` always eventually flips to true.
  const [dataViewsReady, setDataViewsReady] = useState(false);
  useEffect(() => {
    let cancelled = false;
    const MAX_ATTEMPTS = 3;
    const RETRY_DELAY_MS = 4000;

    const attempt = (n: number) => {
      core.http
        .post('/api/tlsoc/data_views/_ensure', { body: JSON.stringify({ perEndpoint: true }) })
        .then(() => {
          if (!cancelled) setDataViewsReady(true);
        })
        .catch(() => {
          if (cancelled) return;
          if (n < MAX_ATTEMPTS) {
            setTimeout(() => attempt(n + 1), RETRY_DELAY_MS);
          } else {
            // Never trap the user behind a failed ensure — proceed regardless.
            setDataViewsReady(true);
          }
        });
    };
    attempt(1);

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const live = vm?.state === 'live';
  const freshColor = live && vm?.kpis ? freshnessColor(vm.kpis.freshness, nowMs) : 'subdued';
  const liveDot =
    refreshMs === 0 ? { color: 'subdued' as const, label: 'Paused' } : freshColor === 'success' ? { color: 'success' as const, label: 'Live' } : freshColor === 'warning' ? { color: 'warning' as const, label: 'Stale' } : { color: 'primary' as const, label: 'Live' };

  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="m">
          <EuiFlexItem>
            <EuiTitle size="l">
              <h1>Security operations overview</h1>
            </EuiTitle>
            <EuiText color="subdued" size="s">
              <p>Collection health across every endpoint and log source feeding your SOC.</p>
            </EuiText>
          </EuiFlexItem>
          {live && (
            <EuiFlexItem grow={false}>
              <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
                {refreshing && (
                  <EuiFlexItem grow={false}>
                    <EuiLoadingSpinner size="s" />
                  </EuiFlexItem>
                )}
                <EuiFlexItem grow={false}>
                  <EuiHealth color={liveDot.color}>{liveDot.label}</EuiHealth>
                </EuiFlexItem>
                <EuiFlexItem grow={false} style={{ minWidth: 90 }}>
                  <EuiSelect
                    compressed
                    prepend="Refresh"
                    options={REFRESH_OPTIONS}
                    value={String(refreshMs)}
                    onChange={(e) => setRefreshMs(Number(e.target.value))}
                    aria-label="Auto-refresh interval"
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButtonGroup
                    legend="Time range"
                    options={OVERVIEW_WINDOWS.map((w) => ({ id: w.id, label: w.id }))}
                    idSelected={window}
                    onChange={(id) => setWindow(id)}
                    buttonSize="compressed"
                  />
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiToolTip content="Refresh now">
                    <EuiButtonIcon iconType="refresh" aria-label="Refresh now" onClick={reload} />
                  </EuiToolTip>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiToolTip content="Add another endpoint or log source">
                    <EuiButtonIcon
                      iconType="iInCircle"
                      aria-label="How to add a source"
                      onClick={() => setShowGuide(true)}
                    />
                  </EuiToolTip>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>

        {live && (
          <>
            <EuiSpacer size="m" />
            <FilterBar
              filters={filters}
              onChange={setFilters}
              options={{
                org: vm?.orgValues,
                dept: vm?.topDepts,
                env: vm?.envValues,
                endpoint: vm?.topEndpoints,
                logSource: vm?.topSources,
              }}
            />
            <EuiHorizontalRule margin="m" />
          </>
        )}

        {!live && <EuiSpacer size="l" />}

        {!dataViewsReady && !vm && <SeedingState />}

        {dataViewsReady && loading && !vm && (
          <EuiFlexGroup justifyContent="center" alignItems="center" style={{ minHeight: 240 }}>
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="xl" />
            </EuiFlexItem>
          </EuiFlexGroup>
        )}

        {error && (
          <EuiCallOut title="Could not load the overview" color="danger" iconType="alert">
            <EuiText size="s">
              <p>{error}</p>
            </EuiText>
          </EuiCallOut>
        )}

        {vm && vm.state === 'pristine' && (
          <PristineState indexPattern={vm.indexPattern} onRefresh={reload} refreshing={refreshing} />
        )}

        {vm && vm.state === 'live' && (
          <LiveDashboard vm={vm} darkMode={darkMode} nowMs={nowMs} onWiden={() => setWindow('1y')} />
        )}

        {showGuide && (
          <EuiFlyout ownFocus onClose={() => setShowGuide(false)} size="m" aria-labelledby="tlsoc-add-source">
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m">
                <h2 id="tlsoc-add-source">Add an endpoint or log source</h2>
              </EuiTitle>
              <EuiSpacer size="xs" />
              <EuiText size="s" color="subdued">
                <p>Onboard another device or a new log type — the same agentless flow.</p>
              </EuiText>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <OnboardingGuide withIntro={false} />
              <EuiSpacer size="m" />
              <EuiButton onClick={() => { setShowGuide(false); reload(); }} iconType="refresh">
                Done — refresh the overview
              </EuiButton>
            </EuiFlyoutBody>
          </EuiFlyout>
        )}
      </EuiPageBody>
    </EuiPage>
  );
};
