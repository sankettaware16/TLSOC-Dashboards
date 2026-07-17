/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiSpacer, EuiFlexGroup, EuiFlexItem, EuiCallOut, EuiButton, EuiText } from '@elastic/eui';
import { OverviewViewModel } from '../../../common/overview/types';
import { CoverageStrip } from './coverage_strip';
import { AssetDiscovery } from './asset_discovery';
import { EventsByTypeChart } from './events_by_type_chart';
import { SourceTypeBreakdown } from './source_type_breakdown';
import { GeoAsnPanel } from './geo_asn_panel';
import { KafkaTile } from './kafka_tile';
import { TopList } from './top_list';
import { RecentEventsTable } from './recent_events_table';
import { timeAgo } from '../format';

interface LiveDashboardProps {
  vm: OverviewViewModel;
  darkMode: boolean;
  nowMs: number;
  onWiden: () => void;
}

/** The SIEM collection cockpit (state==='live'). */
export const LiveDashboard: React.FC<LiveDashboardProps> = ({ vm, darkMode, nowMs, onWiden }) => {
  const kpis = vm.kpis!;

  if (vm.emptyWindow) {
    return (
      <>
        <CoverageStrip kpis={kpis} nowMs={nowMs} />
        <EuiSpacer size="l" />
        <EuiCallOut title="No events in the selected time range" color="primary" iconType="clock">
          <EuiText size="s">
            <p>
              This window is quiet, but your onboarded sources have data.
              {vm.latestEventAllTime ? ` The most recent event was ${timeAgo(vm.latestEventAllTime, nowMs)}.` : ''} Widen the
              range to see it.
            </p>
          </EuiText>
          <EuiSpacer size="s" />
          <EuiButton size="s" onClick={onWiden} iconType="expand">
            Widen to last year
          </EuiButton>
        </EuiCallOut>
      </>
    );
  }

  return (
    <>
      {/* P1 — coverage & collection-health heartbeat */}
      <CoverageStrip kpis={kpis} nowMs={nowMs} />
      <EuiSpacer size="l" />

      {/* P2 — asset-discovery (new + newly silent) */}
      <AssetDiscovery
        newEndpoints={vm.newEndpoints ?? []}
        newSources={vm.newSources ?? []}
        silentSources={vm.silentSources ?? []}
        silentEndpoints={vm.silentEndpoints ?? []}
        nowMs={nowMs}
      />
      <EuiSpacer size="l" />

      {/* P4 — events over time, by source type */}
      <EventsByTypeChart data={vm.eventsOverTime ?? []} darkMode={darkMode} />
      <EuiSpacer size="l" />

      {/* P3 + P7 — source-type breakdown + ECS category/kind */}
      <EuiFlexGroup gutterSize="l">
        <EuiFlexItem grow={3}>
          <SourceTypeBreakdown sourceTypes={vm.sourceTypes ?? []} />
        </EuiFlexItem>
        <EuiFlexItem grow={2}>
          <EuiFlexGroup gutterSize="l" direction="column">
            {vm.eventCategory && vm.eventCategory.length > 0 && (
              <EuiFlexItem>
                <TopList title="Event categories (ECS)" buckets={vm.eventCategory} />
              </EuiFlexItem>
            )}
            {vm.eventOutcome && vm.eventOutcome.length > 0 && (
              <EuiFlexItem>
                <TopList title="Event outcomes" buckets={vm.eventOutcome} />
              </EuiFlexItem>
            )}
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="l" />

      {/* P5 — volume leaders */}
      <EuiFlexGroup gutterSize="l">
        {vm.topEndpoints && (
          <EuiFlexItem>
            <TopList title="Top endpoints (by volume)" buckets={vm.topEndpoints} />
          </EuiFlexItem>
        )}
        {vm.topSources && (
          <EuiFlexItem>
            <TopList title="Top log sources" buckets={vm.topSources} />
          </EuiFlexItem>
        )}
        {vm.topDepts && vm.topDepts.length > 0 ? (
          <EuiFlexItem>
            <TopList title="Top departments" buckets={vm.topDepts} />
          </EuiFlexItem>
        ) : (
          <EuiFlexItem>
            <TopList title="Top source IPs" buckets={vm.topSourceIps ?? []} />
          </EuiFlexItem>
        )}
      </EuiFlexGroup>
      <EuiSpacer size="l" />

      {/* P6 — geo + ASN */}
      <GeoAsnPanel countries={vm.topCountries} asns={vm.topAsns} />
      <EuiSpacer size="l" />

      {/* recent events across all source types */}
      <RecentEventsTable events={vm.recentEvents ?? []} />
      <EuiSpacer size="l" />

      {/* P9 — honesty tile */}
      <KafkaTile />
    </>
  );
};
