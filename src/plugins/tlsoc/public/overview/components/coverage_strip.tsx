/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiText, EuiFlexGroup, EuiFlexItem, EuiToolTip } from '@elastic/eui';
import { euiThemeVars } from '@osd/ui-shared-deps/theme';
import { OverviewKpis } from '../../../common/overview/types';
import { compactNumber, timeAgo, freshnessColor } from '../format';
import { Sparkline } from './sparkline';

interface CoverageStripProps {
  kpis: OverviewKpis;
  nowMs: number;
}

type TileColor = 'success' | 'subdued' | 'warning' | 'danger' | 'default';

function humanizeMs(ms: number | null): string {
  if (ms === null) return 'n/a';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;
}

const Tile: React.FC<{
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  color?: TileColor;
  tip?: string;
}> = ({ label, value, sub, color = 'default', tip }) => {
  const valueColor =
    color === 'success'
      ? euiThemeVars.euiColorSuccessText
      : color === 'warning'
      ? euiThemeVars.euiColorWarningText
      : color === 'danger'
      ? euiThemeVars.euiColorDangerText
      : euiThemeVars.euiTextColor;
  const inner = (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" style={{ height: '100%' }}>
      <div style={{ fontSize: 24, fontWeight: 700, lineHeight: 1.15, color: valueColor }}>{value}</div>
      <EuiText size="xs" color="subdued">
        <p style={{ marginBottom: 0 }}>{label}</p>
      </EuiText>
      {sub && (
        <EuiText size="xs" color="subdued">
          <p style={{ marginTop: 2, opacity: 0.8 }}>{sub}</p>
        </EuiText>
      )}
    </EuiPanel>
  );
  return (
    <EuiFlexItem style={{ minWidth: 150 }}>{tip ? <EuiToolTip content={tip}>{inner}</EuiToolTip> : inner}</EuiFlexItem>
  );
};

/** Coverage & collection-health — the SIEM heartbeat strip. */
export const CoverageStrip: React.FC<CoverageStripProps> = ({ kpis, nowMs }) => {
  const fresh = kpis.freshness ? timeAgo(kpis.freshness, nowMs) : '—';
  const freshColor = freshnessColor(kpis.freshness, nowMs);

  return (
    <EuiFlexGroup gutterSize="m" wrap responsive>
      <Tile label="Events in window" value={compactNumber(kpis.eventsInWindow)} />

      <EuiFlexItem style={{ minWidth: 170 }}>
        <EuiPanel hasBorder hasShadow={false} paddingSize="m" style={{ height: '100%' }}>
          <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
            <EuiFlexItem grow={false}>
              <div style={{ fontSize: 24, fontWeight: 700, lineHeight: 1.15 }}>{kpis.epsNow}</div>
            </EuiFlexItem>
            <EuiFlexItem>
              <Sparkline values={kpis.eventsPerMin} />
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiText size="xs" color="subdued">
            <p style={{ marginBottom: 0 }}>Events/sec (last 60m)</p>
          </EuiText>
        </EuiPanel>
      </EuiFlexItem>

      <Tile
        label="Endpoints reporting"
        value={kpis.endpoints}
        sub={kpis.endpointsFromHostName ? 'via host.name' : undefined}
        tip="Distinct hosts forwarding logs (observer.source_host)"
      />
      <Tile
        label="Log sources"
        value={kpis.logSources}
        tip="Distinct log source programs (observer.source_program)"
      />
      {(kpis.orgs > 0 || kpis.depts > 0) && (
        <Tile
          label="Orgs · Departments"
          value={`${kpis.orgs} · ${kpis.depts}`}
          tip="Distinct observer.org and observer.dept"
        />
      )}
      {kpis.ingestLagP50Ms !== null && (
        <Tile
          label="Ingest lag (p50 · p95)"
          value={humanizeMs(kpis.ingestLagP50Ms)}
          sub={`p95 ${humanizeMs(kpis.ingestLagP95Ms)}`}
          color={kpis.ingestLagP95Ms !== null && kpis.ingestLagP95Ms > 10000 ? 'warning' : 'success'}
          tip="Time from event to index (event.ingested − @timestamp)"
        />
      )}
      <Tile label="Last event" value={fresh} color={freshColor} tip="Freshness — newest @timestamp in window" />
      {kpis.parseFallbackPct !== null && (
        <Tile
          label="Parse fallback"
          value={`${(kpis.parseFallbackPct * 100).toFixed(1)}%`}
          color={kpis.parseFallbackPct > 0.02 ? 'warning' : 'success'}
          tip="Events the engine could not time-parse (event.timestamp_source: ingest_fallback)"
        />
      )}
    </EuiFlexGroup>
  );
};
