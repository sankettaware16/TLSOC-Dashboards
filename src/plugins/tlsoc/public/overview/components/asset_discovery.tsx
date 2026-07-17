/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiTitle, EuiSpacer, EuiText, EuiFlexGroup, EuiFlexItem, EuiBadge, EuiIcon } from '@elastic/eui';
import { euiThemeVars } from '@osd/ui-shared-deps/theme';
import { AssetRow } from '../../../common/overview/types';
import { SOURCE_TYPE_LABELS, SourceType } from '../../../common/overview/source_types';
import { timeAgo, compactNumber } from '../format';

interface AssetDiscoveryProps {
  newEndpoints: AssetRow[];
  newSources: AssetRow[];
  silentSources: AssetRow[];
  silentEndpoints: AssetRow[];
  nowMs: number;
}

const AssetList: React.FC<{
  title: string;
  accent: string;
  icon: string;
  rows: Array<{ row: AssetRow; kind: 'endpoint' | 'source' }>;
  timeField: 'firstSeen' | 'lastSeen';
  timeLabel: string;
  emptyText: string;
  nowMs: number;
}> = ({ title, accent, icon, rows, timeField, timeLabel, emptyText, nowMs }) => {
  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" style={{ height: '100%', borderLeft: `3px solid ${accent}` }}>
      <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiIcon type={icon} color={accent} />
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiTitle size="xxs">
            <h3>
              {title} <EuiBadge color="hollow">{rows.length}</EuiBadge>
            </h3>
          </EuiTitle>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      {rows.length === 0 ? (
        <EuiText size="s" color="subdued">
          <p>{emptyText}</p>
        </EuiText>
      ) : (
        rows.slice(0, 8).map(({ row, kind }) => (
          <EuiFlexGroup key={`${kind}:${row.name}`} gutterSize="s" alignItems="center" responsive={false} style={{ marginBottom: 4 }}>
            <EuiFlexItem grow={false}>
              <EuiBadge color={kind === 'endpoint' ? 'default' : 'hollow'}>
                {kind === 'endpoint' ? 'host' : row.type ? SOURCE_TYPE_LABELS[row.type as SourceType] ?? row.type : 'source'}
              </EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem>
              <EuiText size="xs" className="eui-textTruncate" title={row.name}>
                <strong>{row.name}</strong>
              </EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued">
                {timeLabel} {timeAgo(row[timeField], nowMs)} · {compactNumber(row.events)} ev
              </EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
        ))
      )}
    </EuiPanel>
  );
};

/** New (onboarded <24h) and Newly-Silent (collector stopped) — the SIEM owner's change radar. */
export const AssetDiscovery: React.FC<AssetDiscoveryProps> = ({
  newEndpoints,
  newSources,
  silentSources,
  silentEndpoints,
  nowMs,
}) => {
  const newRows = [
    ...newSources.map((row) => ({ row, kind: 'source' as const })),
    ...newEndpoints.map((row) => ({ row, kind: 'endpoint' as const })),
  ];
  const silentRows = [
    ...silentSources.map((row) => ({ row, kind: 'source' as const })),
    ...silentEndpoints.map((row) => ({ row, kind: 'endpoint' as const })),
  ];

  return (
    <EuiFlexGroup gutterSize="l">
      <EuiFlexItem>
        <AssetList
          title="New in last 24h"
          accent={euiThemeVars.euiColorSuccess}
          icon="plusInCircle"
          rows={newRows}
          timeField="firstSeen"
          timeLabel="onboarded"
          emptyText="No new sources or endpoints in the last 24h."
          nowMs={nowMs}
        />
      </EuiFlexItem>
      <EuiFlexItem>
        <AssetList
          title="Newly silent"
          accent={euiThemeVars.euiColorDanger}
          icon="alert"
          rows={silentRows}
          timeField="lastSeen"
          timeLabel="last seen"
          emptyText="All sources are reporting on schedule."
          nowMs={nowMs}
        />
      </EuiFlexItem>
    </EuiFlexGroup>
  );
};
