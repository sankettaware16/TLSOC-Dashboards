/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiTitle, EuiSpacer, EuiText, EuiFlexGroup, EuiFlexItem } from '@elastic/eui';
import { euiThemeVars } from '@osd/ui-shared-deps/theme';
import { TermBucket } from '../../../common/overview/types';
import { compactNumber } from '../format';

interface TopListProps {
  title: string;
  buckets: TermBucket[];
  emptyText?: string;
}

/**
 * A ranked "top N" panel: each row is a label + a proportional bar + count. Bars use the theme
 * primary color so they read in light and dark. Matches the hand-rolled panel style used across
 * the tlsoc plugin (no EuiStat / no chart dependency needed for these).
 */
export const TopList: React.FC<TopListProps> = ({ title, buckets, emptyText }) => {
  const max = buckets.reduce((m, b) => Math.max(m, b.count), 0) || 1;

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" style={{ height: '100%' }}>
      <EuiTitle size="xxs">
        <h3>{title}</h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {buckets.length === 0 ? (
        <EuiText size="s" color="subdued">
          <p>{emptyText ?? 'No data in this range.'}</p>
        </EuiText>
      ) : (
        buckets.map((b) => (
          <div key={b.key} style={{ marginBottom: euiThemeVars.euiSizeS }}>
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
              <EuiFlexItem>
                <EuiText size="xs" className="eui-textTruncate" title={b.key}>
                  {b.key}
                </EuiText>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="xs" color="subdued">
                  <strong>{compactNumber(b.count)}</strong>
                </EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
            <div
              style={{
                height: 4,
                borderRadius: 2,
                marginTop: 2,
                width: `${Math.max(2, (b.count / max) * 100)}%`,
                // Inline styles are unreachable by stylesheets, so the accent must come through
                // the CSS var published by accent/apply.ts. euiThemeVars.euiColorPrimary is the
                // UNPATCHED upstream teal (the euiThemeVars JSON was never recolored) — never
                // use it for accent surfaces. No hex fallback: the var is ALWAYS set by the
                // always-on default patch, and a hardcoded fallback would be mode-wrong in dark.
                backgroundColor: 'var(--tlsoc-accent)',
              }}
            />
          </div>
        ))
      )}
    </EuiPanel>
  );
};
