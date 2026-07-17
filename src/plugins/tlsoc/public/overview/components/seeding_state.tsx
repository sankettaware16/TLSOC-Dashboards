/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiTitle, EuiText, EuiSpacer, EuiFlexGroup, EuiFlexItem, EuiLoadingSpinner } from '@elastic/eui';

/**
 * PROB-2 WORKSPACE-FLOW fix: a brief branded interstitial shown while the Overview page's
 * data-view `_ensure` call (see `overview_app.tsx`) is still in flight on first entry into a
 * workspace. The client-side workspace-entry hook (`public/plugin.ts`) is the primary fix and
 * usually wins the race, but this covers the moment between page load and that POST resolving so
 * the analyst never sees a jarring flash of "no data" state. Mirrors `PristineState`'s panel
 * styling/branding; deliberately much simpler — this is a transient loading state, not onboarding.
 */
export const SeedingState: React.FC = () => {
  return (
    <EuiPanel hasBorder paddingSize="l">
      <EuiFlexGroup justifyContent="center" alignItems="center" style={{ minHeight: 200 }}>
        <EuiFlexItem grow={false}>
          <EuiFlexGroup direction="column" alignItems="center" gutterSize="m">
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="xl" />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiTitle size="s">
                <h2>Setting up your data views…</h2>
              </EuiTitle>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText color="subdued" size="s" textAlign="center">
                <p>This only takes a moment the first time you enter a workspace.</p>
              </EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="xs" />
    </EuiPanel>
  );
};
