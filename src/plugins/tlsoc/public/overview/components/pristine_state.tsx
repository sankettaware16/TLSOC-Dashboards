/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  EuiPanel,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiIcon,
  EuiHorizontalRule,
  EuiButton,
} from '@elastic/eui';
import { PipelineDiagram } from './pipeline_diagram';
import { OnboardingGuide } from './onboarding_guide';

interface PristineStateProps {
  indexPattern: string;
  /** poll the API now (the page also auto-polls every 12s and flips to the cockpit on first data) */
  onRefresh: () => void;
  refreshing?: boolean;
}

/**
 * First-run onboarding page — shown when no logs have been ingested yet (fresh install, no Kafka
 * topics, no sources onboarded). Explains the agentless pipeline and walks the user through
 * onboarding their first endpoint + log source with copy-paste commands. Polls in the background
 * and auto-flips to the live cockpit the moment data arrives; a Refresh button forces a re-check.
 */
export const PristineState: React.FC<PristineStateProps> = ({ indexPattern, onRefresh, refreshing }) => {
  return (
    <>
      {/* Hero */}
      <EuiPanel hasBorder paddingSize="l">
        <EuiTitle size="l">
          <h1>Welcome to your Security Operations Center</h1>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiText color="subdued">
          <p>
            No logs are flowing yet. TLSOC collects logs <strong>agentlessly</strong> — you point a
            device's rsyslog forwarder at the collector and its logs are parsed, normalized and
            searchable here. Onboard your first source below and this page turns into your live SOC
            overview automatically.
          </p>
        </EuiText>
        <EuiSpacer size="l" />
        <PipelineDiagram />
      </EuiPanel>

      <EuiSpacer size="l" />

      <EuiFlexGroup gutterSize="l" alignItems="flexStart">
        <EuiFlexItem grow={3}>
          <EuiPanel hasBorder paddingSize="l">
            <EuiTitle size="s">
              <h2>Onboard your first endpoint &amp; log source</h2>
            </EuiTitle>
            <EuiSpacer size="m" />
            <OnboardingGuide withIntro />
          </EuiPanel>
        </EuiFlexItem>

        <EuiFlexItem grow={1}>
          {/* Listening + refresh */}
          <EuiPanel hasBorder paddingSize="l">
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size="m" />
              </EuiFlexItem>
              <EuiFlexItem>
                <EuiTitle size="xs">
                  <h3>Listening for your first events…</h3>
                </EuiTitle>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="s" />
            <EuiText size="s" color="subdued">
              <p>
                Watching <code>{indexPattern}</code>. This page refreshes on its own and switches to
                the live cockpit as soon as data lands.
              </p>
            </EuiText>
            <EuiSpacer size="s" />
            <EuiButton fill iconType="refresh" onClick={onRefresh} isLoading={refreshing} fullWidth>
              I've onboarded a source — refresh
            </EuiButton>

            <EuiHorizontalRule margin="m" />

            <EuiTitle size="xxs">
              <h4>Why agentless?</h4>
            </EuiTitle>
            <EuiSpacer size="s" />
            {[
              'No software to install or maintain on your endpoints.',
              'Uses the rsyslog forwarder your servers already run.',
              'Logs are parsed and normalized to a common schema (ECS) centrally.',
              'Add or remove sources without touching TLSOC.',
            ].map((line) => (
              <EuiFlexGroup key={line} gutterSize="s" alignItems="flexStart" responsive={false}>
                <EuiFlexItem grow={false}>
                  <EuiIcon type="checkInCircleFilled" color="success" />
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiText size="s">
                    <p>{line}</p>
                  </EuiText>
                </EuiFlexItem>
              </EuiFlexGroup>
            ))}
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>
    </>
  );
};
