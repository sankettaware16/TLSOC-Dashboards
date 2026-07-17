/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiFlexGroup, EuiFlexItem, EuiIcon, EuiText, EuiBadge } from '@elastic/eui';

/**
 * Honesty tile: Kafka topic/broker/consumer-lag live in Kafka, NOT in the indexed logs. TLSOC's
 * system of record is OpenSearch — it measures ingest lag, freshness and silence at index time,
 * but cannot see in-flight Kafka backlog. We say so rather than fabricate a topic count from logs.
 */
export const KafkaTile: React.FC = () => (
  <EuiPanel hasBorder hasShadow={false} paddingSize="m" color="subdued">
    <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
      <EuiFlexItem grow={false}>
        <EuiIcon type="logstashIf" color="subdued" />
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiText size="s">
          <strong>Collection pipeline (Kafka)</strong> <EuiBadge color="hollow">Phase 6</EuiBadge>
        </EuiText>
        <EuiText size="xs" color="subdued">
          <p style={{ marginBottom: 0 }}>
            Broker health, topic list and consumer-lag come from a Kafka-admin integration (planned).
            TLSOC measures pipeline health from what has already landed in OpenSearch — ingest lag,
            freshness, and silent-source detection above.
          </p>
        </EuiText>
      </EuiFlexItem>
    </EuiFlexGroup>
  </EuiPanel>
);
