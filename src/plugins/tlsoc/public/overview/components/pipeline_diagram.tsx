/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { EuiPanel, EuiText } from '@elastic/eui';
import { euiThemeVars } from '@osd/ui-shared-deps/theme';

/**
 * The agentless collection pipeline, left to right. Rendered with theme tokens (not hard-coded
 * colors) so it reads correctly in light and dark. The final "TLSOC" node is highlighted as the
 * stage the user is looking at. Deliberately agentless-only — no agent-based collector is shown.
 */
const NODES: Array<{ label: string; caption: string }> = [
  { label: 'Endpoints', caption: 'rsyslog forwarding' },
  { label: 'Kafka', caption: 'log transport' },
  { label: 'FOSS SOC Engine', caption: 'parse & normalize to ECS' },
  { label: 'OpenSearch', caption: 'index & store' },
  { label: 'TLSOC', caption: 'detect, investigate, respond' },
];

export const PipelineDiagram: React.FC = () => {
  return (
    <div
      role="img"
      aria-label="Agentless pipeline: Endpoints to Kafka to FOSS SOC Engine to OpenSearch to TLSOC"
      style={{
        display: 'flex',
        alignItems: 'stretch',
        flexWrap: 'wrap',
        gap: euiThemeVars.euiSizeS,
      }}
    >
      {NODES.map((node, i) => {
        const isLast = i === NODES.length - 1;
        return (
          <React.Fragment key={node.label}>
            <EuiPanel
              hasBorder
              hasShadow={false}
              paddingSize="m"
              color={isLast ? 'primary' : 'subdued'}
              style={{ flex: '1 1 140px', minWidth: 120, textAlign: 'center' }}
            >
              <EuiText size="s">
                <strong>{node.label}</strong>
              </EuiText>
              <EuiText size="xs" color="subdued">
                {node.caption}
              </EuiText>
            </EuiPanel>
            {!isLast && (
              <div
                aria-hidden
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  color: euiThemeVars.euiTextSubduedColor,
                  fontSize: euiThemeVars.euiSizeL,
                  fontWeight: 700,
                }}
              >
                →
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};
