/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { mount } from 'enzyme';
import { act } from 'react';
import { AlertFlyout } from './alert_flyout';
import { normalizeAlert, RuleRefMap } from '../../common/alerts';
import { coreMock } from '../../../../core/public/mocks';

// WS-18 (PROB-18): stub the related-docs fetch — tested in isolation by use_related_docs.test.ts
// (if it exists) / exercised via the mock's return value here, not a real HTTP round-trip.
jest.mock('./use_related_docs', () => ({
  useRelatedDocs: jest.fn(),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { useRelatedDocs } = require('./use_related_docs');
const mockedUseRelatedDocs = useRelatedDocs as jest.Mock;

// Live GET /_plugins/_alerting/monitors/alerts fixture (trimmed) — bucket data nests under
// agg_alert_content (WS-18 root cause). See normalize.test.ts for the full-shape unit coverage.
const rawBucketAlert = {
  id: 'JNKZcZ8BxjOJSPnTUcrh',
  monitor_id: 'c9KUcZ8BxjOJSPnTwMkL',
  monitor_name: 'SSH brute force >3 in 5m per IP',
  trigger_name: 'SSH brute force >3 in 5m per IP threshold breached',
  finding_ids: [],
  related_doc_ids: [],
  state: 'COMPLETED',
  error_message: null,
  severity: '1',
  start_time: 1784317301212,
  last_notification_time: 1784317301212,
  end_time: 1784317900911,
  acknowledged_time: null,
  agg_alert_content: {
    parent_bucket_path: 'tlsoc_groups',
    bucket_keys: ['10.8.0.10'],
    bucket: {
      doc_count: 14,
      key: { source_ip: '10.8.0.10' },
    },
  },
};

const rawDocAlert = {
  id: 'doc-alert-1',
  monitor_id: 'c9KUcZ8BxjOJSPnTwMkL',
  monitor_name: 'SSH brute force >3 in 5m per IP',
  trigger_name: 'SSH brute force >3 in 5m per IP threshold breached',
  finding_ids: [],
  related_doc_ids: ['d1|logs-*'],
  state: 'ACTIVE',
  error_message: null,
  severity: '1',
  start_time: 1784317301212,
  last_notification_time: 1784317301212,
  end_time: null,
  acknowledged_time: null,
};

const rules: RuleRefMap = {
  c9KUcZ8BxjOJSPnTwMkL: {
    soId: 'so1',
    name: 'SSH brute force >3 in 5m per IP',
    mode: 'stateful',
    index: 'logs-*',
    groupBy: ['source.ip'],
    threat: [
      {
        framework: 'MITRE ATT&CK',
        tactic: {
          id: 'TA0006',
          name: 'Credential Access',
          reference: 'https://attack.mitre.org/tactics/TA0006/',
        },
        technique: [
          {
            id: 'T1110',
            name: 'Brute Force',
            reference: 'https://attack.mitre.org/techniques/T1110/',
          },
        ],
      },
    ],
    riskScore: 80,
    note: 'Investigate {{source.ip}} for brute force attempts.',
    falsePositives: ['Known internal scanner'],
    references: ['https://example.com/runbook'],
  },
};

const noop = () => undefined;

describe('AlertFlyout — bucket-level alert (WS-18, PROB-18)', () => {
  beforeEach(() => {
    mockedUseRelatedDocs.mockReturnValue({ docs: [], loading: false, error: null });
  });

  it('renders the enriched bucket alert', () => {
    const alert = normalizeAlert(rawBucketAlert, rules);
    let wrapper: any;
    act(() => {
      wrapper = mount(
        <AlertFlyout
          core={coreMock.createStart()}
          alert={alert}
          onClose={noop}
          onAcknowledge={noop}
          canInvestigate={false}
          onInvestigate={noop}
          onCreateCase={noop}
        />
      );
    });
    wrapper.update();

    // Highlighted row: 'source.ip' -> '10.8.0.10' via the NAMED bucketKeyMap lookup.
    const highlightTitles = wrapper.find('EuiDescriptionListTitle').map((n: any) => n.text());
    const highlightDescriptions = wrapper
      .find('EuiDescriptionListDescription')
      .map((n: any) => n.text());
    expect(highlightTitles).toContain('source.ip');
    expect(highlightDescriptions).toContain('10.8.0.10');

    // MITRE badges render.
    const badgeText = wrapper.find('EuiBadge').map((n: any) => n.text());
    expect(
      badgeText.some((t: string) => t.includes('TA0006') && t.includes('Credential Access'))
    ).toBe(true);
    expect(badgeText.some((t: string) => t.includes('T1110') && t.includes('Brute Force'))).toBe(
      true
    );

    // Risk score renders.
    expect(badgeText).toContain('80 / 100');

    // Runbook renders with the substituted group value (via the named bucketKeyMap lookup).
    expect(wrapper.text()).toContain('Investigate 10.8.0.10 for brute force attempts.');

    // "Events in window" bottom row shows the bucket's doc_count.
    expect(highlightTitles).toContain('Events in window');
    expect(highlightDescriptions).toContain('14');
  });
});

describe('AlertFlyout — doc-level alert (no regression)', () => {
  beforeEach(() => {
    mockedUseRelatedDocs.mockReturnValue({
      docs: [
        {
          id: 'd1',
          index: 'logs-*',
          found: true,
          source: {
            host: { name: 'web-01' },
            source: { ip: '66.66.66.66', port: 443 },
            user: { name: 'jdoe' },
          },
        },
      ],
      loading: false,
      error: null,
    });
  });

  it('highlighted fields from the related doc still render', () => {
    const alert = normalizeAlert(rawDocAlert, rules);
    let wrapper: any;
    act(() => {
      wrapper = mount(
        <AlertFlyout
          core={coreMock.createStart()}
          alert={alert}
          onClose={noop}
          onAcknowledge={noop}
          canInvestigate={false}
          onInvestigate={noop}
          onCreateCase={noop}
        />
      );
    });
    wrapper.update();

    const highlightTitles = wrapper.find('EuiDescriptionListTitle').map((n: any) => n.text());
    const highlightDescriptions = wrapper
      .find('EuiDescriptionListDescription')
      .map((n: any) => n.text());
    expect(highlightTitles).toContain('host.name');
    expect(highlightDescriptions).toContain('web-01');
    expect(highlightTitles).toContain('source.ip');
    expect(highlightDescriptions).toContain('66.66.66.66');
    expect(highlightTitles).toContain('user.name');
    expect(highlightDescriptions).toContain('jdoe');

    // No bucket-only content leaks into a doc-level render.
    expect(highlightTitles).not.toContain('Events in window');
  });
});
