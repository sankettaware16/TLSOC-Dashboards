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

describe('AlertFlyout — Add exception action (v1.2.3 W4b, D9)', () => {
  beforeEach(() => {
    mockedUseRelatedDocs.mockReturnValue({ docs: [], loading: false, error: null });
  });

  const mountFlyout = (alertRaw: any, core: any) => {
    const alert = normalizeAlert(alertRaw, rules);
    let wrapper: any;
    act(() => {
      wrapper = mount(
        <AlertFlyout
          core={core}
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
    return wrapper;
  };

  it('renders the button for a bucket alert and pre-fills field=value from the group keys', () => {
    const core = coreMock.createStart();
    const wrapper = mountFlyout(rawBucketAlert, core);

    const button = wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionButton"]');
    expect(button).toHaveLength(1);

    act(() => {
      button.prop('onClick')();
    });
    wrapper.update();

    const select = wrapper.find('EuiSelect[data-test-subj="tlsocAddExceptionSelect"]');
    expect(select).toHaveLength(1);
    // Pre-filled from groupBy × bucketKeys: source.ip = 10.8.0.10.
    expect(select.prop('options')).toEqual([{ value: 0, text: 'source.ip = 10.8.0.10' }]);
  });

  it('confirm GETs the rule, appends the exception, and PUTs it back (enabled omitted)', async () => {
    const core = coreMock.createStart();
    (core.http.get as jest.Mock).mockResolvedValue({
      soId: 'so1',
      mode: 'stateful',
      rule: {
        name: 'SSH brute force >3 in 5m per IP',
        exceptions: [{ field: 'user.name', op: 'equals', values: ['svc-old'] }],
      },
    });
    (core.http.put as jest.Mock).mockResolvedValue({ id: 'mon1', soId: 'so1' });

    const wrapper = mountFlyout(rawBucketAlert, core);
    act(() => {
      wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionButton"]').prop('onClick')();
    });
    wrapper.update();
    await act(async () => {
      await wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionConfirm"]').prop('onClick')();
    });
    wrapper.update();

    expect(core.http.get).toHaveBeenCalledWith('/api/tlsoc/detection/monitors/so1');
    expect(core.http.put).toHaveBeenCalledTimes(1);
    const [path, opts] = (core.http.put as jest.Mock).mock.calls[0];
    expect(path).toBe('/api/tlsoc/detection/monitors/so1');
    const body = JSON.parse(opts.body);
    expect(body.mode).toBe('stateful');
    expect(body.enabled).toBeUndefined(); // the route preserves the current enabled state
    expect(body.rule.exceptions).toEqual([
      { field: 'user.name', op: 'equals', values: ['svc-old'] }, // pre-existing entry kept
      { field: 'source.ip', op: 'equals', values: ['10.8.0.10'] }, // the pre-filled addition
    ]);

    // The success confirmation renders.
    expect(
      wrapper.find('EuiCallOut[data-test-subj="tlsocAddExceptionDone"]')
    ).toHaveLength(1);
  });

  it('surfaces the server error verbatim (e.g. the DETECTION_WRITERS 403) without closing', async () => {
    const core = coreMock.createStart();
    (core.http.get as jest.Mock).mockRejectedValue({
      body: { message: 'You do not have permission to edit detections.' },
    });

    const wrapper = mountFlyout(rawBucketAlert, core);
    act(() => {
      wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionButton"]').prop('onClick')();
    });
    wrapper.update();
    await act(async () => {
      await wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionConfirm"]').prop('onClick')();
    });
    wrapper.update();

    expect(core.http.put).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain('You do not have permission to edit detections.');
    // The panel stays open for retry/cancel.
    expect(wrapper.find('[data-test-subj="tlsocAddExceptionPanel"]').length).toBeGreaterThan(0);
  });

  it('doc-level alert: candidates come from the highlighted related-doc fields', () => {
    mockedUseRelatedDocs.mockReturnValue({
      docs: [
        {
          id: 'd1',
          index: 'logs-*',
          found: true,
          source: { user: { name: 'jdoe' }, source: { ip: '66.66.66.66' } },
        },
      ],
      loading: false,
      error: null,
    });
    const core = coreMock.createStart();
    const wrapper = mountFlyout(rawDocAlert, core);
    act(() => {
      wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionButton"]').prop('onClick')();
    });
    wrapper.update();
    const options = wrapper
      .find('EuiSelect[data-test-subj="tlsocAddExceptionSelect"]')
      .prop('options') as Array<{ text: string }>;
    expect(options.map((o) => o.text)).toEqual(
      expect.arrayContaining(['user.name = jdoe', 'source.ip = 66.66.66.66'])
    );
  });

  it('no button when the alert has no known rule (nothing to attach the exception to)', () => {
    const orphanAlert = { ...rawBucketAlert, monitor_id: 'unknown-monitor' };
    const core = coreMock.createStart();
    const wrapper = mountFlyout(orphanAlert, core);
    expect(wrapper.find('EuiButton[data-test-subj="tlsocAddExceptionButton"]')).toHaveLength(0);
  });
});
