/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { buildBucketContext, buildReason, substituteFieldPlaceholders } from './reason';
import { TlsocAlert } from './types';

function baseAlert(overrides: Partial<TlsocAlert> = {}): TlsocAlert {
  return {
    id: 'a1',
    monitorId: 'm1',
    monitorName: 'monitor-name',
    triggerName: 'trigger',
    state: 'ACTIVE',
    severity: '2',
    severityLabel: 'high',
    findingIds: [],
    relatedDocIds: [],
    startTime: null,
    lastNotificationTime: null,
    acknowledgedTime: null,
    endTime: null,
    errorMessage: null,
    rule: { soId: 'so1', name: 'Suspicious login', mode: 'stateless', index: 'foo-*' },
    ruleKnown: true,
    ...overrides,
  };
}

describe('buildReason — doc-level', () => {
  it('full doc: host, source.ip:port, and user all present', () => {
    const alert = baseAlert();
    const doc = {
      host: { name: 'web-01' },
      source: { ip: '66.66.66.66', port: 443 },
      user: { name: 'jdoe' },
    };
    expect(buildReason(alert, doc)).toBe(
      'Event from web-01 (66.66.66.66:443, user jdoe) matched "Suspicious login" — high alert.'
    );
  });

  it('partial doc: missing user.name → omits the user clause', () => {
    const alert = baseAlert();
    const doc = { host: { name: 'web-01' }, source: { ip: '66.66.66.66', port: 443 } };
    expect(buildReason(alert, doc)).toBe(
      'Event from web-01 (66.66.66.66:443) matched "Suspicious login" — high alert.'
    );
  });

  it('partial doc: missing source.port → ip without a port suffix', () => {
    const alert = baseAlert();
    const doc = { host: { name: 'web-01' }, source: { ip: '66.66.66.66' } };
    expect(buildReason(alert, doc)).toBe(
      'Event from web-01 (66.66.66.66) matched "Suspicious login" — high alert.'
    );
  });

  it('partial doc: missing source.ip but user present → only the user clause', () => {
    const alert = baseAlert();
    const doc = { host: { name: 'web-01' }, user: { name: 'jdoe' } };
    expect(buildReason(alert, doc)).toBe(
      'Event from web-01 (user jdoe) matched "Suspicious login" — high alert.'
    );
  });

  it('missing host.name → "Event" (no "from X"), rest still composed', () => {
    const alert = baseAlert();
    const doc = { source: { ip: '66.66.66.66' } };
    expect(buildReason(alert, doc)).toBe(
      'Event (66.66.66.66) matched "Suspicious login" — high alert.'
    );
  });

  it('doc with none of the known fields → bare "Event matched" sentence', () => {
    const alert = baseAlert();
    expect(buildReason(alert, {})).toBe('Event matched "Suspicious login" — high alert.');
  });

  it('falls back to monitorName when rule is unknown', () => {
    const alert = baseAlert({ rule: null, ruleKnown: false });
    const doc = { host: { name: 'web-01' } };
    expect(buildReason(alert, doc)).toBe('Event from web-01 matched "monitor-name" — high alert.');
  });
});

describe('buildReason — bucket-level (no doc, bucketKeys present)', () => {
  it('composes groupBy = bucketKeys with the rule threshold sentence', () => {
    const alert = baseAlert({
      rule: {
        soId: 'so1',
        name: 'Request flood',
        mode: 'stateful',
        index: 'foo-*',
        groupBy: ['source.ip'],
      },
      bucketKeys: ['66.66.66.66'],
    });
    expect(buildReason(alert)).toBe(
      '"Request flood": source.ip = 66.66.66.66 crossed the rule threshold — high alert.'
    );
  });

  it('multiple groupBy fields / bucketKeys, joined in order', () => {
    const alert = baseAlert({
      rule: {
        soId: 'so1',
        name: 'Multi-field flood',
        mode: 'stateful',
        index: 'foo-*',
        groupBy: ['source.ip', 'user.name'],
      },
      bucketKeys: ['66.66.66.66', 'jdoe'],
    });
    expect(buildReason(alert)).toBe(
      '"Multi-field flood": source.ip, user.name = 66.66.66.66, jdoe crossed the rule threshold — high alert.'
    );
  });

  it('groupBy metadata absent on the rule → falls back to bare bucketKeys', () => {
    const alert = baseAlert({
      rule: { soId: 'so1', name: 'Legacy threshold', mode: 'stateful', index: 'foo-*' },
      bucketKeys: ['66.66.66.66'],
    });
    expect(buildReason(alert)).toBe(
      '"Legacy threshold": 66.66.66.66 crossed the rule threshold — high alert.'
    );
  });

  // ---------------------------------------------------------------------------
  // WS-18 (PROB-18): bucketDocCount present → the count-prefixed sentence.
  // ---------------------------------------------------------------------------
  it('bucketDocCount present → leads with the count (live fixture shape)', () => {
    const alert = baseAlert({
      rule: {
        soId: 'so1',
        name: 'SSH brute force >3 in 5m per IP',
        mode: 'stateful',
        index: 'foo-*',
        groupBy: ['source.ip'],
      },
      bucketKeys: ['10.8.0.10'],
      bucketDocCount: 14,
    });
    expect(buildReason(alert)).toBe(
      '14 events grouped by source.ip = 10.8.0.10 crossed the threshold — high alert.'
    );
  });

  it('bucketDocCount absent → the existing named-rule sentence (no-count fallback)', () => {
    const alert = baseAlert({
      rule: {
        soId: 'so1',
        name: 'Request flood',
        mode: 'stateful',
        index: 'foo-*',
        groupBy: ['source.ip'],
      },
      bucketKeys: ['66.66.66.66'],
    });
    expect(buildReason(alert)).toBe(
      '"Request flood": source.ip = 66.66.66.66 crossed the rule threshold — high alert.'
    );
  });
});

describe('buildReason — fallback (no doc, no bucketKeys)', () => {
  it('names the rule + severity only', () => {
    const alert = baseAlert();
    expect(buildReason(alert)).toBe('"Suspicious login" fired — high alert.');
  });

  it('empty bucketKeys array is treated as absent (falls through to fallback)', () => {
    const alert = baseAlert({ bucketKeys: [] });
    expect(buildReason(alert)).toBe('"Suspicious login" fired — high alert.');
  });

  it('unknown severity still renders (no crash)', () => {
    const alert = baseAlert({ severityLabel: 'unknown' });
    expect(buildReason(alert)).toBe('"Suspicious login" fired — unknown alert.');
  });
});

describe('substituteFieldPlaceholders', () => {
  it('substitutes a simple top-level placeholder', () => {
    expect(substituteFieldPlaceholders('User: {{user.name}}', { user: { name: 'jdoe' } })).toBe(
      'User: jdoe'
    );
  });

  it('substitutes multiple placeholders', () => {
    const md = 'Host {{host.name}} saw {{source.ip}}';
    expect(
      substituteFieldPlaceholders(md, { host: { name: 'web-01' }, source: { ip: '1.2.3.4' } })
    ).toBe('Host web-01 saw 1.2.3.4');
  });

  it('tolerates whitespace inside the braces', () => {
    expect(substituteFieldPlaceholders('{{ host.name }}', { host: { name: 'web-01' } })).toBe(
      'web-01'
    );
  });

  it('missing field → em dash', () => {
    expect(substituteFieldPlaceholders('User: {{user.name}}', { host: { name: 'web-01' } })).toBe(
      'User: —'
    );
  });

  it('undefined context → em dash for every placeholder', () => {
    expect(substituteFieldPlaceholders('{{a.b}} / {{c.d}}', undefined)).toBe('— / —');
  });

  it('array-valued field → comma-joined', () => {
    expect(substituteFieldPlaceholders('{{tags}}', { tags: ['a', 'b'] })).toBe('a, b');
  });

  it('object-valued field → JSON stringified', () => {
    expect(substituteFieldPlaceholders('{{geo}}', { geo: { country: 'IN' } })).toBe(
      '{"country":"IN"}'
    );
  });

  it('markdown with no placeholders is returned unchanged', () => {
    expect(substituteFieldPlaceholders('# No placeholders here', {})).toBe(
      '# No placeholders here'
    );
  });
});

describe('buildBucketContext', () => {
  it('pairs groupBy paths with bucketKeys values positionally', () => {
    expect(buildBucketContext(['source.ip'], ['66.66.66.66'])).toEqual({
      source: { ip: '66.66.66.66' },
    });
  });

  it('builds nested paths for multiple dotted fields without collision', () => {
    expect(buildBucketContext(['source.ip', 'source.port'], ['66.66.66.66', '443'])).toEqual({
      source: { ip: '66.66.66.66', port: '443' },
    });
  });

  it('handles a flat (non-dotted) field name', () => {
    expect(buildBucketContext(['host'], ['web-01'])).toEqual({ host: 'web-01' });
  });

  it('ignores extra groupBy entries with no matching bucketKeys value', () => {
    expect(buildBucketContext(['source.ip', 'user.name'], ['66.66.66.66'])).toEqual({
      source: { ip: '66.66.66.66' },
    });
  });

  it('empty inputs → empty object', () => {
    expect(buildBucketContext([], [])).toEqual({});
  });

  it('round-trips through substituteFieldPlaceholders for a bucket-alert runbook', () => {
    const ctx = buildBucketContext(['source.ip'], ['66.66.66.66']);
    expect(substituteFieldPlaceholders('Investigate {{source.ip}}', ctx)).toBe(
      'Investigate 66.66.66.66'
    );
  });

  // ---------------------------------------------------------------------------
  // WS-18 (PROB-18): named lookup via bucketKeyMap, preferred over the positional zip.
  // ---------------------------------------------------------------------------
  it('bucketKeyMap present → looks up by compositeSourceName(path), not position', () => {
    expect(buildBucketContext(['source.ip'], ['66.66.66.66'], { source_ip: '10.8.0.10' })).toEqual({
      source: { ip: '10.8.0.10' },
    });
  });

  it('bucketKeyMap present but missing an entry for a field → falls back to the positional value', () => {
    expect(
      buildBucketContext(['source.ip', 'user.name'], ['66.66.66.66', 'jdoe'], {
        source_ip: '10.8.0.10',
      })
    ).toEqual({ source: { ip: '10.8.0.10' }, user: { name: 'jdoe' } });
  });

  it('bucketKeyMap absent → unchanged positional behavior (backward-compatible)', () => {
    expect(buildBucketContext(['source.ip'], ['66.66.66.66'], undefined)).toEqual({
      source: { ip: '66.66.66.66' },
    });
  });

  it('bucketKeyMap named lookup round-trips through substituteFieldPlaceholders', () => {
    const ctx = buildBucketContext(['source.ip'], ['66.66.66.66'], { source_ip: '10.8.0.10' });
    expect(substituteFieldPlaceholders('Investigate {{source.ip}}', ctx)).toBe(
      'Investigate 10.8.0.10'
    );
  });
});
