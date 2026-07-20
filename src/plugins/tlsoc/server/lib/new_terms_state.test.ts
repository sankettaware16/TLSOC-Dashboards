/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  NewTermsSweepTarget,
  SEEN_AGG,
  __resetNewTermsSweepDebounceForTests,
  bootstrapSeenValues,
  deleteSeenValuesDoc,
  ensureStateIndex,
  refreshSeenValuesForRules,
  refreshSeenValuesSweep,
} from './new_terms_state';
import { NewTermsRuleDefinition } from '../../common/detection/new_terms';

function aggResponse(keys: string[], sumOther = 0) {
  return {
    body: {
      aggregations: {
        [SEEN_AGG]: {
          buckets: keys.map((key) => ({ key, doc_count: 1 })),
          sum_other_doc_count: sumOther,
        },
      },
    },
  };
}

function mockEsClient(overrides: Record<string, any> = {}) {
  return {
    indices: {
      exists: jest.fn().mockResolvedValue({ body: true }),
      create: jest.fn().mockResolvedValue({ body: { acknowledged: true } }),
    },
    search: jest.fn().mockResolvedValue(aggResponse([])),
    index: jest.fn().mockResolvedValue({ body: { result: 'created' } }),
    delete: jest.fn().mockResolvedValue({ body: { result: 'deleted' } }),
    ...overrides,
  };
}

function mockLogger() {
  return { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } as any;
}

function rule(overrides: Partial<NewTermsRuleDefinition> = {}): NewTermsRuleDefinition {
  return {
    name: 'New user seen',
    severity: 'medium',
    index: 'fosstlsoc-logs-*',
    termField: 'user.name',
    historyWindow: { value: 30, unit: 'DAYS' },
    groupBy: ['user.name'],
    ...overrides,
  };
}

beforeEach(() => {
  __resetNewTermsSweepDebounceForTests();
});

describe('ensureStateIndex', () => {
  it('does nothing when the index exists', async () => {
    const es = mockEsClient();
    await ensureStateIndex(es);
    expect(es.indices.create).not.toHaveBeenCalled();
  });

  it('creates the index with the pinned mappings when absent', async () => {
    const es = mockEsClient();
    es.indices.exists.mockResolvedValue({ body: false });
    await ensureStateIndex(es);
    expect(es.indices.create).toHaveBeenCalledWith({
      index: 'tlsoc-detection-state',
      body: {
        settings: { index: { number_of_shards: 1, auto_expand_replicas: '0-1' } },
        mappings: {
          properties: {
            rule_id: { type: 'keyword' },
            values: { type: 'keyword' },
            truncated: { type: 'boolean' },
            updated_at: { type: 'date' },
          },
        },
      },
    });
  });

  it('treats a lost create race (resource_already_exists_exception) as success', async () => {
    const es = mockEsClient();
    es.indices.exists.mockResolvedValue({ body: false });
    es.indices.create.mockRejectedValue({
      meta: { body: { error: { type: 'resource_already_exists_exception' } } },
    });
    await expect(ensureStateIndex(es)).resolves.toBeUndefined();
  });

  it('rethrows any other create failure', async () => {
    const es = mockEsClient();
    es.indices.exists.mockResolvedValue({ body: false });
    es.indices.create.mockRejectedValue(
      Object.assign(new Error('boom'), { meta: { body: { error: { type: 'oh_no' } } } })
    );
    await expect(ensureStateIndex(es)).rejects.toThrow('boom');
  });
});

describe('bootstrapSeenValues', () => {
  it('aggregates the history window and PUTs the state doc (refresh: wait_for)', async () => {
    const es = mockEsClient();
    es.search.mockResolvedValue(aggResponse(['alice', 'bob']));

    const result = await bootstrapSeenValues(es, rule(), 'seen-so1-user.name', 'so1');

    expect(result).toEqual({ values: ['alice', 'bob'], truncated: false });
    expect(es.search).toHaveBeenCalledWith({
      index: 'fosstlsoc-logs-*',
      allow_no_indices: true,
      ignore_unavailable: true,
      body: {
        size: 0,
        query: {
          bool: {
            filter: [{ range: { '@timestamp': { gte: 'now-30d', lte: 'now' } } }],
          },
        },
        aggregations: {
          [SEEN_AGG]: { terms: { field: 'user.name', size: 65536 } },
        },
      },
    });
    expect(es.index).toHaveBeenCalledWith(
      expect.objectContaining({
        index: 'tlsoc-detection-state',
        id: 'seen-so1-user.name',
        refresh: 'wait_for',
        body: expect.objectContaining({
          rule_id: 'so1',
          values: ['alice', 'bob'],
          truncated: false,
        }),
      })
    );
  });

  it('includes the pre-filter as a query_string clause', async () => {
    const es = mockEsClient();
    await bootstrapSeenValues(
      es,
      rule({
        filter: {
          logic: 'AND',
          conditions: [{ field: 'event.category', operator: 'equals', value: 'authentication' }],
        },
      }),
      'seen-so1-user.name',
      'so1'
    );
    const searchBody = es.search.mock.calls[0][0].body;
    expect(searchBody.query.bool.filter[1]).toEqual({
      query_string: { query: 'event.category:"authentication"', analyze_wildcard: true },
    });
  });

  it('an empty history window writes an empty values array (everything IS new — correct)', async () => {
    const es = mockEsClient();
    es.search.mockResolvedValue({ body: { aggregations: undefined } });
    const result = await bootstrapSeenValues(es, rule(), 'seen-so1-user.name', 'so1');
    expect(result).toEqual({ values: [], truncated: false });
    expect(es.index).toHaveBeenCalledWith(
      expect.objectContaining({ body: expect.objectContaining({ values: [] }) })
    );
  });

  it('flags truncation when the terms agg left values uncounted (sum_other_doc_count > 0)', async () => {
    const es = mockEsClient();
    es.search.mockResolvedValue(aggResponse(['alice'], 7));
    const result = await bootstrapSeenValues(es, rule(), 'seen-so1-user.name', 'so1');
    expect(result.truncated).toBe(true);
    expect(es.index).toHaveBeenCalledWith(
      expect.objectContaining({ body: expect.objectContaining({ truncated: true }) })
    );
  });

  it('creates the state index first when it is missing', async () => {
    const es = mockEsClient();
    es.indices.exists.mockResolvedValue({ body: false });
    await bootstrapSeenValues(es, rule(), 'seen-so1-user.name', 'so1');
    expect(es.indices.create).toHaveBeenCalled();
  });

  it('rejects an invalid rule BY NAME before touching the cluster', async () => {
    const es = mockEsClient();
    await expect(
      bootstrapSeenValues(es, rule({ termField: '' }), 'seen-so1-', 'so1')
    ).rejects.toThrow(/must specify the term field/);
    expect(es.search).not.toHaveBeenCalled();
    expect(es.index).not.toHaveBeenCalled();
  });
});

describe('deleteSeenValuesDoc', () => {
  it('deletes the doc, and treats 404 (already gone) as success', async () => {
    const es = mockEsClient();
    await deleteSeenValuesDoc(es, 'seen-so1-user.name');
    expect(es.delete).toHaveBeenCalledWith({
      index: 'tlsoc-detection-state',
      id: 'seen-so1-user.name',
    });

    es.delete.mockRejectedValue({ meta: { statusCode: 404 } });
    await expect(deleteSeenValuesDoc(es, 'seen-so1-user.name')).resolves.toBeUndefined();
  });

  it('rethrows non-404 failures', async () => {
    const es = mockEsClient();
    es.delete.mockRejectedValue(Object.assign(new Error('down'), { meta: { statusCode: 500 } }));
    await expect(deleteSeenValuesDoc(es, 'x')).rejects.toThrow('down');
  });
});

describe('refreshSeenValuesForRules', () => {
  const targets: NewTermsSweepTarget[] = [
    { soId: 'so1', rule: rule() },
    {
      soId: 'so2',
      rule: rule({ name: 'New host seen', termField: 'host.name', groupBy: ['host.name'] }),
    },
  ];

  it('refreshes every target (no refresh=wait_for on the background path)', async () => {
    const es = mockEsClient();
    es.search
      .mockResolvedValueOnce(aggResponse(['alice']))
      .mockResolvedValueOnce(aggResponse(['web-01']));
    const logger = mockLogger();

    await refreshSeenValuesForRules(es, targets, logger);

    expect(es.index).toHaveBeenCalledTimes(2);
    expect(es.index.mock.calls[0][0]).toEqual(
      expect.objectContaining({
        id: 'seen-so1-user.name',
        body: expect.objectContaining({ rule_id: 'so1', values: ['alice'] }),
      })
    );
    expect(es.index.mock.calls[0][0].refresh).toBeUndefined();
    expect(es.index.mock.calls[1][0]).toEqual(
      expect.objectContaining({
        id: 'seen-so2-host.name',
        body: expect.objectContaining({ rule_id: 'so2', values: ['web-01'] }),
      })
    );
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('prefers a persisted rule.stateDocId over the re-derived id', async () => {
    const es = mockEsClient();
    const logger = mockLogger();
    await refreshSeenValuesForRules(
      es,
      [{ soId: 'so9', rule: rule({ stateDocId: 'seen-legacy-id' }) }],
      logger
    );
    expect(es.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'seen-legacy-id' }));
  });

  it('PER-RULE ISOLATION: one rule failing is logged and the rest still refresh', async () => {
    const es = mockEsClient();
    es.search
      .mockRejectedValueOnce(new Error('field caps blew up'))
      .mockResolvedValueOnce(aggResponse(['web-01']));
    const logger = mockLogger();

    await expect(refreshSeenValuesForRules(es, targets, logger)).resolves.toBeUndefined();

    expect(es.index).toHaveBeenCalledTimes(1);
    expect(es.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'seen-so2-host.name' }));
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('so1'));
  });
});

describe('refreshSeenValuesSweep', () => {
  function mockSoClient(savedObjects: any[] = []) {
    return { find: jest.fn().mockResolvedValue({ saved_objects: savedObjects }) } as any;
  }

  const newTermsSo = {
    id: 'so1',
    attributes: { mode: 'new_terms', rule: rule() },
  };
  const statefulSo = {
    id: 'so2',
    attributes: { mode: 'stateful', rule: { name: 'threshold rule' } },
  };

  it('sweeps only new_terms rules', async () => {
    const es = mockEsClient();
    es.search.mockResolvedValue(aggResponse(['alice']));
    const so = mockSoClient([newTermsSo, statefulSo]);

    await refreshSeenValuesSweep(es, so, mockLogger());

    expect(so.find).toHaveBeenCalledWith({ type: 'tlsoc-detection-rule', perPage: 1000 });
    expect(es.index).toHaveBeenCalledTimes(1);
    expect(es.index).toHaveBeenCalledWith(expect.objectContaining({ id: 'seen-so1-user.name' }));
  });

  it('DEBOUNCE: a second call within 60s does not even scan the SOs', async () => {
    const es = mockEsClient();
    const so = mockSoClient([newTermsSo]);

    await refreshSeenValuesSweep(es, so, mockLogger());
    await refreshSeenValuesSweep(es, so, mockLogger());

    expect(so.find).toHaveBeenCalledTimes(1);
  });

  it('NEVER throws: an SO-scan failure is logged and the sweep abandoned', async () => {
    const es = mockEsClient();
    const so = { find: jest.fn().mockRejectedValue(new Error('workspace denied')) } as any;
    const logger = mockLogger();

    await expect(refreshSeenValuesSweep(es, so, logger)).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('skipping this sweep'));
    expect(es.search).not.toHaveBeenCalled();
  });

  it('NEVER throws: a state-index failure is logged and the sweep abandoned', async () => {
    const es = mockEsClient();
    es.indices.exists.mockRejectedValue(new Error('cluster sad'));
    const logger = mockLogger();

    await expect(
      refreshSeenValuesSweep(es, mockSoClient([newTermsSo]), logger)
    ).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('state index unavailable'));
    expect(es.index).not.toHaveBeenCalled();
  });

  it('skips the state-index check entirely when no new_terms rules exist', async () => {
    const es = mockEsClient();
    await refreshSeenValuesSweep(es, mockSoClient([statefulSo]), mockLogger());
    expect(es.indices.exists).not.toHaveBeenCalled();
    expect(es.index).not.toHaveBeenCalled();
  });
});
