/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { RequestHandler } from '../../../../core/server';
import {
  prepareIndicatorMatchRule,
  registerValueListRoutes,
  syncIndicatorListMonitors,
} from './value_lists';
import {
  isValidIpOrCidr,
  parseValueLines,
  validateValueListValues,
  valueListIdFromName,
  assertValidValueListInput,
} from '../../common/value_lists';

/* eslint-disable @typescript-eslint/no-explicit-any */

const LISTS_API = '/api/tlsoc/value_lists';

function getHandler(
  router: ReturnType<typeof httpServiceMock.createRouter>,
  method: 'get' | 'post' | 'put' | 'delete',
  path: string
): RequestHandler<any, any, any> {
  const call = (router[method] as jest.Mock).mock.calls.find((c: any[]) => c[0].path === path);
  if (!call) throw new Error(`No ${method.toUpperCase()} handler registered for ${path}`);
  return call[1];
}

/** A context with pre-stubbed transport + fieldCaps + SO find (detection_validate idiom). */
function makeContext(transportRequest: jest.Mock, soFind?: jest.Mock) {
  const ctx = coreMock.createRequestHandlerContext();
  Object.assign(ctx.opensearch.client.asCurrentUser, {
    transport: { request: transportRequest },
  });
  if (soFind) {
    (ctx.savedObjects.client.find as jest.Mock).mockImplementation(soFind);
  } else {
    (ctx.savedObjects.client.find as jest.Mock).mockResolvedValue({ saved_objects: [] });
  }
  return { core: ctx } as any;
}

const req = (opts: { body?: any; params?: any }) =>
  httpServerMock.createOpenSearchDashboardsRequest(opts);

/** An authenticated non-writer (an L1 analyst) — write routes must 403. */
const analystAuth = {
  get: jest.fn().mockReturnValue({
    status: 'authenticated',
    state: { authInfo: { backend_roles: ['tlsoc_l1'] } },
  }),
} as any;

const indicatorRuleSo = (over: Partial<any> = {}) => ({
  id: 'so-1',
  attributes: {
    name: 'IOC hits',
    mode: 'indicator_match',
    severity: 'high',
    monitorId: 'm1',
    rule: {
      name: 'IOC hits',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      eventField: 'source.ip',
      listId: 'bad_ips',
      listMode: 'inline',
      groupBy: ['source.ip'],
    },
    createdAt: '2026-07-20T00:00:00.000Z',
    ...over,
  },
});

describe('value-list validators (pure)', () => {
  it('isValidIpOrCidr — accept set (v4/v6, plain + CIDR)', () => {
    for (const v of [
      '10.0.0.1',
      '0.0.0.0',
      '255.255.255.255',
      '10.0.0.0/8',
      '192.168.1.0/24',
      '10.0.0.1/32',
      '::',
      '::1',
      '2001:db8::1',
      '1:2:3:4:5:6:7:8',
      'fe80::/10',
      '::ffff:10.0.0.1',
      '::/0',
      '2001:db8::/128',
    ]) {
      expect({ v, ok: isValidIpOrCidr(v) }).toEqual({ v, ok: true });
    }
  });

  it('isValidIpOrCidr — reject set', () => {
    for (const v of [
      '',
      '10.0.0',
      '10.0.0.256',
      '10.00.0.1',
      '1.2.3.4.5',
      '10.0.0.1/33',
      '10.0.0.1/',
      '10.0.0.1/8/8',
      'abc',
      'evil.example.com',
      '2001:db8:::1',
      'g::1',
      '1:2:3:4:5:6:7:8:9',
      '2001:db8::1/129',
      '10.0.0.1 ',
    ]) {
      expect({ v, ok: isValidIpOrCidr(v) }).toEqual({ v, ok: false });
    }
  });

  it('validateValueListValues names bad ip lines positionally and flags duplicates', () => {
    const errors = validateValueListValues('ip', ['10.0.0.1', 'nonsense', '10.0.0.1', '']);
    expect(errors).toEqual([
      { index: 1, value: 'nonsense', reason: 'not a valid IP address or CIDR block' },
      { index: 2, value: '10.0.0.1', reason: 'duplicate value' },
      { index: 3, value: '', reason: 'empty values are not allowed' },
    ]);
    expect(validateValueListValues('keyword', ['evil.exe', 'evil2.exe'])).toEqual([]);
  });

  it('parseValueLines trims, drops empties, dedupes (first wins)', () => {
    expect(parseValueLines('  a \n\nb\r\na\nc  ')).toEqual(['a', 'b', 'c']);
  });

  it('valueListIdFromName slugs like the detection compilers; degenerate names reject', () => {
    expect(valueListIdFromName('Known Bad IPs!')).toBe('known_bad_ips');
    expect(valueListIdFromName('—— ——')).toBe('');
    expect(() => assertValidValueListInput({ name: '——', type: 'keyword', values: ['x'] })).toThrow(
      /at least one letter or digit/
    );
  });

  it('rejects a list over the 65536 hard ceiling by name', () => {
    const values = Array.from({ length: 65537 }, (_, i) => `v${i}`);
    expect(() => assertValidValueListInput({ name: 'Big', type: 'keyword', values })).toThrow(
      /65537 values.*65536/s
    );
  });
});

describe('value-list routes', () => {
  let router: ReturnType<typeof httpServiceMock.createRouter>;
  const logger = loggerMock.create();

  beforeEach(() => {
    router = httpServiceMock.createRouter();
    jest.clearAllMocks();
  });

  describe('POST (create)', () => {
    it('happy path: ensures the index, then a conflict-checked _create write', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockResolvedValue({ body: {} });
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'post', LISTS_API)(
        makeContext(transport),
        req({ body: { name: 'Known Bad IPs', type: 'ip', values: ['10.0.0.66', '192.168.0.0/16'] } }),
        response
      );

      expect(transport).toHaveBeenCalledTimes(2);
      expect(transport.mock.calls[0][0]).toEqual(
        expect.objectContaining({ method: 'PUT', path: '/tlsoc-value-lists' })
      );
      const write = transport.mock.calls[1][0];
      expect(write.method).toBe('PUT');
      expect(write.path).toBe('/tlsoc-value-lists/_create/known_bad_ips');
      expect(write.querystring).toEqual({ refresh: 'wait_for' });
      expect(write.body).toEqual({
        name: 'Known Bad IPs',
        type: 'ip',
        values: ['10.0.0.66', '192.168.0.0/16'],
        updated_at: expect.any(String),
      });
      expect(response.ok).toHaveBeenCalledWith({
        body: expect.objectContaining({ id: 'known_bad_ips', type: 'ip', count: 2 }),
      });
    });

    it('invalid ip values 400 BY LINE before any cluster call', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn();
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'post', LISTS_API)(
        makeContext(transport),
        req({ body: { name: 'Bad', type: 'ip', values: ['10.0.0.1', 'not-an-ip'] } }),
        response
      );

      expect(transport).not.toHaveBeenCalled();
      expect(response.badRequest).toHaveBeenCalledWith({
        body: {
          message: expect.stringContaining(
            'line 2 ("not-an-ip"): not a valid IP address or CIDR block'
          ),
        },
      });
    });

    it('an unknown type 400s BY NAME', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn();
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'post', LISTS_API)(
        makeContext(transport),
        req({ body: { name: 'Hashes', type: 'hash', values: ['x'] } }),
        response
      );

      expect(transport).not.toHaveBeenCalled();
      expect(response.badRequest).toHaveBeenCalledWith({
        body: { message: 'Unknown value list type "hash". Supported: keyword, ip.' },
      });
    });

    it('an existing id 409s with the name', async () => {
      registerValueListRoutes(router, logger);
      const conflict: any = new Error('version conflict');
      conflict.meta = { statusCode: 409 };
      const transport = jest.fn().mockImplementation(({ path }: any) =>
        path === '/tlsoc-value-lists' ? Promise.resolve({ body: {} }) : Promise.reject(conflict)
      );
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'post', LISTS_API)(
        makeContext(transport),
        req({ body: { name: 'Known Bad IPs', type: 'ip', values: ['10.0.0.1'] } }),
        response
      );

      expect(response.customError).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 409,
          body: { message: expect.stringContaining('already exists') },
        })
      );
    });

    it('writes are DETECTION_WRITERS-guarded: an L1 gets a clean 403', async () => {
      registerValueListRoutes(router, logger, analystAuth);
      const transport = jest.fn();
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'post', LISTS_API)(
        makeContext(transport),
        req({ body: { name: 'X', type: 'keyword', values: ['x'] } }),
        response
      );

      expect(transport).not.toHaveBeenCalled();
      expect(response.forbidden).toHaveBeenCalled();
    });
  });

  describe('GET (list + one)', () => {
    it('lists summaries with counts and linked-rule counts', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockResolvedValue({
        body: {
          hits: {
            hits: [
              {
                _id: 'bad_ips',
                _source: {
                  name: 'Bad IPs',
                  type: 'ip',
                  values: ['10.0.0.1', '10.0.0.2'],
                  updated_at: '2026-07-20T10:00:00.000Z',
                },
              },
            ],
          },
        },
      });
      const soFind = jest.fn().mockResolvedValue({
        saved_objects: [
          indicatorRuleSo(),
          indicatorRuleSo({ name: 'Other type', mode: 'stateless' }),
        ],
      });
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'get', LISTS_API)(
        makeContext(transport, soFind),
        req({}),
        response
      );

      expect(response.ok).toHaveBeenCalledWith({
        body: {
          lists: [
            {
              id: 'bad_ips',
              name: 'Bad IPs',
              type: 'ip',
              count: 2,
              updatedAt: '2026-07-20T10:00:00.000Z',
              linkedRules: 1,
            },
          ],
        },
      });
    });

    it('no index yet (404) is an empty manager page, not an error', async () => {
      registerValueListRoutes(router, logger);
      const missing: any = new Error('index_not_found_exception');
      missing.meta = { statusCode: 404 };
      const transport = jest.fn().mockRejectedValue(missing);
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'get', LISTS_API)(makeContext(transport), req({}), response);

      expect(response.ok).toHaveBeenCalledWith({ body: { lists: [] } });
    });

    it('GET one returns full values; a missing list 404s by id', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockResolvedValue({
        body: {
          found: true,
          _source: {
            name: 'Bad IPs',
            type: 'ip',
            values: ['10.0.0.1'],
            updated_at: '2026-07-20T10:00:00.000Z',
          },
        },
      });
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'get', `${LISTS_API}/{id}`)(
        makeContext(transport),
        req({ params: { id: 'bad_ips' } }),
        response
      );
      expect(transport).toHaveBeenCalledWith(
        expect.objectContaining({ method: 'GET', path: '/tlsoc-value-lists/_doc/bad_ips' })
      );
      expect(response.ok).toHaveBeenCalledWith({
        body: {
          id: 'bad_ips',
          name: 'Bad IPs',
          type: 'ip',
          values: ['10.0.0.1'],
          updatedAt: '2026-07-20T10:00:00.000Z',
        },
      });

      const gone: any = new Error('not found');
      gone.meta = { statusCode: 404 };
      const transport404 = jest.fn().mockRejectedValue(gone);
      const response404 = httpServerMock.createResponseFactory();
      await getHandler(router, 'get', `${LISTS_API}/{id}`)(
        makeContext(transport404),
        req({ params: { id: 'ghost' } }),
        response404
      );
      expect(response404.notFound).toHaveBeenCalledWith({
        body: { message: 'Value list "ghost" not found.' },
      });
    });
  });

  describe('PUT (update)', () => {
    const existingDoc = {
      body: {
        found: true,
        _source: {
          name: 'Bad IPs',
          type: 'ip',
          values: ['10.0.0.1'],
          updated_at: '2026-07-20T09:00:00.000Z',
        },
      },
    };

    it('happy path: values replaced in place, type/name identity preserved', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockImplementation(({ method }: any) =>
        method === 'GET' ? Promise.resolve(existingDoc) : Promise.resolve({ body: {} })
      );
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'put', `${LISTS_API}/{id}`)(
        makeContext(transport),
        req({ params: { id: 'bad_ips' }, body: { values: ['10.0.0.1', '10.0.0.9'] } }),
        response
      );

      const write = transport.mock.calls.find((c: any[]) => c[0].method === 'PUT')![0];
      expect(write.path).toBe('/tlsoc-value-lists/_doc/bad_ips');
      expect(write.body).toEqual({
        name: 'Bad IPs',
        type: 'ip',
        values: ['10.0.0.1', '10.0.0.9'],
        updated_at: expect.any(String),
      });
      expect(response.ok).toHaveBeenCalledWith({
        body: expect.objectContaining({ id: 'bad_ips', count: 2 }),
      });
    });

    it('the type is immutable — a change 400s by name', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockResolvedValue(existingDoc);
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'put', `${LISTS_API}/{id}`)(
        makeContext(transport),
        req({ params: { id: 'bad_ips' }, body: { type: 'keyword', values: ['x'] } }),
        response
      );

      expect(response.badRequest).toHaveBeenCalledWith({
        body: { message: expect.stringContaining('type cannot change ("ip" → "keyword")') },
      });
    });

    it('a rename that would change the id (rules reference it) 400s by name', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockResolvedValue(existingDoc);
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'put', `${LISTS_API}/{id}`)(
        makeContext(transport),
        req({ params: { id: 'bad_ips' }, body: { name: 'Worse IPs', values: ['10.0.0.1'] } }),
        response
      );

      expect(response.badRequest).toHaveBeenCalledWith({
        body: { message: expect.stringContaining('would change the list id ("bad_ips")') },
      });
    });

    it('growing past the inline cap warns, naming the inline rules left on old values', async () => {
      registerValueListRoutes(router, logger);
      const bigValues = Array.from({ length: 901 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}/32`);
      const transport = jest.fn().mockImplementation(({ method, path }: any) => {
        if (method === 'GET' && path === '/tlsoc-value-lists/_doc/bad_ips') {
          return Promise.resolve(existingDoc);
        }
        return Promise.resolve({ body: {} });
      });
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [indicatorRuleSo()] });
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'put', `${LISTS_API}/{id}`)(
        makeContext(transport, soFind),
        req({ params: { id: 'bad_ips' }, body: { values: bigValues } }),
        response
      );

      const body = (response.ok as jest.Mock).mock.calls[0][0].body;
      expect(body.count).toBe(901);
      expect(body.warning).toContain('"IOC hits"');
      expect(body.warning).toContain('lookup mode');
    });
  });

  describe('DELETE', () => {
    it('refuses (409) while any indicator-match rule references the list — by rule name', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn();
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [indicatorRuleSo()] });
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'delete', `${LISTS_API}/{id}`)(
        makeContext(transport, soFind),
        req({ params: { id: 'bad_ips' } }),
        response
      );

      expect(transport).not.toHaveBeenCalled();
      expect(response.customError).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 409,
          body: {
            message: expect.stringContaining('used by 1 detection rule(s): "IOC hits"'),
          },
        })
      );
    });

    it('deletes an unreferenced list', async () => {
      registerValueListRoutes(router, logger);
      const transport = jest.fn().mockResolvedValue({ body: {} });
      const response = httpServerMock.createResponseFactory();

      await getHandler(router, 'delete', `${LISTS_API}/{id}`)(
        makeContext(transport),
        req({ params: { id: 'old_list' } }),
        response
      );

      expect(transport).toHaveBeenCalledWith(
        expect.objectContaining({ method: 'DELETE', path: '/tlsoc-value-lists/_doc/old_list' })
      );
      expect(response.ok).toHaveBeenCalledWith({ body: { deleted: true } });
    });
  });
});

describe('prepareIndicatorMatchRule — the save gate', () => {
  const esWith = (impl: {
    listDoc?: any;
    fieldCaps?: any;
    fieldCapsError?: any;
  }) => ({
    transport: {
      request: jest.fn().mockImplementation(({ path }: any) => {
        if (path.startsWith('/tlsoc-value-lists/_doc/')) {
          if (impl.listDoc === null) {
            const err: any = new Error('not found');
            err.meta = { statusCode: 404 };
            return Promise.reject(err);
          }
          return Promise.resolve({ body: { found: true, _source: impl.listDoc } });
        }
        return Promise.resolve({ body: {} });
      }),
    },
    fieldCaps: jest.fn().mockImplementation(() => {
      if (impl.fieldCapsError) return Promise.reject(impl.fieldCapsError);
      return Promise.resolve({ body: impl.fieldCaps });
    }),
  });

  beforeEach(() => jest.clearAllMocks());

  const rule = () => ({ ...indicatorRuleSo().attributes.rule } as Record<string, unknown>);

  it('a missing list 400s by name', async () => {
    const es = esWith({ listDoc: null });
    await expect(prepareIndicatorMatchRule(es, rule())).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('Value list "bad_ips" was not found'),
    });
  });

  it('picks + STAMPS inline for a small list and returns its values (keyword list: no field_caps)', async () => {
    const es = esWith({ listDoc: { name: 'l', type: 'keyword', values: ['a', 'b'] } });
    const r = rule();
    (r as any).listMode = 'lookup'; // a stale client value — the server re-picks
    const out = await prepareIndicatorMatchRule(es, r);
    expect(out).toEqual({ listMode: 'inline', values: ['a', 'b'] });
    expect((r as any).listMode).toBe('inline');
    expect(es.fieldCaps).not.toHaveBeenCalled();
  });

  it('picks lookup past the 900 cap; refuses an empty list', async () => {
    const big = Array.from({ length: 901 }, (_, i) => `v${i}`);
    const es = esWith({ listDoc: { name: 'l', type: 'keyword', values: big } });
    const r = rule();
    await expect(prepareIndicatorMatchRule(es, r)).resolves.toMatchObject({ listMode: 'lookup' });
    expect((r as any).listMode).toBe('lookup');

    const empty = esWith({ listDoc: { name: 'l', type: 'keyword', values: [] } });
    await expect(prepareIndicatorMatchRule(empty, rule())).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('has no values'),
    });
  });

  it('ip lists REQUIRE an ip-mapped event field (field_caps gate, by mapping name)', async () => {
    const es = esWith({
      listDoc: { name: 'l', type: 'ip', values: ['10.0.0.0/8'] },
      fieldCaps: {
        indices: ['fosstlsoc-logs-2026.07.20'],
        fields: { 'source.ip': { keyword: { type: 'keyword' } } },
      },
    });
    await expect(prepareIndicatorMatchRule(es, rule())).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('mapped as "keyword"'),
    });
  });

  it('ip list: an absent field and zero matching indices are both refused', async () => {
    const absent = esWith({
      listDoc: { name: 'l', type: 'ip', values: ['10.0.0.0/8'] },
      fieldCaps: { indices: ['idx-1'], fields: {} },
    });
    await expect(prepareIndicatorMatchRule(absent, rule())).rejects.toMatchObject({
      message: expect.stringContaining('does not exist'),
    });

    const noIdx = esWith({
      listDoc: { name: 'l', type: 'ip', values: ['10.0.0.0/8'] },
      fieldCaps: { indices: [], fields: {} },
    });
    await expect(prepareIndicatorMatchRule(noIdx, rule())).rejects.toMatchObject({
      message: expect.stringContaining('No indices currently match'),
    });
  });

  it('ip list happy path: ip-mapped field passes', async () => {
    const es = esWith({
      listDoc: { name: 'l', type: 'ip', values: ['10.0.0.0/8'] },
      fieldCaps: {
        indices: ['fosstlsoc-logs-2026.07.20'],
        fields: { 'source.ip': { ip: { type: 'ip' } } },
      },
    });
    await expect(prepareIndicatorMatchRule(es, rule())).resolves.toEqual({
      listMode: 'inline',
      values: ['10.0.0.0/8'],
    });
  });
});

describe('syncIndicatorListMonitors — the inline drift-repair sweep', () => {
  const logger = loggerMock.create();

  beforeEach(() => jest.clearAllMocks());

  function soClientWith(rules: any[]) {
    return ({ find: jest.fn().mockResolvedValue({ saved_objects: rules }) } as unknown) as any;
  }

  it('rewrites a drifted inline monitor query in place (concurrency-checked PUT)', async () => {
    const transport = jest.fn().mockImplementation(({ method, path }: any) => {
      if (path === '/tlsoc-value-lists/_doc/bad_ips') {
        return Promise.resolve({
          body: { found: true, _source: { name: 'l', type: 'ip', values: ['1.2.3.4'] } },
        });
      }
      if (method === 'GET' && path === '/_plugins/_alerting/monitors/m1') {
        return Promise.resolve({
          body: {
            monitor: {
              inputs: [{ doc_level_input: { queries: [{ query: 'source.ip:("9.9.9.9")' }] } }],
            },
            _seq_no: 7,
            _primary_term: 2,
          },
        });
      }
      return Promise.resolve({ body: {} });
    });

    await syncIndicatorListMonitors(
      { transport: { request: transport } },
      soClientWith([indicatorRuleSo()]),
      logger,
      { force: true }
    );

    const put = transport.mock.calls.find(
      (c: any[]) => c[0].method === 'PUT' && c[0].path === '/_plugins/_alerting/monitors/m1'
    )![0];
    expect(put.body.inputs[0].doc_level_input.queries[0].query).toBe('source.ip:("1.2.3.4")');
    expect(put.querystring).toEqual({ refresh: 'wait_for', if_seq_no: 7, if_primary_term: 2 });
  });

  it('an in-sync monitor is left untouched', async () => {
    const transport = jest.fn().mockImplementation(({ method, path }: any) => {
      if (path === '/tlsoc-value-lists/_doc/bad_ips') {
        return Promise.resolve({
          body: { found: true, _source: { name: 'l', type: 'ip', values: ['1.2.3.4'] } },
        });
      }
      if (method === 'GET' && path === '/_plugins/_alerting/monitors/m1') {
        return Promise.resolve({
          body: {
            monitor: {
              inputs: [{ doc_level_input: { queries: [{ query: 'source.ip:("1.2.3.4")' }] } }],
            },
          },
        });
      }
      return Promise.resolve({ body: {} });
    });

    await syncIndicatorListMonitors(
      { transport: { request: transport } },
      soClientWith([indicatorRuleSo()]),
      logger,
      { force: true }
    );

    expect(
      transport.mock.calls.some((c: any[]) => c[0].method === 'PUT')
    ).toBe(false);
  });

  it('an over-cap list is SKIPPED with a warning — never truncated, never flipped', async () => {
    const big = Array.from({ length: 901 }, (_, i) => `v${i}`);
    const transport = jest.fn().mockImplementation(({ path }: any) => {
      if (path === '/tlsoc-value-lists/_doc/bad_ips') {
        return Promise.resolve({
          body: { found: true, _source: { name: 'l', type: 'keyword', values: big } },
        });
      }
      return Promise.resolve({ body: {} });
    });

    await syncIndicatorListMonitors(
      { transport: { request: transport } },
      soClientWith([indicatorRuleSo()]),
      logger,
      { force: true }
    );

    // Only the list fetch — the monitor is never read or written.
    expect(transport).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('over the inline cap'));
  });

  it('lookup-mode rules are out of scope (the engine reads the list live)', async () => {
    const transport = jest.fn();
    const lookupRule = indicatorRuleSo();
    (lookupRule.attributes.rule as any).listMode = 'lookup';

    await syncIndicatorListMonitors(
      { transport: { request: transport } },
      soClientWith([lookupRule]),
      logger,
      { force: true }
    );

    expect(transport).not.toHaveBeenCalled();
  });
});
