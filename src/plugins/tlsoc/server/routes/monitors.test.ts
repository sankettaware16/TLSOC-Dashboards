/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { HttpAuth, RequestHandler } from '../../../../core/server';
import { needsExecutionTargetSync, registerMonitorRoutes } from './monitors';
import { bootstrapSeenValues, deleteSeenValuesDoc } from '../lib/new_terms_state';

/* eslint-disable @typescript-eslint/no-explicit-any */

// v1.2.3 D5: the seen-state module is mocked so these route tests pin the LIFECYCLE (bootstrap
// before monitor POST, rollback, cleanup) without re-testing the module's own cluster calls
// (new_terms_state.test.ts owns those). jest.clearAllMocks clears calls, not implementations.
jest.mock('../lib/new_terms_state', () => ({
  bootstrapSeenValues: jest.fn().mockResolvedValue({ values: [], truncated: false }),
  deleteSeenValuesDoc: jest.fn().mockResolvedValue(undefined),
}));

const TYPE = 'tlsoc-detection-rule';

/** Fake auth: always resolves to an authenticated caller with the given backend roles. */
const authWithRoles = (backendRoles: string[]): HttpAuth =>
  ({
    get: jest.fn().mockReturnValue({
      status: 'authenticated',
      state: { authInfo: { backend_roles: backendRoles } },
    }),
    isAuthenticated: jest.fn(),
  } as unknown) as HttpAuth;

/** A stateful (bucket-level) rule body — avoids prepareMonitor's alias/cat.indices path entirely. */
const statefulRule = {
  name: 'Brute force',
  severity: 'high',
  index: 'security-logs',
  filter: {
    logic: 'AND',
    conditions: [{ field: 'event.outcome', operator: 'equals', value: 'failure' }],
  },
  groupBy: ['user.name'],
  window: { value: 5, unit: 'MINUTES' },
  threshold: { operator: 'gt', value: 5 },
};

function findHandler(
  router: ReturnType<typeof httpServiceMock.createRouter>,
  method: 'get' | 'post' | 'put' | 'delete',
  path: string
): RequestHandler<any, any, any> {
  const call = (router[method] as jest.Mock).mock.calls.find((c: any[]) => c[0].path === path);
  if (!call) throw new Error(`No ${method.toUpperCase()} handler registered for ${path}`);
  return call[1];
}

/** A context whose savedObjects.client and opensearch asCurrentUser methods are pre-stubbed. */
function makeContext(overrides: { soClient?: any; esClient?: any } = {}) {
  const ctx = coreMock.createRequestHandlerContext();
  if (overrides.soClient) Object.assign(ctx.savedObjects.client, overrides.soClient);
  if (overrides.esClient) Object.assign(ctx.opensearch.client.asCurrentUser, overrides.esClient);
  return { core: ctx } as any;
}

describe('registerMonitorRoutes', () => {
  let router: ReturnType<typeof httpServiceMock.createRouter>;
  const logger = loggerMock.create();
  const writerAuth = authWithRoles(['tlsoc_engineer']);

  beforeEach(() => {
    router = httpServiceMock.createRouter();
    jest.clearAllMocks();
  });

  describe('_toggle', () => {
    it('disables a monitor: PUTs enabled:false with concurrency params and rewrites the SO', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors/{soId}/_toggle');

      const soGet = jest.fn().mockResolvedValue({
        id: 'so1',
        attributes: { monitorId: 'm1', name: 'Rule', mode: 'stateful', enabled: true },
      });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ method }: any) => {
        if (method === 'GET') {
          return Promise.resolve({
            body: { monitor: { name: 'Rule', enabled: true }, _seq_no: 3, _primary_term: 1 },
          });
        }
        return Promise.resolve({ body: { _id: 'm1' } });
      });

      const context = makeContext({
        soClient: { get: soGet, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { enabled: false },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(soGet).toHaveBeenCalledWith(TYPE, 'so1');

      const putCall = transportRequest.mock.calls.find((c: any[]) => c[0].method === 'PUT');
      expect(putCall).toBeTruthy();
      expect(putCall![0].body.enabled).toBe(false);
      expect(putCall![0].querystring.if_seq_no).toBe(3);
      expect(putCall![0].querystring.if_primary_term).toBe(1);

      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({ monitorId: 'm1', enabled: false }),
        { id: 'so1', overwrite: true }
      );
      expect(response.ok).toHaveBeenCalledWith({ body: { enabled: false } });
    });

    it('denies a caller without a DETECTION_WRITERS role', async () => {
      registerMonitorRoutes(router, logger, authWithRoles(['tlsoc_l1']));
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors/{soId}/_toggle');

      const context = makeContext();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { enabled: false },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(response.forbidden).toHaveBeenCalled();
      expect(response.ok).not.toHaveBeenCalled();
    });
  });

  describe('UPDATE preserves enabled state (the trap)', () => {
    it('an edit that omits `enabled` keeps a previously-disabled rule disabled', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'put', '/api/tlsoc/detection/monitors/{soId}');

      const soGet = jest.fn().mockResolvedValue({
        id: 'so1',
        attributes: {
          monitorId: 'm1',
          name: 'Brute force',
          mode: 'stateful',
          enabled: false,
          createdAt: '2026-01-01T00:00:00.000Z',
        },
      });
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] }); // no name conflicts
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ method }: any) => {
        if (method === 'GET') {
          return Promise.resolve({
            body: { monitor: { name: 'Brute force', enabled: true }, _seq_no: 5, _primary_term: 2 },
          });
        }
        return Promise.resolve({ body: {} });
      });

      const context = makeContext({
        soClient: { get: soGet, find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { mode: 'stateful', rule: statefulRule }, // no `enabled` in the body
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      const putCall = transportRequest.mock.calls.find((c: any[]) => c[0].method === 'PUT');
      expect(putCall![0].body.enabled).toBe(false);

      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({ enabled: false }),
        { id: 'so1', overwrite: true }
      );
      expect(response.ok).toHaveBeenCalled();
    });
  });

  describe('CREATE default', () => {
    it('a create with no `enabled` field defaults the monitor and SO to enabled:true', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');

      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockResolvedValue({ body: { _id: 'm1' } });

      const context = makeContext({
        soClient: { find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'stateful', rule: statefulRule },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      const postCall = transportRequest.mock.calls.find((c: any[]) => c[0].method === 'POST');
      expect(postCall![0].body.enabled).toBe(true);

      expect(soCreate).toHaveBeenCalledWith(TYPE, expect.objectContaining({ enabled: true }));
      expect(response.ok).toHaveBeenCalled();
    });
  });

  describe('LIST reconciliation', () => {
    it('live monitor.enabled overrides a stale SO value', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'get', '/api/tlsoc/detection/monitors');

      const soFind = jest.fn().mockResolvedValue({
        saved_objects: [
          { id: 'so1', attributes: { name: 'A', mode: 'stateful', severity: 'high', monitorId: 'm1', enabled: true, createdAt: '2026-01-01T00:00:00.000Z' } },
          { id: 'so2', attributes: { name: 'B', mode: 'stateful', severity: 'low', monitorId: 'm2', enabled: true, createdAt: '2026-01-02T00:00:00.000Z' } },
        ],
      });
      const transportRequest = jest.fn().mockResolvedValue({
        body: {
          hits: {
            hits: [{ _id: 'm1', _source: { monitor: { enabled: false } } }],
          },
        },
      });

      const context = makeContext({
        soClient: { find: soFind },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest();
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      const body = (response.ok as jest.Mock).mock.calls[0][0].body;
      const bySoId = Object.fromEntries(body.rules.map((r: any) => [r.soId, r.enabled]));
      expect(bySoId.so1).toBe(false); // live wins over the stale SO `true`
      expect(bySoId.so2).toBe(true); // no live hit for m2 → SO value stands
    });

    it('falls back to SO values (and still 200s) when the live search throws', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'get', '/api/tlsoc/detection/monitors');

      const soFind = jest.fn().mockResolvedValue({
        saved_objects: [
          { id: 'so1', attributes: { name: 'A', mode: 'stateful', severity: 'high', monitorId: 'm1', enabled: false, createdAt: '2026-01-01T00:00:00.000Z' } },
        ],
      });
      const transportRequest = jest.fn().mockRejectedValue(new Error('cluster unavailable'));

      const context = makeContext({
        soClient: { find: soFind },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest();
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(response.ok).toHaveBeenCalled();
      const body = (response.ok as jest.Mock).mock.calls[0][0].body;
      expect(body.rules[0].enabled).toBe(false);
      expect(logger.warn).toHaveBeenCalled();
    });
  });

  describe('unknown rule-type ids (registry reject-by-name — D1)', () => {
    it('CREATE 400s an unregistered mode, naming the id, before touching any client', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');

      const soFind = jest.fn();
      const transportRequest = jest.fn();
      const context = makeContext({
        soClient: { find: soFind },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'sequence', rule: statefulRule },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(response.badRequest).toHaveBeenCalledWith({
        body: { message: expect.stringContaining('"sequence"') },
      });
      expect(response.ok).not.toHaveBeenCalled();
      expect(soFind).not.toHaveBeenCalled();
      expect(transportRequest).not.toHaveBeenCalled();
    });

    it('UPDATE 400s an unregistered mode, naming the id', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'put', '/api/tlsoc/detection/monitors/{soId}');

      const context = makeContext();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { mode: 'sequence', rule: statefulRule },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(response.badRequest).toHaveBeenCalledWith({
        body: { message: expect.stringContaining('"sequence"') },
      });
      expect(response.ok).not.toHaveBeenCalled();
    });
  });

  describe('PPL fieldMap gate (W2 review BLOCKING-1 — the server is the unskippable layer)', () => {
    /** dc(url.path) + by source.ip + = on http.method — every string-context position covered. */
    const pplRule = {
      name: 'Scanner',
      severity: 'high',
      index: 'security-logs',
      pplText:
        'source = security-logs | where http.method = "POST" | ' +
        'stats dc(url.path) as paths by source.ip | where paths >= 40',
      groupBy: ['source.ip'],
      window: { value: 5, unit: 'MINUTES' },
    };

    /** Cluster truth: url.path is analyzed text WITH a keyword subfield; the rest need no map. */
    const capsBody = {
      indices: ['security-logs'],
      fields: {
        'source.ip': { ip: { type: 'ip', searchable: true, aggregatable: true } },
        'http.method': { keyword: { type: 'keyword', searchable: true, aggregatable: true } },
        'url.path': { text: { type: 'text', searchable: true, aggregatable: false } },
        'url.path.keyword': {
          keyword: { type: 'keyword', searchable: true, aggregatable: true },
        },
      },
    };

    function createSetup(fieldCapsBody: any) {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockResolvedValue({ body: { _id: 'm1' } });
      const fieldCaps = jest.fn().mockResolvedValue({ body: fieldCapsBody });
      const context = makeContext({
        soClient: { find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest }, fieldCaps },
      });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest, fieldCaps };
    }

    it('a text-context field MISSING from the fieldMap 400s BY NAME, before any monitor exists', async () => {
      const { handler, context, response, transportRequest } = createSetup(capsBody);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'ppl', rule: pplRule }, // no fieldMap at all — the Path A client bypass
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('"url.path"') },
      });
      expect(response.ok).not.toHaveBeenCalled();
      expect(transportRequest).not.toHaveBeenCalled(); // the monitor was never created
    });

    it('a correct fieldMap passes: the monitor is created and field_caps asked about map targets too', async () => {
      const { handler, context, response, transportRequest, fieldCaps } = createSetup(capsBody);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'ppl',
          rule: { ...pplRule, fieldMap: { 'url.path': 'url.path.keyword' } },
        },
      });

      await handler(context, request, response);

      expect(fieldCaps).toHaveBeenCalledWith(
        expect.objectContaining({
          index: 'security-logs',
          fields: expect.arrayContaining(['url.path', 'url.path.keyword', 'source.ip']),
        })
      );
      const postCall = transportRequest.mock.calls.find((c: any[]) => c[0].method === 'POST');
      expect(postCall).toBeTruthy();
      expect(response.ok).toHaveBeenCalled();
      expect(response.customError).not.toHaveBeenCalled();
    });

    it('keyword/ip fields need no fieldMap entry at all', async () => {
      const { handler, context, response } = createSetup(capsBody);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'ppl',
          rule: {
            ...pplRule,
            pplText:
              'source = security-logs | where http.method = "POST" | ' +
              'stats count() as hits by source.ip | where hits > 5',
            // no fieldMap — http.method (keyword) and source.ip (ip) resolve as themselves
          },
        },
      });

      await handler(context, request, response);

      expect(response.ok).toHaveBeenCalled();
      expect(response.customError).not.toHaveBeenCalled();
    });

    it('a fieldMap claiming a NONEXISTENT mapping 400s naming both field and claim', async () => {
      const { handler, context, response } = createSetup(capsBody);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'ppl',
          rule: { ...pplRule, fieldMap: { 'url.path': 'url.path.raw' } },
        },
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('"url.path.raw"') },
      });
      expect(response.ok).not.toHaveBeenCalled();
    });

    it('zero matching concrete indices 400s with the "No indices currently match" message', async () => {
      const { handler, context, response, transportRequest } = createSetup({
        indices: [],
        fields: {},
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'ppl',
          rule: { ...pplRule, fieldMap: { 'url.path': 'url.path.keyword' } },
        },
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('No indices currently match') },
      });
      expect(transportRequest).not.toHaveBeenCalled();
    });
  });

  describe('custom_query pre-save validation (W2 review BLOCKING-2)', () => {
    const cqRule = {
      name: 'Admin probe',
      severity: 'high',
      index: 'security-logs',
      language: 'lucene',
      queryText: 'url.path:*admin*',
    };

    /** Transport mock that answers _validate/query with `validateBody` and everything else as create. */
    function createSetup(validateBody: any) {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ path }: any) =>
        String(path).includes('/_validate/query')
          ? Promise.resolve({ body: validateBody })
          : Promise.resolve({ body: { _id: 'm1' } })
      );
      const context = makeContext({
        soClient: { find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest };
    }

    const monitorCreateCalls = (transportRequest: jest.Mock) =>
      transportRequest.mock.calls.filter(
        (c: any[]) => c[0].method === 'POST' && c[0].path === '/_plugins/_alerting/monitors'
      );

    it('invalid Lucene 400s with the cluster parse error surfaced; no monitor is created', async () => {
      const parseError =
        "ParseException[Cannot parse 'url.path:(': Encountered \"<EOF>\" at line 1, column 10.]";
      const { handler, context, response, transportRequest } = createSetup({
        valid: false,
        _shards: { total: 1, successful: 1, failed: 0 },
        explanations: [{ index: 'security-logs', valid: false, error: parseError }],
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'custom_query', rule: { ...cqRule, queryText: 'url.path:(' } },
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining(parseError) },
      });
      expect(response.ok).not.toHaveBeenCalled();
      expect(monitorCreateCalls(transportRequest)).toHaveLength(0);
    });

    it('a valid query passes: the exact executed Lucene is validated, then the monitor created', async () => {
      const { handler, context, response, transportRequest } = createSetup({
        valid: true,
        _shards: { total: 2, successful: 2, failed: 0 },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'custom_query', rule: cqRule },
      });

      await handler(context, request, response);

      const validateCall = transportRequest.mock.calls.find((c: any[]) =>
        String(c[0].path).includes('/_validate/query')
      );
      expect(validateCall).toBeTruthy();
      expect(validateCall![0].body).toEqual({
        query: { query_string: { query: 'url.path:*admin*', analyze_wildcard: true } },
      });
      expect(monitorCreateCalls(transportRequest)).toHaveLength(1);
      expect(response.ok).toHaveBeenCalled();
    });

    it('THE 0-SHARDS TRAP: "valid" against zero shards 400s (nothing was actually validated)', async () => {
      const { handler, context, response, transportRequest } = createSetup({
        valid: true,
        _shards: { total: 0, successful: 0, failed: 0 },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'custom_query', rule: cqRule },
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('no indices currently match') },
      });
      expect(monitorCreateCalls(transportRequest)).toHaveLength(0);
    });
  });

  describe('new_terms CREATE — the two-phase seen-state lifecycle (v1.2.3 D5)', () => {
    const newTermsRule = () => ({
      name: 'First-seen country',
      severity: 'high',
      index: 'security-logs',
      termField: 'geo.country',
      historyWindow: { value: 30, unit: 'DAYS' },
      groupBy: ['geo.country'],
    });

    function createSetup(
      overrides: { soCreate?: jest.Mock; concreteIndices?: string[] } = {}
    ) {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = overrides.soCreate ?? jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockResolvedValue({ body: { _id: 'm1' } });
      // The D5 index gate (W3 review) resolves the rule's index via cat.indices before any
      // bootstrap — a matching concrete index is the default; [] exercises the refusal.
      const catIndices = jest.fn().mockResolvedValue({
        body: (overrides.concreteIndices ?? ['security-logs']).map((index) => ({ index })),
      });
      const context = makeContext({
        soClient: { find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      Object.assign(context.core.opensearch.client.asCurrentUser.cat, { indices: catIndices });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest, soCreate, catIndices };
    }

    it('bootstraps the seen values BEFORE the monitor POST, with the pre-generated SO id threaded through', async () => {
      const { handler, context, response, transportRequest, soCreate } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'new_terms', rule: newTermsRule() },
      });

      await handler(context, request, response);

      // The bootstrap ran exactly once, with a docId derived from the pre-generated SO id.
      expect(bootstrapSeenValues).toHaveBeenCalledTimes(1);
      const [, bootRule, bootDocId, bootSoId] = (bootstrapSeenValues as jest.Mock).mock.calls[0];
      expect(bootRule).toEqual(expect.objectContaining({ termField: 'geo.country' }));
      expect(bootDocId).toBe(`seen-${bootSoId}-geo.country`);

      // ORDER: bootstrap strictly before the monitor POST (the lookup target must exist first).
      const postIdx = transportRequest.mock.calls.findIndex((c: any[]) => c[0].method === 'POST');
      expect(postIdx).toBeGreaterThanOrEqual(0);
      expect((bootstrapSeenValues as jest.Mock).mock.invocationCallOrder[0]).toBeLessThan(
        transportRequest.mock.invocationCallOrder[postIdx]
      );

      // The SO is created UNDER the pre-generated id, with the same stateDocId persisted.
      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({
          mode: 'new_terms',
          rule: expect.objectContaining({ stateDocId: bootDocId }),
        }),
        { id: bootSoId }
      );
      expect(response.ok).toHaveBeenCalled();
    });

    it('a failed bootstrap 400s LOUDLY (the save gate) and no monitor is ever created', async () => {
      (bootstrapSeenValues as jest.Mock).mockRejectedValueOnce(
        new Error('field [geo.country] is not aggregatable')
      );
      const { handler, context, response, transportRequest } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'new_terms', rule: newTermsRule() },
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('Could not snapshot the seen values') },
      });
      expect(response.ok).not.toHaveBeenCalled();
      expect(transportRequest).not.toHaveBeenCalled();
    });

    it('an SO failure rolls back the monitor AND the seen-state doc', async () => {
      const soCreate = jest.fn().mockRejectedValue(new Error('SO store down'));
      const { handler, context, response, transportRequest } = createSetup({ soCreate });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'new_terms', rule: newTermsRule() },
      });

      await handler(context, request, response);

      const deleteCall = transportRequest.mock.calls.find((c: any[]) => c[0].method === 'DELETE');
      expect(deleteCall![0].path).toBe('/_plugins/_alerting/monitors/m1');
      const bootDocId = (bootstrapSeenValues as jest.Mock).mock.calls[0][2];
      expect(deleteSeenValuesDoc).toHaveBeenCalledWith(expect.anything(), bootDocId);
      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 500,
        body: { message: expect.stringContaining('rolled back') },
      });
    });

    it('a failed monitor POST rolls back the seen-state doc too (W3 review fix 2)', async () => {
      const { handler, context, response, transportRequest } = createSetup();
      transportRequest.mockRejectedValueOnce(new Error('alerting unavailable'));
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'new_terms', rule: newTermsRule() },
      });

      await handler(context, request, response);

      const bootDocId = (bootstrapSeenValues as jest.Mock).mock.calls[0][2];
      expect(deleteSeenValuesDoc).toHaveBeenCalledWith(expect.anything(), bootDocId);
      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 500,
        body: expect.objectContaining({
          message: expect.stringContaining('Could not save detection'),
        }),
      });
      expect(response.ok).not.toHaveBeenCalled();
    });

    it('ZERO matching indices 400 by name BEFORE any bootstrap (the D5 index gate)', async () => {
      const { handler, context, response, transportRequest, catIndices } = createSetup({
        concreteIndices: [],
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'new_terms', rule: newTermsRule() },
      });

      await handler(context, request, response);

      expect(catIndices).toHaveBeenCalled();
      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('No indices currently match "security-logs"') },
      });
      expect(bootstrapSeenValues).not.toHaveBeenCalled();
      expect(transportRequest).not.toHaveBeenCalled(); // no monitor was ever created
    });

    it('surfaces the bootstrap snapshot ADDITIVELY as seenValues {count, truncated}', async () => {
      (bootstrapSeenValues as jest.Mock).mockResolvedValueOnce({
        values: ['IN', 'DE'],
        truncated: true,
      });
      const { handler, context, response } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'new_terms', rule: newTermsRule() },
      });

      await handler(context, request, response);

      const body = (response.ok as jest.Mock).mock.calls[0][0].body;
      expect(body.seenValues).toEqual({ count: 2, truncated: true });
    });

    it('non-new_terms creates carry NO seenValues field (the additive contract)', async () => {
      const { handler, context, response } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'stateful', rule: statefulRule },
      });

      await handler(context, request, response);

      const body = (response.ok as jest.Mock).mock.calls[0][0].body;
      expect('seenValues' in body).toBe(false);
    });
  });

  describe('indicator_match save gate — the size-based mode pick (v1.2.3 D6)', () => {
    const indicatorRule = () => ({
      name: 'IOC domains',
      severity: 'high',
      index: 'security-logs',
      eventField: 'dns.question.name',
      listId: 'bad_domains',
      listMode: 'lookup', // a stale client value — the server re-picks from the list's size
      groupBy: ['dns.question.name'],
    });

    function createSetup(listValues: string[]) {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ path }: any) => {
        if (String(path).startsWith('/tlsoc-value-lists/_doc/')) {
          return Promise.resolve({
            body: {
              found: true,
              _source: { name: 'Bad domains', type: 'keyword', values: listValues },
            },
          });
        }
        return Promise.resolve({ body: { _id: 'm1' } });
      });
      const context = makeContext({
        soClient: { find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest, soCreate };
    }

    const monitorPost = (transportRequest: jest.Mock) =>
      transportRequest.mock.calls.find(
        (c: any[]) => c[0].method === 'POST' && c[0].path === '/_plugins/_alerting/monitors'
      )![0];

    it('a small list compiles INLINE (doc-level, values baked in) and stamps listMode', async () => {
      const { handler, context, response, transportRequest, soCreate } = createSetup([
        'evil.com',
        'bad.io',
      ]);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'indicator_match', rule: indicatorRule() },
      });

      await handler(context, request, response);

      const posted = monitorPost(transportRequest).body;
      expect(posted.monitor_type).toBe('doc_level_monitor');
      expect(posted.inputs[0].doc_level_input.queries[0].query).toBe(
        'dns.question.name:("evil.com" OR "bad.io")'
      );
      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({ rule: expect.objectContaining({ listMode: 'inline' }) })
      );
      expect(response.ok).toHaveBeenCalled();
    });

    it('a list past the inline cap compiles as the LOOKUP bucket monitor and stamps listMode', async () => {
      const big = Array.from({ length: 901 }, (_, i) => `host${i}.evil`);
      const { handler, context, response, transportRequest, soCreate } = createSetup(big);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'indicator_match', rule: { ...indicatorRule(), listMode: 'inline' } },
      });

      await handler(context, request, response);

      const posted = monitorPost(transportRequest).body;
      expect(posted.monitor_type).toBe('bucket_level_monitor');
      const filters = posted.inputs[0].search.query.query.bool.filter;
      expect(filters).toEqual(
        expect.arrayContaining([
          {
            terms: {
              'dns.question.name': { index: 'tlsoc-value-lists', id: 'bad_domains', path: 'values' },
            },
          },
        ])
      );
      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({ rule: expect.objectContaining({ listMode: 'lookup' }) })
      );
      expect(response.ok).toHaveBeenCalled();
    });

    it('a missing list 400s by name, before any monitor exists', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');
      const notFound: any = new Error('not found');
      notFound.meta = { statusCode: 404 };
      const transportRequest = jest.fn().mockImplementation(({ path }: any) =>
        String(path).startsWith('/tlsoc-value-lists/_doc/')
          ? Promise.reject(notFound)
          : Promise.resolve({ body: { _id: 'm1' } })
      );
      const context = makeContext({
        soClient: { find: jest.fn().mockResolvedValue({ saved_objects: [] }) },
        esClient: { transport: { request: transportRequest } },
      });
      const response = httpServerMock.createResponseFactory();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'indicator_match', rule: indicatorRule() },
      });

      await handler(context, request, response);

      expect(response.customError).toHaveBeenCalledWith({
        statusCode: 400,
        body: { message: expect.stringContaining('Value list "bad_domains" was not found') },
      });
      expect(
        transportRequest.mock.calls.some((c: any[]) => c[0].path === '/_plugins/_alerting/monitors')
      ).toBe(false);
    });
  });

  describe('alias routing re-key — keyed off the COMPILED monitor_type (v1.2.3 D6 regression)', () => {
    /** Transport that answers _validate (valid), value-list GETs, aliases, and monitor create. */
    function createSetup(listValues?: string[]) {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'post', '/api/tlsoc/detection/monitors');
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ path }: any) => {
        if (String(path).includes('/_validate/query')) {
          return Promise.resolve({
            body: { valid: true, _shards: { total: 1, successful: 1, failed: 0 } },
          });
        }
        if (String(path).startsWith('/tlsoc-value-lists/_doc/')) {
          return Promise.resolve({
            body: {
              found: true,
              _source: { name: 'Bad domains', type: 'keyword', values: listValues ?? [] },
            },
          });
        }
        if (path === '/_aliases') return Promise.resolve({ body: { acknowledged: true } });
        return Promise.resolve({ body: { _id: 'm1' } });
      });
      const catIndices = jest
        .fn()
        .mockResolvedValue({ body: [{ index: 'security-1' }] });
      const fieldCaps = jest.fn().mockResolvedValue({
        body: {
          indices: ['security-1'],
          fields: {
            'source.ip': { ip: { type: 'ip', searchable: true, aggregatable: true } },
            'http.method': { keyword: { type: 'keyword', searchable: true, aggregatable: true } },
          },
        },
      });
      const context = makeContext({
        soClient: { find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest }, fieldCaps },
      });
      // `cat` is getter-only on the client mock — assign INTO it rather than replacing it.
      Object.assign(context.core.opensearch.client.asCurrentUser.cat, { indices: catIndices });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest, soCreate, catIndices };
    }

    const monitorPost = (transportRequest: jest.Mock) =>
      transportRequest.mock.calls.find(
        (c: any[]) => c[0].method === 'POST' && c[0].path === '/_plugins/_alerting/monitors'
      )![0];
    const aliasCalls = (transportRequest: jest.Mock) =>
      transportRequest.mock.calls.filter((c: any[]) => c[0].path === '/_aliases');

    it('stateless on a patterned index STILL alias-routes (behavior identical to the monitorKind key)', async () => {
      const { handler, context, response, transportRequest } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'stateless',
          rule: {
            name: 'SL',
            severity: 'high',
            index: 'security-*',
            group: { logic: 'AND', conditions: [{ field: 'event.outcome', operator: 'exists' }] },
          },
        },
      });

      await handler(context, request, response);

      expect(aliasCalls(transportRequest)).toHaveLength(1);
      expect(monitorPost(transportRequest).body.inputs[0].doc_level_input.indices).toEqual([
        'tlsoc_alias_security_1',
      ]);
      expect(response.ok).toHaveBeenCalled();
    });

    it('custom_query on a patterned index STILL alias-routes', async () => {
      const { handler, context, response, transportRequest } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'custom_query',
          rule: {
            name: 'CQ',
            severity: 'high',
            index: 'security-*',
            language: 'lucene',
            queryText: 'url.path:*admin*',
          },
        },
      });

      await handler(context, request, response);

      expect(aliasCalls(transportRequest)).toHaveLength(1);
      expect(monitorPost(transportRequest).body.inputs[0].doc_level_input.indices).toEqual([
        'tlsoc_alias_security_1',
      ]);
      expect(response.ok).toHaveBeenCalled();
    });

    it('stateful on a patterned index does NOT alias-route (bucket monitors take patterns)', async () => {
      const { handler, context, response, transportRequest, catIndices } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: { mode: 'stateful', rule: { ...statefulRule, index: 'security-*' } },
      });

      await handler(context, request, response);

      expect(catIndices).not.toHaveBeenCalled();
      expect(aliasCalls(transportRequest)).toHaveLength(0);
      expect(monitorPost(transportRequest).body.monitor_type).toBe('bucket_level_monitor');
      expect(response.ok).toHaveBeenCalled();
    });

    it('ppl on a patterned index does NOT alias-route', async () => {
      const { handler, context, response, transportRequest, catIndices } = createSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'ppl',
          rule: {
            name: 'Scanner',
            severity: 'high',
            index: 'security-*',
            pplText:
              'source = security-* | where http.method = "POST" | ' +
              'stats count() as hits by source.ip | where hits > 5',
            groupBy: ['source.ip'],
            window: { value: 5, unit: 'MINUTES' },
          },
        },
      });

      await handler(context, request, response);

      expect(catIndices).not.toHaveBeenCalled();
      expect(aliasCalls(transportRequest)).toHaveLength(0);
      expect(monitorPost(transportRequest).body.monitor_type).toBe('bucket_level_monitor');
      expect(response.ok).toHaveBeenCalled();
    });

    it('LOOKUP indicator_match on a patterned index does NOT alias-route (compiled bucket)', async () => {
      const big = Array.from({ length: 901 }, (_, i) => `host${i}.evil`);
      const { handler, context, response, transportRequest, catIndices } = createSetup(big);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'indicator_match',
          rule: {
            name: 'IOC lookup',
            severity: 'high',
            index: 'security-*',
            eventField: 'dns.question.name',
            listId: 'bad_domains',
            listMode: 'inline',
            groupBy: ['dns.question.name'],
          },
        },
      });

      await handler(context, request, response);

      expect(catIndices).not.toHaveBeenCalled();
      expect(aliasCalls(transportRequest)).toHaveLength(0);
      expect(monitorPost(transportRequest).body.monitor_type).toBe('bucket_level_monitor');
      expect(response.ok).toHaveBeenCalled();
    });

    it('INLINE indicator_match on a patterned index DOES alias-route (the re-key exists for this)', async () => {
      const { handler, context, response, transportRequest } = createSetup(['evil.com']);
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        body: {
          mode: 'indicator_match',
          rule: {
            name: 'IOC inline',
            severity: 'high',
            index: 'security-*',
            eventField: 'dns.question.name',
            listId: 'bad_domains',
            listMode: 'lookup',
            groupBy: ['dns.question.name'],
          },
        },
      });

      await handler(context, request, response);

      expect(aliasCalls(transportRequest)).toHaveLength(1);
      const posted = monitorPost(transportRequest).body;
      expect(posted.monitor_type).toBe('doc_level_monitor');
      expect(posted.inputs[0].doc_level_input.indices).toEqual(['tlsoc_alias_security_1']);
      expect(response.ok).toHaveBeenCalled();
    });
  });

  describe('UPDATE — the rule type is IMMUTABLE after creation (v1.2.3 D-A)', () => {
    it('400s BY NAME when the body mode differs from the saved mode, before touching the cluster', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'put', '/api/tlsoc/detection/monitors/{soId}');

      const soGet = jest.fn().mockResolvedValue({
        id: 'so1',
        attributes: { monitorId: 'm1', name: 'Brute force', mode: 'stateful', enabled: true },
      });
      const soFind = jest.fn();
      const soCreate = jest.fn();
      const transportRequest = jest.fn();
      const context = makeContext({
        soClient: { get: soGet, find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: {
          mode: 'stateless',
          rule: {
            name: 'Brute force',
            severity: 'high',
            index: 'security-logs',
            group: { logic: 'AND', conditions: [{ field: 'event.outcome', operator: 'exists' }] },
          },
        },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(response.badRequest).toHaveBeenCalledWith({
        body: {
          message: expect.stringContaining(
            'the rule type cannot be changed after creation'
          ),
        },
      });
      const message = (response.badRequest as jest.Mock).mock.calls[0][0].body.message;
      expect(message).toContain('"stateful"');
      expect(message).toContain('"stateless"');
      expect(response.ok).not.toHaveBeenCalled();
      expect(soFind).not.toHaveBeenCalled(); // refused before dedup/compile
      expect(soCreate).not.toHaveBeenCalled();
      expect(transportRequest).not.toHaveBeenCalled();
    });
  });

  describe('UPDATE — indicator_match monitor-kind swap (v1.2.3 D-B)', () => {
    const MONITORS = '/_plugins/_alerting/monitors';
    const imRule = (overrides: Record<string, unknown> = {}) => ({
      name: 'IOC domains',
      severity: 'high',
      index: 'security-logs',
      eventField: 'dns.question.name',
      listId: 'bad_domains',
      listMode: 'inline',
      groupBy: ['dns.question.name'],
      ...overrides,
    });

    function updateSetup(listValues: string[], existingMonitorType: string) {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'put', '/api/tlsoc/detection/monitors/{soId}');
      const soGet = jest.fn().mockResolvedValue({
        id: 'so1',
        attributes: {
          monitorId: 'm1',
          name: 'IOC domains',
          mode: 'indicator_match',
          enabled: true,
          createdAt: '2026-01-01T00:00:00.000Z',
          rule: imRule(),
        },
      });
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ method, path }: any) => {
        if (String(path).startsWith('/tlsoc-value-lists/_doc/')) {
          return Promise.resolve({
            body: {
              found: true,
              _source: { name: 'Bad domains', type: 'keyword', values: listValues },
            },
          });
        }
        if (method === 'GET' && path === `${MONITORS}/m1`) {
          return Promise.resolve({
            body: {
              monitor: { monitor_type: existingMonitorType, name: 'IOC domains' },
              _seq_no: 3,
              _primary_term: 1,
            },
          });
        }
        if (method === 'POST' && path === MONITORS) {
          return Promise.resolve({ body: { _id: 'm2' } });
        }
        return Promise.resolve({ body: {} });
      });
      const context = makeContext({
        soClient: { get: soGet, find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest, soCreate };
    }

    it('a list crossing the inline cap SWAPS monitors: create new, SO gets the new id, old deleted AFTER the SO write', async () => {
      const big = Array.from({ length: 901 }, (_, i) => `host${i}.evil`);
      // The saved rule ran INLINE (doc-level); the grown list now compiles to the LOOKUP bucket
      // shape — a PUT across monitor_type is never attempted.
      const { handler, context, response, transportRequest, soCreate } = updateSetup(
        big,
        'doc_level_monitor'
      );
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { mode: 'indicator_match', rule: imRule() },
      });

      await handler(context, request, response);

      // No PUT ever touched the old monitor; the replacement was POSTed instead.
      expect(
        transportRequest.mock.calls.some(
          (c: any[]) => c[0].method === 'PUT' && String(c[0].path).startsWith(MONITORS)
        )
      ).toBe(false);
      const postIdx = transportRequest.mock.calls.findIndex(
        (c: any[]) => c[0].method === 'POST' && c[0].path === MONITORS
      );
      expect(postIdx).toBeGreaterThanOrEqual(0);
      expect(transportRequest.mock.calls[postIdx][0].body.monitor_type).toBe(
        'bucket_level_monitor'
      );

      // The SO records the REPLACEMENT id (the LIST/GET-ONE/alerts joins all read this field).
      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({ monitorId: 'm2' }),
        { id: 'so1', overwrite: true }
      );

      // The superseded monitor is deleted ONLY AFTER both writes succeeded (BLOCKING-1 order).
      const deleteIdx = transportRequest.mock.calls.findIndex(
        (c: any[]) => c[0].method === 'DELETE' && c[0].path === `${MONITORS}/m1`
      );
      expect(deleteIdx).toBeGreaterThanOrEqual(0);
      expect(transportRequest.mock.invocationCallOrder[deleteIdx]).toBeGreaterThan(
        transportRequest.mock.invocationCallOrder[postIdx]
      );
      expect(transportRequest.mock.invocationCallOrder[deleteIdx]).toBeGreaterThan(
        soCreate.mock.invocationCallOrder[0]
      );

      const body = (response.ok as jest.Mock).mock.calls[0][0].body;
      expect(body.id).toBe('m2');
    });

    it('a same-kind update still PUTs the existing monitor in place (no swap, no delete)', async () => {
      const { handler, context, response, transportRequest, soCreate } = updateSetup(
        ['evil.com', 'bad.io'],
        'doc_level_monitor'
      );
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { mode: 'indicator_match', rule: imRule() },
      });

      await handler(context, request, response);

      const putCall = transportRequest.mock.calls.find(
        (c: any[]) => c[0].method === 'PUT' && c[0].path === `${MONITORS}/m1`
      );
      expect(putCall).toBeTruthy();
      expect(putCall![0].querystring.if_seq_no).toBe(3);
      expect(
        transportRequest.mock.calls.some(
          (c: any[]) => c[0].method === 'POST' && c[0].path === MONITORS
        )
      ).toBe(false);
      expect(
        transportRequest.mock.calls.some((c: any[]) => c[0].method === 'DELETE')
      ).toBe(false);
      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({ monitorId: 'm1' }),
        { id: 'so1', overwrite: true }
      );
      expect((response.ok as jest.Mock).mock.calls[0][0].body.id).toBe('m1');
    });
  });

  describe('new_terms UPDATE/DELETE lifecycle (v1.2.3 W3 review)', () => {
    const MONITORS = '/_plugins/_alerting/monitors';
    const updateRule = (overrides: Record<string, unknown> = {}) => ({
      name: 'First-seen country',
      severity: 'high',
      index: 'security-logs',
      termField: 'geo.country',
      historyWindow: { value: 30, unit: 'DAYS' },
      groupBy: ['geo.country'],
      ...overrides,
    });

    function updateSetup() {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'put', '/api/tlsoc/detection/monitors/{soId}');
      const soGet = jest.fn().mockResolvedValue({
        id: 'so1',
        attributes: {
          monitorId: 'm1',
          name: 'First-seen country',
          mode: 'new_terms',
          enabled: true,
          createdAt: '2026-01-01T00:00:00.000Z',
          rule: { ...updateRule(), stateDocId: 'seen-so1-geo.country' },
        },
      });
      const soFind = jest.fn().mockResolvedValue({ saved_objects: [] });
      const soCreate = jest.fn().mockResolvedValue({ id: 'so1' });
      const transportRequest = jest.fn().mockImplementation(({ method, path }: any) => {
        if (method === 'GET' && path === `${MONITORS}/m1`) {
          return Promise.resolve({
            body: {
              monitor: { monitor_type: 'bucket_level_monitor', name: 'First-seen country' },
              _seq_no: 3,
              _primary_term: 1,
            },
          });
        }
        return Promise.resolve({ body: {} });
      });
      const catIndices = jest.fn().mockResolvedValue({ body: [{ index: 'security-logs' }] });
      const context = makeContext({
        soClient: { get: soGet, find: soFind, create: soCreate },
        esClient: { transport: { request: transportRequest } },
      });
      Object.assign(context.core.opensearch.client.asCurrentUser.cat, { indices: catIndices });
      const response = httpServerMock.createResponseFactory();
      return { handler, context, response, transportRequest, soCreate };
    }

    it('UPDATE re-injects the deterministic stateDocId even when the client dropped it', async () => {
      const { handler, context, response, soCreate } = updateSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: { mode: 'new_terms', rule: updateRule() }, // no stateDocId in the body
      });

      await handler(context, request, response);

      expect(bootstrapSeenValues).toHaveBeenCalledTimes(1);
      const [, , bootDocId, bootSoId] = (bootstrapSeenValues as jest.Mock).mock.calls[0];
      expect(bootSoId).toBe('so1');
      expect(bootDocId).toBe('seen-so1-geo.country');
      expect(soCreate).toHaveBeenCalledWith(
        TYPE,
        expect.objectContaining({
          rule: expect.objectContaining({ stateDocId: 'seen-so1-geo.country' }),
        }),
        { id: 'so1', overwrite: true }
      );
      // Same termField → same doc id → nothing to clean up.
      expect(deleteSeenValuesDoc).not.toHaveBeenCalled();
      expect(response.ok).toHaveBeenCalled();
    });

    it('a termField change deletes the OLD seen doc only AFTER the monitor PUT and SO write (BLOCKING-1)', async () => {
      const { handler, context, response, transportRequest, soCreate } = updateSetup();
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
        body: {
          mode: 'new_terms',
          rule: updateRule({ termField: 'user.name', groupBy: ['user.name'] }),
        },
      });

      await handler(context, request, response);

      // The new doc was bootstrapped under the NEW id; the OLD doc was removed.
      expect((bootstrapSeenValues as jest.Mock).mock.calls[0][2]).toBe('seen-so1-user.name');
      expect(deleteSeenValuesDoc).toHaveBeenCalledWith(expect.anything(), 'seen-so1-geo.country');

      // ORDER: the old-doc delete ran strictly AFTER the monitor write AND the SO write — the
      // live monitor keeps reading the old doc until the rewritten one is durably in place.
      const putIdx = transportRequest.mock.calls.findIndex(
        (c: any[]) => c[0].method === 'PUT' && c[0].path === `${MONITORS}/m1`
      );
      expect(putIdx).toBeGreaterThanOrEqual(0);
      const deleteOrder = (deleteSeenValuesDoc as jest.Mock).mock.invocationCallOrder[0];
      expect(deleteOrder).toBeGreaterThan(transportRequest.mock.invocationCallOrder[putIdx]);
      expect(deleteOrder).toBeGreaterThan(soCreate.mock.invocationCallOrder[0]);
      expect(response.ok).toHaveBeenCalled();
    });

    it('DELETE drops the rule seen-state doc (best-effort, after monitor + SO deletion)', async () => {
      registerMonitorRoutes(router, logger, writerAuth);
      const handler = findHandler(router, 'delete', '/api/tlsoc/detection/monitors/{soId}');
      const soGet = jest.fn().mockResolvedValue({
        id: 'so1',
        attributes: {
          monitorId: 'm1',
          name: 'First-seen country',
          mode: 'new_terms',
          rule: { ...updateRule(), stateDocId: 'seen-so1-geo.country' },
        },
      });
      const soDelete = jest.fn().mockResolvedValue(undefined);
      const transportRequest = jest.fn().mockResolvedValue({ body: {} });
      const context = makeContext({
        soClient: { get: soGet, delete: soDelete },
        esClient: { transport: { request: transportRequest } },
      });
      const request = httpServerMock.createOpenSearchDashboardsRequest({
        params: { soId: 'so1' },
      });
      const response = httpServerMock.createResponseFactory();

      await handler(context, request, response);

      expect(soDelete).toHaveBeenCalledWith(TYPE, 'so1');
      expect(deleteSeenValuesDoc).toHaveBeenCalledWith(expect.anything(), 'seen-so1-geo.country');
      expect(response.ok).toHaveBeenCalledWith({ body: { deleted: true } });
    });
  });

  describe('needsExecutionTargetSync — the drift-repair selection predicate (W3 review)', () => {
    const attrs = (mode: string, rule: Record<string, unknown> = {}) =>
      ({ mode, rule, name: 'R', severity: 'high', monitorId: 'm1', createdAt: '' } as any);

    it('selects every doc-kind type', () => {
      expect(needsExecutionTargetSync(attrs('stateless'))).toBe(true);
      expect(needsExecutionTargetSync(attrs('custom_query'))).toBe(true);
    });

    it('excludes bucket-kind types (new_terms included)', () => {
      expect(needsExecutionTargetSync(attrs('stateful'))).toBe(false);
      expect(needsExecutionTargetSync(attrs('ppl'))).toBe(false);
      expect(needsExecutionTargetSync(attrs('new_terms'))).toBe(false);
    });

    it('splits the indicator_match hybrid on listMode: inline in, lookup out', () => {
      expect(needsExecutionTargetSync(attrs('indicator_match', { listMode: 'inline' }))).toBe(
        true
      );
      expect(needsExecutionTargetSync(attrs('indicator_match', { listMode: 'lookup' }))).toBe(
        false
      );
      expect(needsExecutionTargetSync(attrs('indicator_match'))).toBe(false); // mangled rule attr
    });

    it('skips (never crashes on) an unregistered mode', () => {
      expect(needsExecutionTargetSync(attrs('sequence'))).toBe(false);
    });
  });
});
