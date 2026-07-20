/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { HttpAuth, RequestHandler } from '../../../../core/server';
import { registerMonitorRoutes } from './monitors';

/* eslint-disable @typescript-eslint/no-explicit-any */

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
});
