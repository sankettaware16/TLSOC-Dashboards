/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { HttpAuth, RequestHandler } from '../../../../core/server';
import { registerCaseRoutes } from './cases';

/* eslint-disable @typescript-eslint/no-explicit-any */

const ALERTS_LIST_PATH = '/_plugins/_alerting/monitors/alerts';

/** Fake auth: always resolves to an authenticated caller with the given backend roles. */
const authWithRoles = (backendRoles: string[]): HttpAuth =>
  ({
    get: jest.fn().mockReturnValue({
      status: 'authenticated',
      state: { authInfo: { backend_roles: backendRoles } },
    }),
    isAuthenticated: jest.fn(),
  } as unknown) as HttpAuth;

function findHandler(
  router: ReturnType<typeof httpServiceMock.createRouter>,
  method: 'get' | 'post' | 'put' | 'delete',
  path: string
): RequestHandler<any, any, any> {
  const call = (router[method] as jest.Mock).mock.calls.find((c: any[]) => c[0].path === path);
  if (!call) throw new Error(`No ${method.toUpperCase()} handler registered for ${path}`);
  return call[1];
}

function makeContext(overrides: { soClient?: any; esClient?: any } = {}) {
  const ctx = coreMock.createRequestHandlerContext();
  if (overrides.soClient) Object.assign(ctx.savedObjects.client, overrides.soClient);
  if (overrides.esClient) Object.assign(ctx.opensearch.client.asCurrentUser, overrides.esClient);
  return { core: ctx } as any;
}

/** An In Progress → Contained → Closed-able case SO with three linked alerts on two monitors. */
const containedCase = (linkedAlertIds: string[]) => ({
  id: 'case1',
  attributes: {
    title: 'Brute force from 10.8.0.10',
    description: 'd',
    status: 'Contained',
    severity: 'high',
    assignee: null,
    tags: [],
    linkedAlertIds,
    linkedFindingIds: [],
    comments: [],
    activity: [],
    createdAt: '2026-07-18T00:00:00.000Z',
    updatedAt: '2026-07-18T00:00:00.000Z',
  },
});

/** Raw Alerting list alerts: a1/a2 on monitor m1 (ACTIVE), a3 on m2 (ACTIVE), a4 already ACKNOWLEDGED. */
const rawAlert = (id: string, monitorId: string, state = 'ACTIVE') => ({
  id,
  monitor_id: monitorId,
  state,
});

describe('registerCaseRoutes — PUT /api/tlsoc/cases/{id} close-time acknowledge (PROB-24)', () => {
  let router: ReturnType<typeof httpServiceMock.createRouter>;
  const logger = loggerMock.create();
  const statusAuth = authWithRoles(['tlsoc_l1']);

  beforeEach(() => {
    router = httpServiceMock.createRouter();
    jest.clearAllMocks();
  });

  const setup = (opts: {
    linked?: string[];
    listAlerts?: any[];
    ackImpl?: (path: string) => Promise<any>;
  }) => {
    registerCaseRoutes(router, logger, statusAuth);
    const handler = findHandler(router, 'put', '/api/tlsoc/cases/{id}');
    const linked = opts.linked ?? ['a1', 'a2', 'a3', 'a4'];
    const soGet = jest.fn().mockResolvedValue(containedCase(linked));
    const soUpdate = jest.fn().mockResolvedValue({ id: 'case1' });
    const transportRequest = jest.fn().mockImplementation(({ method, path }: any) => {
      if (method === 'GET' && path === ALERTS_LIST_PATH) {
        // One short page — fetchAlertsByIds stops after it.
        return Promise.resolve({
          body: {
            alerts: opts.listAlerts ?? [
              rawAlert('a1', 'm1'),
              rawAlert('a2', 'm1'),
              rawAlert('a3', 'm2'),
              rawAlert('a4', 'm1', 'ACKNOWLEDGED'),
            ],
          },
        });
      }
      if (method === 'POST' && path.endsWith('/_acknowledge/alerts')) {
        return opts.ackImpl ? opts.ackImpl(path) : Promise.resolve({ body: { success: [] } });
      }
      return Promise.resolve({ body: {} });
    });
    const context = makeContext({
      soClient: { get: soGet, update: soUpdate },
      esClient: { transport: { request: transportRequest } },
    });
    const response = httpServerMock.createResponseFactory();
    return { handler, soGet, soUpdate, transportRequest, context, response };
  };

  it('closing acknowledges the ACTIVE linked alerts grouped per monitor and records the audit entry', async () => {
    const { handler, soUpdate, transportRequest, context, response } = setup({});
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'Closed' },
    });

    await handler(context, request, response);

    const ackCalls = transportRequest.mock.calls.filter((c: any[]) =>
      String(c[0].path).endsWith('/_acknowledge/alerts')
    );
    // a1+a2 batch to m1, a3 to m2; the already-ACKNOWLEDGED a4 is skipped entirely.
    expect(ackCalls.map((c: any[]) => [c[0].path, c[0].body])).toEqual([
      ['/_plugins/_alerting/monitors/m1/_acknowledge/alerts', { alerts: ['a1', 'a2'] }],
      ['/_plugins/_alerting/monitors/m2/_acknowledge/alerts', { alerts: ['a3'] }],
    ]);

    expect(soUpdate).toHaveBeenCalledTimes(1);
    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('Closed');
    expect(patch.closedAt).toBeTruthy();
    const summaries = patch.activity.map((a: any) => [a.type, a.summary]);
    expect(summaries).toEqual([
      ['status_changed', 'Status changed from Contained to Closed'],
      ['alerts_acknowledged', 'Acknowledged 3 linked alerts on close'],
    ]);
    expect(response.ok).toHaveBeenCalledWith({ body: { id: 'case1' } });
  });

  it('acknowledgeAlerts:false opts out — the case closes with zero Alerting calls', async () => {
    const { handler, soUpdate, transportRequest, context, response } = setup({});
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'Closed', acknowledgeAlerts: false },
    });

    await handler(context, request, response);

    expect(transportRequest).not.toHaveBeenCalled();
    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('Closed');
    expect(patch.activity.map((a: any) => a.type)).toEqual(['status_changed']);
    expect(response.ok).toHaveBeenCalled();
  });

  it('a per-monitor acknowledge failure never blocks the close and is recorded honestly', async () => {
    const { handler, soUpdate, context, response } = setup({
      ackImpl: (path) =>
        path.includes('/m2/')
          ? Promise.reject(new Error('alerting deadlock'))
          : Promise.resolve({ body: { success: [] } }),
    });
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'Closed' },
    });

    await handler(context, request, response);

    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('Closed'); // the close still lands
    expect(patch.activity.map((a: any) => a.summary)).toEqual([
      'Status changed from Contained to Closed',
      'Acknowledged 2 linked alerts on close (1 could not be acknowledged)',
    ]);
    expect(response.ok).toHaveBeenCalledWith({ body: { id: 'case1' } });
  });

  it('even a failed alert LISTING never blocks the close (ack simply skipped)', async () => {
    const { handler, soUpdate, context, response } = setup({});
    (context.core.opensearch.client.asCurrentUser.transport.request as jest.Mock).mockRejectedValue(
      new Error('alerting API down')
    );
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'Closed' },
    });

    await handler(context, request, response);

    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('Closed');
    expect(patch.activity.map((a: any) => a.type)).toEqual(['status_changed']);
    expect(response.ok).toHaveBeenCalled();
  });

  it('a NON-close transition triggers no acknowledge, even with acknowledgeAlerts set', async () => {
    const { handler, transportRequest, context, response } = setup({});
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'In Progress', acknowledgeAlerts: true },
    });

    await handler(context, request, response);

    expect(transportRequest).not.toHaveBeenCalled();
    expect(response.ok).toHaveBeenCalled();
  });

  it('closing a case with no linked alerts makes no Alerting calls', async () => {
    const { handler, transportRequest, context, response } = setup({ linked: [] });
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'Closed' },
    });

    await handler(context, request, response);

    expect(transportRequest).not.toHaveBeenCalled();
    expect(response.ok).toHaveBeenCalled();
  });

  // PROB-29: re-closing an already-reopened case must also drop the reopen display-overrides so the
  // alerts stop reading as reactivated (the acknowledge covers the engine; this covers TLSOC) — but
  // ONLY the overrides THIS case owns: a4's override belongs to another still-reopened case and must
  // survive the re-close (shared-alert guard).
  it('closing deletes only this case’s reopen overrides, leaving another case’s intact', async () => {
    registerCaseRoutes(router, logger, statusAuth);
    const handler = findHandler(router, 'put', '/api/tlsoc/cases/{id}');
    const soGet = jest.fn().mockImplementation((type: string, id: string) => {
      if (type === 'tlsoc-alert-override') {
        // a1/a2/a3 were reopened by case1 (this case); a4 by a different still-open case.
        return Promise.resolve({
          id,
          type,
          attributes: { alertId: id, caseId: id === 'a4' ? 'other-case' : 'case1' },
        });
      }
      return Promise.resolve(containedCase(['a1', 'a2', 'a3', 'a4']));
    });
    const soUpdate = jest.fn().mockResolvedValue({ id: 'case1' });
    const soDelete = jest.fn().mockResolvedValue({});
    const transportRequest = jest.fn().mockResolvedValue({ body: { alerts: [] } });
    const context = makeContext({
      soClient: { get: soGet, update: soUpdate, delete: soDelete },
      esClient: { transport: { request: transportRequest } },
    });
    const response = httpServerMock.createResponseFactory();
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'Closed', acknowledgeAlerts: false },
    });

    await handler(context, request, response);

    // Only case1's own overrides (a1/a2/a3) are deleted; a4 (owned by other-case) is left in place.
    const deletedIds = soDelete.mock.calls
      .filter((c: any[]) => c[0] === 'tlsoc-alert-override')
      .map((c: any[]) => c[1])
      .sort();
    expect(deletedIds).toEqual(['a1', 'a2', 'a3']);
    expect(deletedIds).not.toContain('a4');
    expect(response.ok).toHaveBeenCalled();
  });
});

describe('registerCaseRoutes — PUT reopen (Closed → In Progress) creates display overrides (PROB-29)', () => {
  let router: ReturnType<typeof httpServiceMock.createRouter>;
  const logger = loggerMock.create();
  const statusAuth = authWithRoles(['tlsoc_l1']);

  const closedCase = (linkedAlertIds: string[]) => ({
    id: 'case1',
    attributes: {
      title: 'Brute force from 10.8.0.10',
      description: 'd',
      status: 'Closed',
      severity: 'high',
      assignee: null,
      tags: [],
      linkedAlertIds,
      linkedFindingIds: [],
      comments: [],
      activity: [],
      createdAt: '2026-07-18T00:00:00.000Z',
      updatedAt: '2026-07-18T00:00:00.000Z',
      closedAt: '2026-07-19T00:00:00.000Z',
    },
  });

  beforeEach(() => {
    router = httpServiceMock.createRouter();
    jest.clearAllMocks();
  });

  const setup = (opts: { linked?: string[]; listAlerts?: any[]; createImpl?: () => Promise<any> }) => {
    registerCaseRoutes(router, logger, statusAuth);
    const handler = findHandler(router, 'put', '/api/tlsoc/cases/{id}');
    const linked = opts.linked ?? ['a1', 'a2', 'a3'];
    const soGet = jest.fn().mockResolvedValue(closedCase(linked));
    const soUpdate = jest.fn().mockResolvedValue({ id: 'case1' });
    const soCreate = opts.createImpl
      ? jest.fn().mockImplementation(opts.createImpl)
      : jest.fn().mockResolvedValue({ id: 'ok' });
    const soDelete = jest.fn().mockResolvedValue({});
    const transportRequest = jest.fn().mockImplementation(({ method, path }: any) => {
      if (method === 'GET' && path === ALERTS_LIST_PATH) {
        return Promise.resolve({
          body: {
            alerts: opts.listAlerts ?? [
              rawAlert('a1', 'm1', 'ACKNOWLEDGED'),
              rawAlert('a2', 'm1', 'ACKNOWLEDGED'),
              rawAlert('a3', 'm2', 'ACTIVE'),
            ],
          },
        });
      }
      return Promise.resolve({ body: {} });
    });
    const context = makeContext({
      soClient: { get: soGet, update: soUpdate, create: soCreate, delete: soDelete },
      esClient: { transport: { request: transportRequest } },
    });
    const response = httpServerMock.createResponseFactory();
    return { handler, soGet, soUpdate, soCreate, soDelete, transportRequest, context, response };
  };

  it('upserts an override ONLY for the ACKNOWLEDGED linked alerts and records the audit entry', async () => {
    const { handler, soCreate, soUpdate, context, response } = setup({});
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'In Progress' },
    });

    await handler(context, request, response);

    // a1 + a2 are ACKNOWLEDGED → overrides; a3 is ACTIVE → NOT overridden.
    expect(soCreate).toHaveBeenCalledTimes(2);
    const createdIds = soCreate.mock.calls.map((c: any[]) => c[2].id);
    expect(createdIds).toEqual(['a1', 'a2']);
    for (const call of soCreate.mock.calls) {
      expect(call[0]).toBe('tlsoc-alert-override');
      expect(call[2].overwrite).toBe(true);
      expect(call[1]).toMatchObject({ caseId: 'case1', caseName: 'Brute force from 10.8.0.10' });
    }
    expect(soCreate.mock.calls[0][1].alertId).toBe('a1');

    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('In Progress');
    expect(patch.closedAt).toBeNull(); // reopen clears closedAt
    const summaries = patch.activity.map((a: any) => [a.type, a.summary]);
    expect(summaries).toEqual([
      ['status_changed', 'Status changed from Closed to In Progress'],
      ['alerts_reopened', 'Reactivated 2 linked alerts on reopen'],
    ]);
    expect(response.ok).toHaveBeenCalledWith({ body: { id: 'case1' } });
  });

  it('never overrides ACTIVE or COMPLETED alerts (no override, no audit entry when none acknowledged)', async () => {
    const { handler, soCreate, soUpdate, context, response } = setup({
      listAlerts: [rawAlert('a1', 'm1', 'ACTIVE'), rawAlert('a2', 'm1', 'COMPLETED')],
      linked: ['a1', 'a2'],
    });
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'In Progress' },
    });

    await handler(context, request, response);

    expect(soCreate).not.toHaveBeenCalled();
    const patch = soUpdate.mock.calls[0][2];
    expect(patch.activity.map((a: any) => a.type)).toEqual(['status_changed']);
    expect(response.ok).toHaveBeenCalled();
  });

  it('a failed override write never blocks the reopen and is recorded honestly', async () => {
    const { handler, soUpdate, context, response } = setup({
      createImpl: () => Promise.reject(new Error('so write conflict')),
    });
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'In Progress' },
    });

    await handler(context, request, response);

    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('In Progress'); // reopen still lands
    expect(patch.activity.map((a: any) => a.summary)).toEqual([
      'Status changed from Closed to In Progress',
      'Reactivated 0 linked alerts on reopen (2 could not be reactivated)',
    ]);
    expect(response.ok).toHaveBeenCalled();
  });

  it('a failed alert LISTING never blocks the reopen (override step skipped)', async () => {
    const { handler, soCreate, soUpdate, context, response } = setup({});
    (context.core.opensearch.client.asCurrentUser.transport.request as jest.Mock).mockRejectedValue(
      new Error('alerting API down')
    );
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'In Progress' },
    });

    await handler(context, request, response);

    expect(soCreate).not.toHaveBeenCalled();
    const patch = soUpdate.mock.calls[0][2];
    expect(patch.status).toBe('In Progress');
    expect(patch.activity.map((a: any) => a.type)).toEqual(['status_changed']);
    expect(response.ok).toHaveBeenCalled();
  });

  it('reopening a case with no linked alerts creates no overrides', async () => {
    const { handler, soCreate, transportRequest, context, response } = setup({ linked: [] });
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      params: { id: 'case1' },
      body: { status: 'In Progress' },
    });

    await handler(context, request, response);

    expect(soCreate).not.toHaveBeenCalled();
    expect(transportRequest).not.toHaveBeenCalled();
    expect(response.ok).toHaveBeenCalled();
  });
});
