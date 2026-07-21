/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { HttpAuth, RequestHandler } from '../../../../core/server';
import { ALERT_OVERRIDE_SO_TYPE } from '../saved_objects';
import { deleteAlertOverrides, mergeAlertOverrides, registerAlertRoutes } from './alerts';
import { TlsocAlert, AlertState } from '../../common/alerts';

const flush = () => new Promise((r) => setImmediate(r));

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
  method: 'get' | 'post',
  path: string
): RequestHandler<any, any, any> {
  const call = (router[method] as jest.Mock).mock.calls.find((c: any[]) => c[0].path === path);
  if (!call) throw new Error(`No ${method.toUpperCase()} handler for ${path}`);
  return call[1];
}

const alert = (id: string, state: AlertState): TlsocAlert =>
  ({
    id,
    monitorId: 'm1',
    monitorName: 'n',
    triggerName: 't',
    state,
    severity: '2',
    severityLabel: 'high',
    findingIds: [],
    relatedDocIds: [],
    startTime: 1,
    lastNotificationTime: null,
    acknowledgedTime: null,
    endTime: null,
    errorMessage: null,
    rule: null,
    ruleKnown: false,
  } as TlsocAlert);

const overrideSo = (alertId: string) => ({
  id: alertId,
  attributes: {
    alertId,
    caseId: 'c-1',
    caseName: 'Case One',
    monitorId: 'm1',
    reopenedAt: '2026-07-21T00:00:00.000Z',
    reopenedBy: 'analyst',
  },
});

describe('mergeAlertOverrides (PROB-29 LIST hydration)', () => {
  const logger = loggerMock.create();
  beforeEach(() => jest.clearAllMocks());

  it('attaches reopenedFromCase to an ACKNOWLEDGED alert with a live override; deletes nothing', async () => {
    const del = jest.fn().mockResolvedValue({});
    const find = jest.fn().mockResolvedValue({ saved_objects: [overrideSo('a1')] });
    const soClient = { find, delete: del } as any;

    const out = await mergeAlertOverrides(soClient, [alert('a1', 'ACKNOWLEDGED')], logger);
    await flush();

    expect(find).toHaveBeenCalledWith({ type: ALERT_OVERRIDE_SO_TYPE, perPage: 1000 });
    expect(out[0].reopenedFromCase).toEqual({
      caseId: 'c-1',
      caseName: 'Case One',
      reopenedAt: '2026-07-21T00:00:00.000Z',
    });
    expect(out[0].state).toBe('ACKNOWLEDGED'); // engine state untouched
    expect(del).not.toHaveBeenCalled();
  });

  it('engine-COMPLETE wins: no badge, and the stale override is lazily deleted', async () => {
    const del = jest.fn().mockResolvedValue({});
    const find = jest.fn().mockResolvedValue({ saved_objects: [overrideSo('a1')] });
    const soClient = { find, delete: del } as any;

    const out = await mergeAlertOverrides(soClient, [alert('a1', 'COMPLETED')], logger);
    await flush();

    expect(out[0].reopenedFromCase).toBeUndefined();
    expect(out[0].state).toBe('COMPLETED');
    expect(del).toHaveBeenCalledWith(ALERT_OVERRIDE_SO_TYPE, 'a1');
  });

  it('an ACTIVE alert is never overridden and its stale override is cleaned', async () => {
    const del = jest.fn().mockResolvedValue({});
    const find = jest.fn().mockResolvedValue({ saved_objects: [overrideSo('a1')] });
    const soClient = { find, delete: del } as any;

    const out = await mergeAlertOverrides(soClient, [alert('a1', 'ACTIVE')], logger);
    await flush();

    expect(out[0].reopenedFromCase).toBeUndefined();
    expect(del).toHaveBeenCalledWith(ALERT_OVERRIDE_SO_TYPE, 'a1');
  });

  it('no overrides → alerts returned unchanged, no delete', async () => {
    const del = jest.fn();
    const find = jest.fn().mockResolvedValue({ saved_objects: [] });
    const soClient = { find, delete: del } as any;

    const input = [alert('a1', 'ACKNOWLEDGED')];
    const out = await mergeAlertOverrides(soClient, input, logger);

    expect(out).toBe(input);
    expect(del).not.toHaveBeenCalled();
  });

  it('an override for an alert not in the returned page is left untouched (not stale)', async () => {
    const del = jest.fn();
    const find = jest.fn().mockResolvedValue({ saved_objects: [overrideSo('a99')] });
    const soClient = { find, delete: del } as any;

    const out = await mergeAlertOverrides(soClient, [alert('a1', 'ACKNOWLEDGED')], logger);
    await flush();

    expect(out[0].reopenedFromCase).toBeUndefined();
    expect(del).not.toHaveBeenCalled();
  });

  it('best-effort: a find failure returns the alerts unchanged and never throws', async () => {
    const find = jest.fn().mockRejectedValue(new Error('so down'));
    const soClient = { find, delete: jest.fn() } as any;

    const input = [alert('a1', 'ACKNOWLEDGED')];
    await expect(mergeAlertOverrides(soClient, input, logger)).resolves.toBe(input);
  });
});

describe('deleteAlertOverrides (PROB-29)', () => {
  const logger = loggerMock.create();
  beforeEach(() => jest.clearAllMocks());

  it('tolerates a 404 (already gone) without logging a warning', async () => {
    const del = jest.fn().mockRejectedValue({ output: { statusCode: 404 } });
    const soClient = { delete: del } as any;
    await expect(deleteAlertOverrides(soClient, ['a1'], logger, 'test')).resolves.toBeUndefined();
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('logs (but never throws) on a non-404 failure', async () => {
    const del = jest.fn().mockRejectedValue(new Error('boom'));
    const soClient = { delete: del } as any;
    await expect(deleteAlertOverrides(soClient, ['a1'], logger, 'test')).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalled();
  });

  it('deletes each id', async () => {
    const del = jest.fn().mockResolvedValue({});
    const soClient = { delete: del } as any;
    await deleteAlertOverrides(soClient, ['a1', 'a2'], logger, 'test');
    expect(del).toHaveBeenCalledWith(ALERT_OVERRIDE_SO_TYPE, 'a1');
    expect(del).toHaveBeenCalledWith(ALERT_OVERRIDE_SO_TYPE, 'a2');
  });
});

describe('POST /api/tlsoc/alerts/_acknowledge — clears reopen overrides (PROB-29)', () => {
  const logger = loggerMock.create();
  let router: ReturnType<typeof httpServiceMock.createRouter>;

  beforeEach(() => {
    router = httpServiceMock.createRouter();
    jest.clearAllMocks();
  });

  const setup = (roles: string[]) => {
    registerAlertRoutes(router, logger, authWithRoles(roles));
    const handler = findHandler(router, 'post', '/api/tlsoc/alerts/_acknowledge');
    const del = jest.fn().mockResolvedValue({});
    const transportRequest = jest.fn().mockResolvedValue({ body: { success: ['a1'], failed: [] } });
    const ctx = coreMock.createRequestHandlerContext();
    Object.assign(ctx.savedObjects.client, { delete: del });
    Object.assign(ctx.opensearch.client.asCurrentUser, {
      transport: { request: transportRequest },
    });
    const response = httpServerMock.createResponseFactory();
    return { handler, del, transportRequest, context: { core: ctx } as any, response };
  };

  it('after a successful acknowledge, deletes the override for each acknowledged alert id', async () => {
    const { handler, del, context, response } = setup(['tlsoc_l1']);
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      body: { monitorId: 'm1', alertIds: ['a1', 'a2'] },
    });

    await handler(context, request, response);
    await flush();

    expect(response.ok).toHaveBeenCalled();
    expect(del).toHaveBeenCalledWith(ALERT_OVERRIDE_SO_TYPE, 'a1');
    expect(del).toHaveBeenCalledWith(ALERT_OVERRIDE_SO_TYPE, 'a2');
  });

  it('a non-acknowledger role is forbidden and no override cleanup runs', async () => {
    const { handler, del, transportRequest, context, response } = setup(['tlsoc_engineer']);
    const request = httpServerMock.createOpenSearchDashboardsRequest({
      body: { monitorId: 'm1', alertIds: ['a1'] },
    });

    await handler(context, request, response);

    expect(response.forbidden).toHaveBeenCalled();
    expect(transportRequest).not.toHaveBeenCalled();
    expect(del).not.toHaveBeenCalled();
  });
});
