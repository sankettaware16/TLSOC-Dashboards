/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { RequestHandler } from '../../../../core/server';
import { registerDataViewsRoutes } from './data_views';

function findHandler(
  router: ReturnType<typeof httpServiceMock.createRouter>
): RequestHandler<any, any, any> {
  return (router.post as jest.Mock).mock.calls.find(
    (c: any[]) => c[0].path === '/api/tlsoc/data_views/_ensure'
  )![1];
}

const today = () => new Date().toISOString().slice(0, 10).replace(/-/g, '.');
const daysAgo = (n: number) =>
  new Date(Date.now() - n * 86400_000).toISOString().slice(0, 10).replace(/-/g, '.');

describe('data_views _ensure — idempotent + skips stale endpoints', () => {
  const logger = loggerMock.create();

  const setup = (opts: { existingTitles?: string[]; indices?: string[] }) => {
    const router = httpServiceMock.createRouter();
    const created: string[] = [];
    const indexPatterns = {
      getIdsWithTitle: jest
        .fn()
        .mockResolvedValue(
          (opts.existingTitles ?? []).map((t, i) => ({ id: `id-${i}`, title: t }))
        ),
      createAndSave: jest.fn().mockImplementation((spec: any) => {
        created.push(spec.title);
        return Promise.resolve({ id: `new-${spec.title}` });
      }),
    };
    // getIndexPatternsServiceFactory: () => Promise<(request) => Promise<indexPatterns>>
    const factory = async () => (async () => indexPatterns) as any;
    registerDataViewsRoutes(
      router,
      logger,
      factory as any,
      { logIndexPattern: 'fosstlsoc-logs-*' } as any,
      false
    );
    const handler = findHandler(router);
    const ctx = coreMock.createRequestHandlerContext();
    (ctx.opensearch.client.asCurrentUser.cat.indices as jest.Mock) = jest
      .fn()
      .mockResolvedValue({ body: (opts.indices ?? []).map((index) => ({ index })) });
    const context = { core: ctx } as any;
    const response = httpServerMock.createResponseFactory();
    return { handler, context, response, created, indexPatterns };
  };

  const run = async (h: RequestHandler<any, any, any>, context: any, response: any) =>
    h(
      context,
      httpServerMock.createOpenSearchDashboardsRequest({ body: { perEndpoint: true } }),
      response
    );

  it('creates the base view when nothing exists', async () => {
    const { handler, context, response, created } = setup({ existingTitles: [], indices: [] });
    await run(handler, context, response);
    expect(created).toEqual(['fosstlsoc-logs-*']);
  });

  it('does NOT recreate titles that already exist (no duplicates)', async () => {
    const { handler, context, response, created } = setup({
      existingTitles: ['fosstlsoc-logs-*', `fosstlsoc-logs-waf-*`],
      indices: [`fosstlsoc-logs-waf-${today()}`],
    });
    await run(handler, context, response);
    expect(created).toEqual([]); // both already present
  });

  it('creates a per-endpoint view for a FRESH endpoint, skips a STALE one', async () => {
    const { handler, context, response, created } = setup({
      existingTitles: ['fosstlsoc-logs-*'],
      indices: [
        `fosstlsoc-logs-waf-${today()}`, // fresh → create
        `fosstlsoc-logs-mailnile-${daysAgo(60)}`, // stale → skip
      ],
    });
    await run(handler, context, response);
    expect(created).toContain('fosstlsoc-logs-waf-*');
    expect(created).not.toContain('fosstlsoc-logs-mailnile-*');
  });
});
