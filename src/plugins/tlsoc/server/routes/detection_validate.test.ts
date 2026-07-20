/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock, httpServerMock, httpServiceMock } from '../../../../core/server/mocks';
import { loggerMock } from '@osd/logging/target/mocks';
import { RequestHandler } from '../../../../core/server';
import { registerDetectionValidateRoutes } from './detection_validate';

const PATH = '/api/tlsoc/detection/_validate';

function getHandler(
  router: ReturnType<typeof httpServiceMock.createRouter>
): RequestHandler<any, any, any> {
  const call = (router.post as jest.Mock).mock.calls.find((c: any[]) => c[0].path === PATH);
  if (!call) throw new Error(`No POST handler registered for ${PATH}`);
  return call[1];
}

/** A context whose opensearch asCurrentUser transport is pre-stubbed (monitors.test.ts idiom). */
function makeContext(transportRequest: jest.Mock) {
  const ctx = coreMock.createRequestHandlerContext();
  Object.assign(ctx.opensearch.client.asCurrentUser, { transport: { request: transportRequest } });
  return { core: ctx } as any;
}

function makeRequest(body: { index: string; query: string; language: string }) {
  return httpServerMock.createOpenSearchDashboardsRequest({ body });
}

describe('registerDetectionValidateRoutes — POST /api/tlsoc/detection/_validate', () => {
  let router: ReturnType<typeof httpServiceMock.createRouter>;
  const logger = loggerMock.create();

  beforeEach(() => {
    router = httpServiceMock.createRouter();
    jest.clearAllMocks();
  });

  it('valid lucene query → {valid:true}, sent as the exact _validate/query call shape', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest.fn().mockResolvedValue({
      body: { valid: true, _shards: { total: 3, successful: 3, failed: 0 } },
    });
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'fosstlsoc-logs-*', query: 'status:>=400', language: 'lucene' }),
      response
    );

    expect(transportRequest).toHaveBeenCalledTimes(1);
    const call = transportRequest.mock.calls[0][0];
    expect(call.method).toBe('GET');
    expect(call.path).toBe('/fosstlsoc-logs-*/_validate/query');
    expect(call.querystring).toEqual({
      allow_no_indices: 'true',
      ignore_unavailable: 'true',
      explain: 'true',
    });
    expect(call.body).toEqual({
      query: { query_string: { query: 'status:>=400', analyze_wildcard: true } },
    });
    expect(response.ok).toHaveBeenCalledWith({ body: { valid: true } });
  });

  it('invalid query → {valid:false} surfacing explanations[].error', async () => {
    registerDetectionValidateRoutes(router, logger);
    const parseError =
      'ParseException[Cannot parse \'(source.ip:10.0.0.1 AND\': Encountered "<EOF>" at line 1, column 23.]';
    const transportRequest = jest.fn().mockResolvedValue({
      body: {
        valid: false,
        _shards: { total: 1, successful: 1, failed: 0 },
        explanations: [{ index: 'idx-1', valid: false, error: parseError }],
      },
    });
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'idx-1', query: '(source.ip:10.0.0.1 AND', language: 'lucene' }),
      response
    );

    expect(response.ok).toHaveBeenCalledWith({ body: { valid: false, reason: parseError } });
  });

  it('invalid with NO explanations still answers honestly', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest
      .fn()
      .mockResolvedValue({ body: { valid: false, _shards: { total: 1 } } });
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'idx-1', query: 'x:(', language: 'lucene' }),
      response
    );

    expect(response.ok).toHaveBeenCalledWith({
      body: { valid: false, reason: 'The query is invalid.' },
    });
  });

  it('THE 0-SHARDS TRAP: valid:true with _shards.total 0 → valid:false "cannot validate yet"', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest.fn().mockResolvedValue({
      body: { valid: true, _shards: { total: 0, successful: 0, failed: 0 } },
    });
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'tlsoc-nothing-*', query: 'a:1', language: 'lucene' }),
      response
    );

    expect(response.ok).toHaveBeenCalledWith({
      body: {
        valid: false,
        reason: 'no indices currently match "tlsoc-nothing-*" — cannot validate yet',
      },
    });
  });

  it('a 404 (index_not_found despite the flags) is the same "cannot validate yet" verdict', async () => {
    registerDetectionValidateRoutes(router, logger);
    const err: any = new Error('index_not_found_exception');
    err.meta = { statusCode: 404, body: { error: { type: 'index_not_found_exception' } } };
    const transportRequest = jest.fn().mockRejectedValue(err);
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'gone-index', query: 'a:1', language: 'lucene' }),
      response
    );

    expect(response.ok).toHaveBeenCalledWith({
      body: {
        valid: false,
        reason: 'no indices currently match "gone-index" — cannot validate yet',
      },
    });
    expect(response.customError).not.toHaveBeenCalled();
  });

  it('a non-404 cluster failure is a real error (customError), not a fake verdict', async () => {
    registerDetectionValidateRoutes(router, logger);
    const err: any = new Error('security_exception');
    err.meta = { statusCode: 403, body: { error: { type: 'security_exception' } } };
    const transportRequest = jest.fn().mockRejectedValue(err);
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'idx-1', query: 'a:1', language: 'lucene' }),
      response
    );

    expect(response.customError).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403 }));
    expect(response.ok).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalled();
  });

  it('kuery: the query is translated and the TRANSLATED Lucene is what gets validated', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest
      .fn()
      .mockResolvedValue({ body: { valid: true, _shards: { total: 2 } } });
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({
        index: 'fosstlsoc-logs-*',
        query: 'source.ip:"10.0.0.1" and url.path:*admin*',
        language: 'kuery',
      }),
      response
    );

    expect(transportRequest.mock.calls[0][0].body).toEqual({
      query: {
        query_string: {
          query: '(source.ip:"10.0.0.1") AND (url.path:*admin*)',
          analyze_wildcard: true,
        },
      },
    });
    expect(response.ok).toHaveBeenCalledWith({ body: { valid: true } });
  });

  it('kuery syntax error → {valid:false} with the parser message; the cluster is never called', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest.fn();
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'idx-1', query: 'status:', language: 'kuery' }),
      response
    );

    expect(transportRequest).not.toHaveBeenCalled();
    const body = (response.ok as jest.Mock).mock.calls[0][0].body;
    expect(body.valid).toBe(false);
    expect(body.reason).toContain('DQL syntax error: ');
    expect(body.reason).toContain('Expected');
  });

  it('kuery outside the subset → {valid:false} naming the construct; the cluster is never called', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest.fn();
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'idx-1', query: 'user:{ first:"bob" }', language: 'kuery' }),
      response
    );

    expect(transportRequest).not.toHaveBeenCalled();
    const body = (response.ok as jest.Mock).mock.calls[0][0].body;
    expect(body.valid).toBe(false);
    expect(body.reason).toContain('nested query "user:{ … }"');
    expect(body.reason).toContain('threshold rules');
  });

  it('an unknown language 400s BY NAME before any work', async () => {
    registerDetectionValidateRoutes(router, logger);
    const transportRequest = jest.fn();
    const response = httpServerMock.createResponseFactory();

    await getHandler(router)(
      makeContext(transportRequest),
      makeRequest({ index: 'idx-1', query: 'a:1', language: 'sql' }),
      response
    );

    expect(transportRequest).not.toHaveBeenCalled();
    expect(response.badRequest).toHaveBeenCalledWith({
      body: { message: 'Unsupported query language "sql". Supported: lucene, kuery.' },
    });
  });
});
