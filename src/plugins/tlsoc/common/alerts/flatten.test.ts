/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { flattenObject, getPath } from './flatten';

describe('getPath', () => {
  const doc = {
    host: { name: 'web-01' },
    source: { ip: '66.66.66.66', port: 443 },
    tags: ['a', 'b'],
    event: { original: '{"raw":true}' },
  };

  it('reads a top-level field', () => {
    expect(getPath(doc, 'tags')).toEqual(['a', 'b']);
  });

  it('reads a nested field via a dot-path', () => {
    expect(getPath(doc, 'host.name')).toBe('web-01');
    expect(getPath(doc, 'source.ip')).toBe('66.66.66.66');
    expect(getPath(doc, 'source.port')).toBe(443);
  });

  it('returns undefined for a missing top-level field', () => {
    expect(getPath(doc, 'user.name')).toBeUndefined();
  });

  it('returns undefined for a missing nested field', () => {
    expect(getPath(doc, 'host.ip')).toBeUndefined();
  });

  it('returns undefined when traversing THROUGH an array (arrays are leaves)', () => {
    expect(getPath(doc, 'tags.0')).toBeUndefined();
  });

  it('returns undefined when traversing through a primitive', () => {
    expect(getPath(doc, 'source.ip.foo')).toBeUndefined();
  });

  it('returns undefined for an empty path', () => {
    expect(getPath(doc, '')).toBeUndefined();
  });

  it('returns undefined when obj is null/undefined/not an object', () => {
    expect(getPath(null, 'a.b')).toBeUndefined();
    expect(getPath(undefined, 'a.b')).toBeUndefined();
    expect(getPath('str', 'a.b')).toBeUndefined();
  });
});

describe('flattenObject', () => {
  it('flattens nested objects into dot-path keys', () => {
    const flat = flattenObject({ host: { name: 'web-01' }, source: { ip: '1.2.3.4', port: 443 } });
    expect(flat).toEqual({ 'host.name': 'web-01', 'source.ip': '1.2.3.4', 'source.port': 443 });
  });

  it('keeps arrays and primitives as leaves (does not expand array elements)', () => {
    const flat = flattenObject({ tags: ['a', 'b'], count: 3, ok: true });
    expect(flat).toEqual({ tags: ['a', 'b'], count: 3, ok: true });
  });

  it('skips empty nested objects (they contribute no leaves)', () => {
    const flat = flattenObject({ a: {}, b: { c: 1 } });
    expect(flat).toEqual({ 'b.c': 1 });
  });

  it('skips undefined leaf values', () => {
    const flat = flattenObject({ a: undefined, b: 1 });
    expect(flat).toEqual({ b: 1 });
  });

  it('keeps null leaf values (a real, present value)', () => {
    const flat = flattenObject({ a: null, b: 1 });
    expect(flat).toEqual({ a: null, b: 1 });
  });

  it('returns {} for null/non-object input', () => {
    expect(flattenObject(null)).toEqual({});
    expect(flattenObject(undefined)).toEqual({});
    expect(flattenObject('x')).toEqual({});
    expect(flattenObject(['a', 'b'])).toEqual({});
  });

  it('round-trips a realistic multi-level ECS-ish doc', () => {
    const flat = flattenObject({
      '@timestamp': '2026-07-17T00:00:00Z',
      host: { name: 'web-01' },
      source: { ip: '66.66.66.66', geo: { country: 'IN' } },
      event: { action: 'login', outcome: 'failure' },
    });
    expect(flat).toEqual({
      '@timestamp': '2026-07-17T00:00:00Z',
      'host.name': 'web-01',
      'source.ip': '66.66.66.66',
      'source.geo.country': 'IN',
      'event.action': 'login',
      'event.outcome': 'failure',
    });
  });
});
