/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Small pure dot-path helpers over plain nested objects (a raw event `_source`, or a small
 * synthetic context object). Used by `reason.ts`'s `buildReason`/`substituteFieldPlaceholders` and
 * the alert flyout (highlighted fields, `{{field.path}}` markdown substitution, the flattened
 * event-details table) — WS-1 (PROB-1: an alert carries no event context).
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Read the value at a dot-path (e.g. `'host.name'`) from a nested object. Returns `undefined` when
 * any segment is missing, or when a segment along the way isn't a plain traversable object (e.g. an
 * array or a primitive) — arrays are treated as LEAF values, not traversed into.
 */
export function getPath(obj: unknown, path: string): unknown {
  if (obj == null || typeof obj !== 'object' || !path) return undefined;
  const segments = path.split('.');
  let cur: unknown = obj;
  for (const seg of segments) {
    if (cur == null || typeof cur !== 'object' || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, any>)[seg];
  }
  return cur;
}

/**
 * Flatten a nested object into `{ 'a.b.c': value }` dot-path → leaf-value pairs. Arrays and
 * primitives are leaves (not expanded element-by-element); empty nested objects are skipped
 * entirely (they'd otherwise contribute no leaves and just add noise).
 */
export function flattenObject(obj: unknown, prefix = ''): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (obj == null || typeof obj !== 'object' || Array.isArray(obj)) return out;
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const nested = flattenObject(value, path);
      Object.assign(out, nested);
    } else if (value !== undefined) {
      out[path] = value;
    }
  }
  return out;
}
