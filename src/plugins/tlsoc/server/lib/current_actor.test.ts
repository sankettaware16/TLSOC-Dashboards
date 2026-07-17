/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { getCurrentActor, FALLBACK_ACTOR } from './current_actor';

/** Build a minimal HttpAuth whose get() returns the given status/state (the core contract). */
const authWith = (status: string, state?: unknown) =>
  ({
    get: () => ({ status, state }),
    isAuthenticated: () => status === 'authenticated',
  } as any);

const request = {} as any;

describe('getCurrentActor — the 5a current-user seam (decision pinned here)', () => {
  test('authenticated with user_name → that username', () => {
    const auth = authWith('authenticated', { authInfo: { user_name: 'tlsoc-l1' } });
    expect(getCurrentActor(request, auth)).toBe('tlsoc-l1');
  });

  test('user_id is preferred over user_name (core helper contract)', () => {
    const auth = authWith('authenticated', {
      authInfo: { user_id: 'uid-7', user_name: 'tlsoc-l1' },
    });
    expect(getCurrentActor(request, auth)).toBe('uid-7');
  });

  test('unknown auth status (security-off dev) → fallback analyst', () => {
    const auth = authWith('unknown');
    expect(getCurrentActor(request, auth)).toBe(FALLBACK_ACTOR);
  });

  test('unauthenticated (core helper throws NOT_AUTHORIZED) → fallback, never throws', () => {
    const auth = authWith('unauthenticated');
    expect(getCurrentActor(request, auth)).toBe(FALLBACK_ACTOR);
  });

  test('no auth service at all → fallback', () => {
    expect(getCurrentActor(request, undefined)).toBe(FALLBACK_ACTOR);
  });

  test('authenticated but empty/absent authInfo → fallback (defensive)', () => {
    expect(getCurrentActor(request, authWith('authenticated', { authInfo: {} }))).toBe(
      FALLBACK_ACTOR
    );
    expect(getCurrentActor(request, authWith('authenticated', undefined))).toBe(FALLBACK_ACTOR);
  });
});
