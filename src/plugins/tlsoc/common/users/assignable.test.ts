/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { assignableUsersFromInternal } from './assignable';

describe('assignableUsersFromInternal (5b.4a governance)', () => {
  it('keeps only users carrying attributes.tlsoc_role', () => {
    const users = assignableUsersFromInternal({
      'tlsoc-l1': { attributes: { tlsoc_role: 'l1-soc-analyst' } },
      logstash: { attributes: {} }, // demo service account — not reserved, must still be excluded
      kibanaro: {},
      admin: {}, // root account — no tlsoc_role, not assignable
      'tlsoc-manager': { attributes: { tlsoc_role: 'soc-manager' } },
    });
    expect(users).toEqual([
      { name: 'tlsoc-l1', role: 'l1-soc-analyst' },
      { name: 'tlsoc-manager', role: 'soc-manager' },
    ]);
  });

  it('excludes reserved and hidden entries even if they carry a role', () => {
    const users = assignableUsersFromInternal({
      ghost: { hidden: true, attributes: { tlsoc_role: 'superuser' } },
      system: { reserved: true, attributes: { tlsoc_role: 'superuser' } },
      'tlsoc-super': { attributes: { tlsoc_role: 'superuser' } },
    });
    expect(users.map((u) => u.name)).toEqual(['tlsoc-super']);
  });

  it('sorts by name and tolerates empty/undefined input', () => {
    expect(assignableUsersFromInternal(undefined)).toEqual([]);
    expect(assignableUsersFromInternal(null)).toEqual([]);
    const users = assignableUsersFromInternal({
      b: { attributes: { tlsoc_role: 'x' } },
      a: { attributes: { tlsoc_role: 'y' } },
    });
    expect(users.map((u) => u.name)).toEqual(['a', 'b']);
  });
});
