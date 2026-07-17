/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Assignable-user governance (Task 5b.4a). A user is ASSIGNABLE when they are a real,
 * provisioned SOC user — concretely: not reserved, not hidden, and carrying the
 * `attributes.tlsoc_role` marker every TLSOC-provisioned user gets. This is what keeps the
 * OpenSearch demo service accounts (logstash, kibanaro, readall, anomalyadmin,
 * snapshotrestore — NOT flagged reserved in the demo config) and root/service accounts
 * out of the assignee picker.
 */

export interface AssignableUser {
  name: string;
  role: string;
}

interface InternalUserEntry {
  reserved?: boolean;
  hidden?: boolean;
  attributes?: Record<string, string>;
}

/** Filter + shape the security internal-users API response into the assignable SOC users. */
export function assignableUsersFromInternal(
  raw: Record<string, InternalUserEntry> | undefined | null
): AssignableUser[] {
  return Object.entries(raw ?? {})
    .filter(
      ([, u]) => u?.reserved !== true && u?.hidden !== true && !!u?.attributes?.tlsoc_role
    )
    .map(([name, u]) => ({ name, role: u.attributes!.tlsoc_role }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
