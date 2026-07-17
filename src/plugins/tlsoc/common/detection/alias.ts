/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Derive a deterministic, dot-free alias name for an index/data-view pattern (Task 3.5b).
 *
 * OpenSearch 3.7 doc-level (stateless) monitors REJECT index names containing "." or "*" (verified
 * live). Production indices are Logstash daily indices (`fosstlsoc-logs-moodle-YYYY.MM.DD`) — always
 * dotted — so a stateless detection must run against a dot-free ALIAS of the user's index instead.
 *
 * The name is deterministic so (a) every stateless rule on the same data view shares ONE alias, and
 * (b) the user can add the SAME alias to their Logstash/index template to cover future daily indices.
 * Output is guaranteed free of "." and "*" (the characters the doc-level validator rejects).
 */
export function deriveAliasName(indexPattern: string): string {
  const slug = (indexPattern || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return `tlsoc_alias_${slug || 'index'}`;
}
