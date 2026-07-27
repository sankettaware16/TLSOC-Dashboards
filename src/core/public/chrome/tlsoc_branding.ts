/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * TLSOC branding — the ONE place to edit product version + Help-menu links.
 *
 * When the product/repos go public (or move), change the URLs here and nowhere else: the Help
 * popover (Documentation / Parsing engine / Community / Open an issue) and the displayed version
 * all read from this object.
 */
export const TLSOC_BRANDING = {
  /** shown in the Help popover as "v {version}". Bump on each product release. */
  version: '1.3.0',

  /** "Documentation" → the deploy/onboarding repo (rsyslog→Kafka→engine→OpenSearch→TLSOC). */
  docsUrl: 'https://github.com/sankettaware16/TLSOCDockerDeploy',

  /** "Parsing engine" → the FOSS SOC Engine repo (rules, ECS normalization). */
  engineUrl: 'https://github.com/sankettaware16/foss-soc-engine/tree/production-hardening',

  /** "Community" / support link. */
  communityUrl: 'https://github.com/sankettaware16/TLSOCDockerDeploy',

  /** "Open an issue in GitHub" → new-issue page of the deploy repo. */
  githubIssuesUrl: 'https://github.com/sankettaware16/TLSOCDockerDeploy/issues/new',
};
