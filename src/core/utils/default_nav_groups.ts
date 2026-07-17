/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { i18n } from '@osd/i18n';
import { ChromeNavGroup, NavGroupStatus, NavGroupType } from '../types';

export enum UseCaseId {
  ALL_USE_CASE_ID = 'all',
  OBSERVABILITY_USE_CASE_ID = 'observability',
  SECURITY_ANALYTICS_USE_CASE_ID = 'security-analytics',
  ESSENTIAL_USE_CASE_ID = 'essentials',
  SEARCH_USE_CASE_ID = 'search',
}

export const ALL_USE_CASE_ID = UseCaseId.ALL_USE_CASE_ID;
export const OBSERVABILITY_USE_CASE_ID = UseCaseId.OBSERVABILITY_USE_CASE_ID;
export const SECURITY_ANALYTICS_USE_CASE_ID = UseCaseId.SECURITY_ANALYTICS_USE_CASE_ID;
export const ESSENTIAL_USE_CASE_ID = UseCaseId.ESSENTIAL_USE_CASE_ID;
export const SEARCH_USE_CASE_ID = UseCaseId.SEARCH_USE_CASE_ID;

const defaultNavGroups = {
  dataAdministration: {
    id: 'dataAdministration',
    title: i18n.translate('core.ui.group.dataAdministration.title', {
      defaultMessage: 'Data administration',
    }),
    description: i18n.translate('core.ui.group.dataAdministration.description', {
      defaultMessage: 'Apply policies or security on your data.',
    }),
    order: 1000,
    type: NavGroupType.SYSTEM,
    icon: 'database',
  },
  settingsAndSetup: {
    id: 'settingsAndSetup',
    title: i18n.translate('core.ui.group.settingsAndSetup.title', {
      defaultMessage: 'Settings and setup',
    }),
    description: i18n.translate('core.ui.group.settingsAndSetup.description', {
      defaultMessage: 'Set up your cluster with index patterns.',
    }),
    order: 2000,
    type: NavGroupType.SYSTEM,
    icon: 'gear',
  },
  all: {
    id: ALL_USE_CASE_ID,
    title: i18n.translate('core.ui.group.all.title', {
      defaultMessage: 'Analytics',
    }),
    description: i18n.translate('core.ui.group.all.description', {
      defaultMessage:
        'If you aren’t sure where to start with OpenSearch, or if you have needs that cut across multiple use cases.',
    }),
    order: 3000,
    icon: 'wsAnalytics',
    // TLSOC: hidden — TLSOC is a single-use-case product (Security Operations). Hiding the other
    // use cases makes Security Operations the sole visible use case, so it auto-selects on boot.
    status: NavGroupStatus.Hidden,
  },
  observability: {
    id: OBSERVABILITY_USE_CASE_ID,
    title: i18n.translate('core.ui.group.observability.title', {
      defaultMessage: 'Observability',
    }),
    description: i18n.translate('core.ui.group.observability.description', {
      defaultMessage:
        'Gain visibility into system health, performance, and reliability through monitoring of logs, metrics and traces.',
    }),
    order: 4000,
    icon: 'wsObservability',
    // TLSOC: hidden (single-use-case product — see the 'all' group note).
    status: NavGroupStatus.Hidden,
  },
  'security-analytics': {
    id: SECURITY_ANALYTICS_USE_CASE_ID,
    title: i18n.translate('core.ui.group.security.analytics.title', {
      defaultMessage: 'Security Operations',
    }),
    description: i18n.translate('core.ui.group.security.analytics.description', {
      defaultMessage:
        'Monitor, detect, and investigate security threats across your environment.',
    }),
    order: 5000,
    icon: 'wsSecurityAnalytics',
  },
  essentials: {
    id: ESSENTIAL_USE_CASE_ID,
    title: i18n.translate('core.ui.group.essential.title', {
      defaultMessage: 'Essentials',
    }),
    description: i18n.translate('core.ui.group.essential.description', {
      defaultMessage:
        'Analyze data to derive insights, identify patterns and trends, and make data-driven decisions.',
    }),
    order: 7000,
    icon: 'wsEssentials',
    // TLSOC: hidden (single-use-case product — see the 'all' group note).
    status: NavGroupStatus.Hidden,
  },
  search: {
    id: SEARCH_USE_CASE_ID,
    title: i18n.translate('core.ui.group.search.title', {
      defaultMessage: 'Search',
    }),
    description: i18n.translate('core.ui.group.search.description', {
      defaultMessage:
        "Quickly find and explore relevant information across your organization's data sources.",
    }),
    order: 6000,
    icon: 'wsSearch',
    // TLSOC: hidden (single-use-case product — see the 'all' group note).
    status: NavGroupStatus.Hidden,
  },
} as const;

/** @internal */
export const DEFAULT_NAV_GROUPS: Record<
  keyof typeof defaultNavGroups,
  ChromeNavGroup
> = Object.freeze(defaultNavGroups);
