/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { i18n } from '@osd/i18n';
import { Subscription } from 'rxjs';
import {
  AppCategory,
  AppMountParameters,
  CoreSetup,
  CoreStart,
  DEFAULT_NAV_GROUPS,
} from 'opensearch-dashboards/public';
import { EuiIconType } from '@elastic/eui/src/components/icon/icon';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { DataPublicPluginStart } from '../../data/public';
import { ComingSoonProps } from './components/coming_soon';
import { applyAccent } from './accent/apply';
import { AccentPickerNavControl } from './accent/accent_picker';

/** A TLSOC-owned section of the Security Operations nav tree. */
interface SocSection {
  /** App id — also the URL (/app/<id>). Stable; referenced by deep links. */
  id: string;
  /** Order within the Security Operations nav group (matches the SOC tree in PROJECT_BRIEF §5). */
  order: number;
  /** Label shown in the nav. */
  navTitle: string;
  /** Icon shown in the nav. */
  iconType: EuiIconType;
  /** Props for the shared "Coming soon" placeholder this section renders for now. */
  page: ComingSoonProps;
}

export const TLSOC_OVERVIEW_APP_ID = 'tlsoc_overview';

/**
 * The TLSOC-native sections of the Security Operations tree. Sections without a real app yet render
 * the shared {@link ComingSoon} placeholder (decision D-007); each is swapped for its real screen as
 * that feature lands (Phases 3–4). "Investigations" (Discover) and "Dashboards" are existing apps
 * wired into the same group by their own plugins; "Administration" is added in a later task.
 */
function buildSections(): SocSection[] {
  return [
    {
      id: TLSOC_OVERVIEW_APP_ID,
      order: 10,
      navTitle: i18n.translate('tlsoc.nav.overview', { defaultMessage: 'Overview' }),
      iconType: 'wsSecurityAnalytics',
      page: {
        title: i18n.translate('tlsoc.overview.pageTitle', {
          defaultMessage: 'Security operations overview',
        }),
        description: i18n.translate('tlsoc.overview.pageDescription', {
          defaultMessage:
            'A unified view of your security posture — alerts, cases, detections, and threat intelligence — is on the way.',
        }),
        iconType: 'wsSecurityAnalytics',
      },
    },
    {
      id: 'tlsoc_alerts',
      order: 20,
      navTitle: i18n.translate('tlsoc.nav.alerts', { defaultMessage: 'Alerts' }),
      iconType: 'bell',
      page: {
        title: i18n.translate('tlsoc.alerts.pageTitle', { defaultMessage: 'Alerts' }),
        description: i18n.translate('tlsoc.alerts.pageDescription', {
          defaultMessage:
            'Triage the alert queue — prioritize, group, and act on detections across your environment.',
        }),
        iconType: 'bell',
      },
    },
    {
      id: 'tlsoc_cases',
      order: 40,
      navTitle: i18n.translate('tlsoc.nav.cases', { defaultMessage: 'Cases' }),
      iconType: 'folderClosed',
      page: {
        title: i18n.translate('tlsoc.cases.pageTitle', { defaultMessage: 'Cases' }),
        description: i18n.translate('tlsoc.cases.pageDescription', {
          defaultMessage:
            'Track investigations end to end — assignments, status, evidence, and timelines in one place.',
        }),
        iconType: 'folderClosed',
      },
    },
    {
      id: 'tlsoc_detections',
      order: 50,
      navTitle: i18n.translate('tlsoc.nav.detections', { defaultMessage: 'Detections' }),
      iconType: 'inspect',
      page: {
        title: i18n.translate('tlsoc.detections.pageTitle', { defaultMessage: 'Detections' }),
        description: i18n.translate('tlsoc.detections.pageDescription', {
          defaultMessage:
            'Build and manage detection rules with a no-code editor — no Sigma or query language required.',
        }),
        iconType: 'inspect',
      },
    },
    {
      id: 'tlsoc_threat_intel',
      order: 60,
      navTitle: i18n.translate('tlsoc.nav.threatIntel', { defaultMessage: 'Threat Intel' }),
      iconType: 'globe',
      page: {
        title: i18n.translate('tlsoc.threatIntel.pageTitle', {
          defaultMessage: 'Threat intelligence',
        }),
        description: i18n.translate('tlsoc.threatIntel.pageDescription', {
          defaultMessage:
            'Correlate activity against threat-intelligence feeds and indicators of compromise.',
        }),
        iconType: 'globe',
      },
    },
    {
      id: 'tlsoc_assets',
      order: 70,
      navTitle: i18n.translate('tlsoc.nav.assets', { defaultMessage: 'Assets' }),
      iconType: 'compute',
      page: {
        title: i18n.translate('tlsoc.assets.pageTitle', { defaultMessage: 'Assets' }),
        description: i18n.translate('tlsoc.assets.pageDescription', {
          defaultMessage:
            'Inventory the hosts, users, and services across your environment for investigation context.',
        }),
        iconType: 'compute',
      },
    },
  ];
}

/**
 * TLSOC's first in-repo plugin — the home for all TLSOC-native screens. It registers the
 * Security Operations sections (currently shared "Coming soon" placeholders) and wires them into
 * the Security Operations nav group. The detection builder, cases, and investigations land here later.
 */
export class TlsocPlugin {
  /** Workspace ids the entry-seed hook has already fired `_ensure` for this session (see `start`).
   * Defense-in-depth only — workspace switches are always hard page reloads (D-verified), so this
   * Set never actually accumulates more than one entry in practice. */
  private seededWorkspaceIds = new Set<string>();
  private workspaceSeedSubscription?: Subscription;

  public setup(core: CoreSetup) {
    // Universal accent palette: inject the override <style> NOW — uiSettings are synchronously
    // available from injectedMetadata, and plugin setup runs before bootstrap.js attaches the
    // theme CSS, so this is effectively pre-first-paint (no FOUC). Never throws (see apply.ts).
    applyAccent(core);

    const sections = buildSections();

    sections.forEach((section) => {
      core.application.register({
        id: section.id,
        title: section.navTitle,
        order: section.order,
        euiIconType: section.iconType,
        mount: async (params: AppMountParameters) => {
          // The "Overview" section is the SOC landing page: an agentless-pipeline onboarding
          // state when no logs are flowing yet, and a live posture dashboard once they are.
          if (section.id === TLSOC_OVERVIEW_APP_ID) {
            const [coreStart] = await core.getStartServices();
            const { renderOverviewApp } = await import('./application');
            return renderOverviewApp(params, { core: coreStart });
          }
          // The "Alerts" section hosts the triage queue (Task 4.2).
          if (section.id === 'tlsoc_alerts') {
            const [coreStart, plugins] = await core.getStartServices();
            const { renderAlertsApp } = await import('./application');
            const deps = plugins as {
              data: DataPublicPluginStart;
              discover?: import('../../discover/public').DiscoverStart;
            };
            return renderAlertsApp(params, {
              core: coreStart,
              data: deps.data,
              discover: deps.discover,
            });
          }
          // The "Cases" section hosts the case management UI (Task 4.4) + the in-context
          // investigation grid (Task 4.5), which needs the data plugin's search primitives.
          if (section.id === 'tlsoc_cases') {
            const [coreStart, plugins] = await core.getStartServices();
            const { renderCasesApp } = await import('./application');
            return renderCasesApp(params, {
              core: coreStart,
              data: (plugins as { data: DataPublicPluginStart }).data,
            });
          }
          // The "Detections" section hosts the real no-code rule builder (Task 3.4); every other
          // unbuilt section shares the ComingSoon placeholder.
          if (section.id === 'tlsoc_detections') {
            const [coreStart, plugins] = await core.getStartServices();
            const { renderDetectionsApp } = await import('./application');
            return renderDetectionsApp(params, {
              core: coreStart,
              data: (plugins as { data: DataPublicPluginStart }).data,
            });
          }
          // v1.2.3 D6: the "Threat Intel" section hosts the value-lists (IOC) manager.
          if (section.id === 'tlsoc_threat_intel') {
            const [coreStart] = await core.getStartServices();
            const { renderThreatIntelApp } = await import('./application');
            return renderThreatIntelApp(params, { core: coreStart });
          }
          const { renderApp } = await import('./application');
          return renderApp(params, section.page);
        },
      });
    });

    // Surface every TLSOC-native section inside the Security Operations (security-analytics) nav group,
    // plus "Administration" (the existing management app: index patterns, saved objects, advanced
    // settings, …) as the final section. ("Investigations"=Discover and "Dashboards" are added to the
    // same group by their own plugins.)
    //
    // PROB-28 Option B (tester decision 2026-07-20): the three GLOBAL-ONLY entries below (their apps
    // are outsideWorkspace/admin-gated, so they drop out of the in-workspace nav) sit in their own
    // labeled trailing category. That way the nav changing between inside/outside a workspace reads
    // as intentional. Grouping/label only — app ids, routes and per-link orders untouched. Category
    // order 8500 lands the section after the flat SOC links (10–90) and before the workspace
    // plugin's "Manage workspace" category (9000). In the SOC use case categories render as
    // always-open labeled sections (collapsing is an ALL-use-case-only behavior).
    const globalAdministrationCategory: AppCategory = {
      id: 'tlsoc_global_administration',
      label: i18n.translate('tlsoc.nav.globalAdministration', {
        defaultMessage: 'Global administration',
      }),
      order: 8500,
    };
    core.chrome.navGroup.addNavLinksToGroup(DEFAULT_NAV_GROUPS['security-analytics'], [
      ...sections.map((section) => ({
        id: section.id,
        title: section.navTitle,
        order: section.order,
      })),
      {
        // User management → the security plugin's access-control hub (internal users, roles,
        // permissions — the stock ELK-style flows; task 5b.4b). The app registers only for callers
        // with security-API access (restapiinfo has_api_access), so chrome drops this link
        // automatically for non-admins.
        id: 'security-dashboards-plugin_getstarted',
        title: i18n.translate('tlsoc.nav.userManagement', { defaultMessage: 'User management' }),
        order: 85,
        category: globalAdministrationCategory,
      },
      {
        // Organizations → the stock workspace list (1 workspace = 1 org per D-014; task 5b.5).
        // Create/rename/delete are dashboard-admin-gated inside the stock pages; non-admins just
        // see the orgs they belong to. The app is outsideWorkspace, so clicking from inside an
        // org navigates out to the global list (same behavior as settings_landing below).
        id: 'workspace_list',
        title: i18n.translate('tlsoc.nav.organizations', { defaultMessage: 'Organizations' }),
        order: 87,
        category: globalAdministrationCategory,
      },
      {
        // Administration → the management "Settings and setup" landing (index patterns, saved objects,
        // advanced settings, …). We point at `settings_landing` (visible in nav-group mode) rather than the
        // `management` app, which registers as navLinkStatus:hidden when nav groups are enabled and would be
        // filtered out of the rendered nav.
        id: 'settings_landing',
        title: i18n.translate('tlsoc.nav.administration', { defaultMessage: 'Administration' }),
        order: 90,
        category: globalAdministrationCategory,
      },
    ]);

    return {};
  }

  /**
   * PROB-2 WORKSPACE-FLOW fix: the real banner fix. Seeds the agentless pipeline's data view(s) on
   * every WORKSPACE ENTRY, regardless of which app (Overview / Alerts / Cases / Detections) the
   * analyst opens first — the earlier fix only seeded from Overview's own mount effect, so any
   * other app opened first left the workspace with zero data views. `core.workspaces` is on
   * `CoreStart` (non-optional) and `currentWorkspaceId$` is already populated before any plugin's
   * `start()` runs, so this subscription's first emission already carries the real id. `core.http`
   * automatically carries the page's `/w/<id>/` prefix, so the POST lands scoped to that workspace
   * — never global. Workspace switches are always hard page reloads (no client-side navigation
   * between workspaces), so `seededWorkspaceIds` never actually needs to evict; it's defense in
   * depth against a double-fire within one page's lifetime. Mirrors the precedent in
   * `workspace/public/plugin.ts` (`_changeSavedObjectCurrentWorkspace`, ~L117-125): subscribe +
   * guard + stored `Subscription`, unsubscribed in `stop()`.
   */
  public start(core: CoreStart) {
    // The accent-palette header control (brush icon, right side — before the account button at
    // order 2000). Header-control precedent: management/dev_tools register nav controls in
    // start() with a mount that renders + returns an unmount.
    core.chrome.navControls.registerRight({
      order: 1500,
      mount: (element: HTMLElement) => {
        const root = createRoot(element);
        root.render(React.createElement(AccentPickerNavControl, { core }));
        return () => root.unmount();
      },
    });

    this.workspaceSeedSubscription = core.workspaces.currentWorkspaceId$.subscribe((id) => {
      if (id && !this.seededWorkspaceIds.has(id)) {
        this.seededWorkspaceIds.add(id);
        core.http
          .post('/api/tlsoc/data_views/_ensure', { body: JSON.stringify({ perEndpoint: true }) })
          .catch(() => {});
      }
    });
    return {};
  }

  public stop() {
    this.workspaceSeedSubscription?.unsubscribe();
  }
}

export type TlsocSetup = ReturnType<TlsocPlugin['setup']>;
export type TlsocStart = ReturnType<TlsocPlugin['start']>;
