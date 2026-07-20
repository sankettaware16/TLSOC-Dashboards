/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { createRoot } from 'react-dom/client';
import { AppMountParameters, CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../data/public';
import type { DiscoverStart } from '../../discover/public';
import { ComingSoon, ComingSoonProps } from './components/coming_soon';
import { DetectionsApp } from './detection/detections_app';
import { AlertsApp } from './alerts/alerts_app';
import { CasesApp } from './cases/cases_app';
import { OverviewApp } from './overview/overview_app';
import { ThreatIntelApp } from './threat_intel/threat_intel_app';

/**
 * Mounts a TLSOC placeholder section into the app shell. The same render path backs
 * every not-yet-built SOC section; only the {@link ComingSoonProps} differ per section.
 */
export const renderApp = ({ element }: AppMountParameters, props: ComingSoonProps) => {
  const root = createRoot(element);
  root.render(<ComingSoon {...props} />);

  return () => root.unmount();
};

/** Mounts the "Overview" section: the agentless-pipeline onboarding state + live SOC posture dashboard. */
export const renderOverviewApp = (
  { element }: AppMountParameters,
  deps: { core: CoreStart }
) => {
  const root = createRoot(element);
  root.render(<OverviewApp core={deps.core} />);

  return () => root.unmount();
};

/** Mounts the "Detections" section: the saved-rules list + the no-code builder (create/edit). */
export const renderDetectionsApp = (
  { element }: AppMountParameters,
  deps: { core: CoreStart; data: DataPublicPluginStart }
) => {
  const root = createRoot(element);
  root.render(<DetectionsApp core={deps.core} data={deps.data} />);

  return () => root.unmount();
};

/** Mounts the "Alerts" section: the triage queue + flyout detail + acknowledge action. */
export const renderAlertsApp = (
  { element }: AppMountParameters,
  deps: { core: CoreStart; data: DataPublicPluginStart; discover?: DiscoverStart }
) => {
  const root = createRoot(element);
  root.render(<AlertsApp core={deps.core} data={deps.data} discover={deps.discover} />);

  return () => root.unmount();
};

/** Mounts the "Cases" section: the case list + case detail (create / update / comment / evidence / investigate). */
export const renderCasesApp = (
  { element }: AppMountParameters,
  deps: { core: CoreStart; data: DataPublicPluginStart }
) => {
  const root = createRoot(element);
  root.render(<CasesApp core={deps.core} data={deps.data} />);

  return () => root.unmount();
};

/** Mounts the "Threat Intel" section: the value-lists (IOC) manager (v1.2.3 D6). */
export const renderThreatIntelApp = (
  { element }: AppMountParameters,
  deps: { core: CoreStart }
) => {
  const root = createRoot(element);
  root.render(<ThreatIntelApp core={deps.core} />);

  return () => root.unmount();
};
