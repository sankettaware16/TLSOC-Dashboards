/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { first } from 'rxjs/operators';
import { CoreSetup, CoreStart, Logger, PluginInitializerContext } from '../../../core/server';
import { HomeServerPluginSetup } from '../../home/server';
import { PluginStart as DataPluginStart } from '../../data/server';
import { registerDetectionRoutes } from './routes';
import {
  detectionRuleSavedObjectType,
  caseSavedObjectType,
  userDirectorySavedObjectType,
} from './saved_objects';
import { tlsocSecurityLogsSpecProvider } from './sample_data';
import { TlsocConfigType } from './config';

export interface TlsocServerPluginSetupDeps {
  home?: HomeServerPluginSetup;
}

/**
 * Plugins whose START contract we need at REQUEST time (not setup time). PROB-2: index-pattern
 * saved objects are workspace-scoped via a strict term-match at `find()` — a data view created
 * from an internal repository at boot would be invisible inside a workspace — so ensuring one
 * must go through the data plugin's request-scoped `indexPatternsServiceFactory`, reached here via
 * `core.getStartServices()` (the same seam `getSavedObjects` below already uses for saved objects).
 */
export interface TlsocServerPluginStartDeps {
  data: DataPluginStart;
}

/**
 * TLSOC's server plugin. For now it hosts the detection-engine routes (Phase 3): the no-code rule
 * builder POSTs a structured rule, the server compiles it with the shared compiler in
 * `common/detection`, and proxies the result to the OpenSearch Alerting API (decision D-008). It
 * also registers the `tlsoc-detection-rule` saved object that stores a saved rule's editable IR
 * (the monitor itself cannot carry it — OS 3.7 Alerting strips `ui_metadata` on persist).
 */
export class TlsocServerPlugin {
  private readonly logger: Logger;

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }

  public async setup(core: CoreSetup<TlsocServerPluginStartDeps>, plugins: TlsocServerPluginSetupDeps = {}) {
    this.logger.debug('tlsoc: server setup');
    core.savedObjects.registerType(detectionRuleSavedObjectType);
    core.savedObjects.registerType(caseSavedObjectType);
    core.savedObjects.registerType(userDirectorySavedObjectType);
    const router = core.http.createRouter();
    // core.http.auth = the current-user seam (Task 5a.2): case routes resolve the acting
    // user from it via getCurrentActor (populated by the vendored security plugin's registerAuth).
    // The savedObjects getter (5b.4a) lets the users route reach the hidden user-directory
    // cache with the workspace wrapper excluded (one GLOBAL directory doc).
    const getSavedObjects = async () => (await core.getStartServices())[0].savedObjects;
    // PROB-2: the data plugin's request-scoped index-patterns factory (see data_views.ts) — must
    // be resolved per-request, never once at setup, so each `_ensure` call runs in the caller's
    // workspace context.
    const getIndexPatternsServiceFactory = async () =>
      (await core.getStartServices())[1].data.indexPatterns.indexPatternsServiceFactory;
    // Overview page config (index pattern for the agentless log pipeline output).
    const { overview } = await this.initializerContext.config
      .create<TlsocConfigType>()
      .pipe(first())
      .toPromise();
    registerDetectionRoutes(
      router,
      this.logger,
      core.http.auth,
      getSavedObjects,
      overview,
      getIndexPatternsServiceFactory
    );
    // "TLSOC Security Logs" sample dataset (interlude task, 2026-07-15) — appears on the
    // Sample data page (globally and inside workspaces) via home's registry.
    plugins.home?.sampleData.registerSampleDataset(tlsocSecurityLogsSpecProvider);
    return {};
  }

  public start(_core: CoreStart) {
    return {};
  }

  public stop() {}
}
