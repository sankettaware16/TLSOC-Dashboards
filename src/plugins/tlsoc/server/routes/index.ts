/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { HttpAuth, IRouter, Logger, SavedObjectsServiceStart } from '../../../../core/server';
import { registerExecuteDetectionRoute } from './detection';
import { registerMonitorRoutes } from './monitors';
import { registerAlertRoutes } from './alerts';
import { registerCaseRoutes } from './cases';
import { registerUserRoutes } from './users';
import { registerOverviewRoutes } from './overview';
import { registerDataViewsRoutes, GetIndexPatternsServiceFactory } from './data_views';
import { OverviewConfig } from '../config';

export function registerDetectionRoutes(
  router: IRouter,
  logger: Logger,
  auth?: HttpAuth,
  getSavedObjects?: () => Promise<SavedObjectsServiceStart>,
  overview?: OverviewConfig,
  getIndexPatternsServiceFactory?: GetIndexPatternsServiceFactory,
  workspaceEnabled?: boolean
) {
  registerExecuteDetectionRoute(router, logger);
  // Overview aggregates the agentless log pipeline's output; read-only, asCurrentUser-scoped.
  if (overview) {
    registerOverviewRoutes(router, logger, overview);
  }
  // 5b.3c: monitor + alert routes take auth for the per-role guards (the approved matrix);
  // case routes use it for both the guards and audit-actor stamping. Users + the dry-run
  // execute route stay open to any authenticated user; the users route additionally gets
  // the savedObjects getter for the 5b.4a user-directory cache.
  registerMonitorRoutes(router, logger, auth);
  registerAlertRoutes(router, logger, auth);
  registerUserRoutes(router, logger, getSavedObjects);
  registerCaseRoutes(router, logger, auth);
  // PROB-2: data-view bootstrap (request-scoped ensure, see data_views.ts) — a read-style route
  // like overview/GET-alerts, so it takes no role guard (any authenticated user may self-heal
  // their own workspace's data views on Investigate/Overview). `overview` threads the configured
  // log-index pattern for the base view's title; `workspaceEnabled` gates the no-workspace orphan
  // guard (PROB-2 WORKSPACE-FLOW fix).
  if (getIndexPatternsServiceFactory) {
    registerDataViewsRoutes(router, logger, getIndexPatternsServiceFactory, overview, workspaceEnabled);
  }
}
