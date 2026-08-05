/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { combineLatest, Observable, Subscription } from 'rxjs';
import { distinctUntilChanged, map } from 'rxjs/operators';
import { i18n } from '@osd/i18n';

import {
  ChromeStart,
  CoreSetup,
  DEFAULT_APP_CATEGORIES,
  PublicAppInfo,
  WorkspacesSetup,
  DEFAULT_NAV_GROUPS,
  ALL_USE_CASE_ID,
  NavGroupStatus,
} from '../../../../core/public';
import {
  WORKSPACE_DETAIL_APP_ID,
  WORKSPACE_USE_CASES,
  WORKSPACE_COLLABORATORS_APP_ID,
} from '../../common/constants';
import {
  convertNavGroupToWorkspaceUseCase,
  getFirstUseCaseOfFeatureConfigs,
  isEqualWorkspaceUseCase,
} from '../utils';
import { WorkspaceUseCase } from '../types';

export interface UseCaseServiceSetupDeps {
  chrome: CoreSetup['chrome'];
  workspaces: WorkspacesSetup;
  getStartServices: CoreSetup['getStartServices'];
}

export class UseCaseService {
  private workspaceAndManageWorkspaceCategorySubscription?: Subscription;

  constructor() {}

  /**
   * Add nav links belong to `manage workspace` to all of the use cases.
   * @param coreSetup
   * @param currentWorkspace
   */
  private async registerManageWorkspaceCategory(setupDeps: UseCaseServiceSetupDeps) {
    const [coreStart] = await setupDeps.getStartServices();
    const isPermissionEnabled = coreStart?.application?.capabilities.workspaces.permissionEnabled;

    this.workspaceAndManageWorkspaceCategorySubscription?.unsubscribe();
    this.workspaceAndManageWorkspaceCategorySubscription = combineLatest([
      setupDeps.workspaces.currentWorkspace$,
      coreStart.chrome.navGroup.getNavGroupsMap$(),
    ])
      .pipe(
        map(([currentWorkspace, navGroupMap]) => {
          const currentUseCase = getFirstUseCaseOfFeatureConfigs(currentWorkspace?.features || []);
          if (!currentUseCase) {
            return undefined;
          }

          return navGroupMap[currentUseCase];
        })
      )
      .pipe(
        distinctUntilChanged((navGroupInfo, anotherNavGroup) => {
          return navGroupInfo?.id === anotherNavGroup?.id;
        })
      )
      .subscribe((navGroupInfo) => {
        if (navGroupInfo) {
          setupDeps.chrome.navGroup.addNavLinksToGroup(navGroupInfo, [
            {
              id: WORKSPACE_DETAIL_APP_ID,
              category: DEFAULT_APP_CATEGORIES.manageWorkspace,
              order: 100,
              title: i18n.translate('workspace.settings.workspaceDetails', {
                defaultMessage: 'Workspace details',
              }),
              euiIconType: 'spacesApp',
            },
            ...(isPermissionEnabled
              ? [
                  {
                    id: WORKSPACE_COLLABORATORS_APP_ID,
                    category: DEFAULT_APP_CATEGORIES.manageWorkspace,
                    order: 200,
                    title: i18n.translate('workspace.settings.workspaceCollaborators', {
                      defaultMessage: 'Collaborators',
                    }),
                    euiIconType: 'users',
                  },
                ]
              : []),
            // TLSOC (5b.2c, human-decided 2026-07-15): the full upstream list STAYS — including
            // Datasets and Sample data. The human explicitly wants sample-data loading (to
            // exercise visualizations) and self-serve dataset/data-view creation inside
            // workspaces. Do NOT trim these again.
            // TLSOC PROB-26 (Tier-1, human-approved 2026-07-20 — SUPERSEDES the 5b.2c note for
            // this ONE item): the 'dataSources' entry is REMOVED. Multi-data-source is disabled
            // on a single-cluster SOC, so the page it points at is inherently empty (the
            // data_source_management plugin no longer registers the app at all when MDS is off —
            // the link would 404). Restore this entry only if MDS is ever enabled.
            {
              id: 'indexPatterns',
              category: DEFAULT_APP_CATEGORIES.manageWorkspace,
              order: 400,
              euiIconType: 'indexPatternApp',
            },
            {
              id: 'datasets',
              category: DEFAULT_APP_CATEGORIES.manageWorkspace,
              order: 400,
              euiIconType: 'indexMapping',
            },
            // TLSOC: the index-management-dashboards-plugin's Indexes page, surfaced right below
            // Data views. The app id is that plugin's per-page id for ROUTES.INDICES ("/indices",
            // URI-encoded); TLSOC's copy of the plugin registers that one app as
            // insideWorkspace|outsideWorkspace so this link survives the in-workspace availability
            // filter (if the plugin is absent, chrome drops the unmatched link — harmless). NOTE:
            // the page lists CLUSTER-WIDE indices; destructive actions are gated by backend security.
            {
              id: 'opensearch_index_management_dashboards_%2Findices',
              category: DEFAULT_APP_CATEGORIES.manageWorkspace,
              order: 450,
              title: i18n.translate('workspace.left.indexManagement.label', {
                defaultMessage: 'Index management',
              }),
              euiIconType: 'indexSettings',
            },
            {
              id: 'objects',
              category: DEFAULT_APP_CATEGORIES.manageWorkspace,
              order: 500,
              euiIconType: 'package',
            },
            {
              id: 'import_sample_data',
              category: DEFAULT_APP_CATEGORIES.manageWorkspace,
              order: 600,
              title: i18n.translate('workspace.left.sampleData.label', {
                defaultMessage: 'Sample data',
              }),
              euiIconType: 'navGetStarted',
            },
          ]);
        }
      });
  }

  setup({ chrome, workspaces, getStartServices }: UseCaseServiceSetupDeps) {
    this.registerManageWorkspaceCategory({
      chrome,
      workspaces,
      getStartServices,
    });
  }

  start({
    chrome,
    workspaceConfigurableApps$,
  }: {
    chrome: ChromeStart;
    workspaceConfigurableApps$: Observable<PublicAppInfo[]>;
  }) {
    return {
      getRegisteredUseCases$: () => {
        if (chrome.navGroup.getNavGroupEnabled()) {
          return chrome.navGroup
            .getNavGroupsMap$()
            .pipe(
              map((navGroupsMap) => {
                // TLSOC (Task 5b.2, D-014/C2): honor NavGroupStatus.Hidden — nav groups hidden by
                // the fork (all/observability/essentials/search) must not become workspace use
                // cases, otherwise the picker offers personas whose apps don't exist here.
                return Object.values(navGroupsMap)
                  .filter((navGroup) => navGroup.status !== NavGroupStatus.Hidden)
                  .map(convertNavGroupToWorkspaceUseCase);
              })
            )
            .pipe(
              distinctUntilChanged((useCases, anotherUseCases) => {
                return (
                  useCases.length === anotherUseCases.length &&
                  useCases.every(
                    (useCase) =>
                      !!anotherUseCases.find((anotherUseCase) =>
                        isEqualWorkspaceUseCase(useCase, anotherUseCase)
                      )
                  )
                );
              })
            )
            .pipe(
              map((useCases) =>
                useCases.sort((a, b) => {
                  // Make sure all use case should be the latest
                  if (a.id === ALL_USE_CASE_ID) {
                    return 1;
                  }
                  if (b.id === ALL_USE_CASE_ID) {
                    return -1;
                  }
                  return (
                    (a.order ?? Number.MAX_SAFE_INTEGER) - (b.order ?? Number.MAX_SAFE_INTEGER)
                  );
                })
              )
            );
        }

        return workspaceConfigurableApps$.pipe(
          map((configurableApps) => {
            const configurableAppsId = configurableApps.map((app) => app.id);

            return [
              WORKSPACE_USE_CASES.observability,
              WORKSPACE_USE_CASES['security-analytics'],
              WORKSPACE_USE_CASES.essentials,
              WORKSPACE_USE_CASES.search,
            ]
              .filter((useCase) => {
                return useCase.features.some((featureId) => configurableAppsId.includes(featureId));
              })
              .map(
                (item) =>
                  ({
                    ...item,
                    features: item.features.map((featureId) => ({
                      title: configurableApps.find((app) => app.id === featureId)?.title,
                      id: featureId,
                    })),
                  } as WorkspaceUseCase)
              )
              .concat({
                ...DEFAULT_NAV_GROUPS.all,
                features: configurableApps.map((app) => ({
                  id: app.id,
                  title: app.title,
                })),
              } as WorkspaceUseCase);
          })
        );
      },
    };
  }

  stop() {
    this.workspaceAndManageWorkspaceCategorySubscription?.unsubscribe();
  }
}
