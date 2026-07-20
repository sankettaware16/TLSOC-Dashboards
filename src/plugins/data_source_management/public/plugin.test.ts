/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { coreMock } from '../../../core/public/mocks';
import { DataSourceManagementPluginStart } from './plugin';
import {
  testDataSourceManagementPlugin,
  createAuthenticationMethod,
  mockInitializerContext,
  managementMock,
  indexPatternManagementMock,
} from './mocks';
import {
  DataSourceManagementPlugin,
  DataSourceManagementSetupDependencies,
  DSM_APP_ID,
} from './plugin';
import { PLUGIN_NAME } from '../common';
import {
  getRenderAccelerationDetailsFlyout,
  getRenderCreateAccelerationFlyout,
  getRenderAssociatedObjectsDetailsFlyout,
} from './plugin';
import { AuthenticationMethodRegistry } from './auth_registry';

describe('#dataSourceManagement', () => {
  let coreSetup: any;
  let coreStart: any;
  let mockDataSourceManagementPluginStart: MockedKeys<DataSourceManagementPluginStart>;

  beforeEach(() => {
    mockDataSourceManagementPluginStart = {
      getAuthenticationMethodRegistry: jest.fn(() => new AuthenticationMethodRegistry()),
    };

    coreSetup = {
      ...coreMock.createSetup({ pluginStartContract: mockDataSourceManagementPluginStart }),
      management: managementMock,
      indexPatternManagement: indexPatternManagementMock,
    };
    coreStart = coreMock.createStart();
  });

  it('can register custom authentication method', () => {
    const { setup, doStart } = testDataSourceManagementPlugin(coreSetup, coreStart);
    const typeA = createAuthenticationMethod({ name: 'typeA' });
    setup.registerAuthenticationMethod(createAuthenticationMethod(typeA));
    const start = doStart();
    const registry = start.getAuthenticationMethodRegistry();
    expect(registry.getAuthenticationMethod('typeA')).toEqual(typeA);
    expect(setup.ui).toEqual({
      DataSourceSelector: expect.any(Function),
      getDataSourceMenu: expect.any(Function),
    });
  });

  it('should not register any authentication method if feature flag is disabled', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    const setupDeps: DataSourceManagementSetupDependencies = {
      management: coreSetup.management,
      indexPatternManagement: coreSetup.indexPatternManagement,
      dataSource: undefined, // Feature flag disabled
    };

    const setup = plugin.setup(coreSetup, setupDeps);
    expect(setup).toBeUndefined();
  });

  it('should return setup object with methods when feature flag is enabled', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    const setupDeps: DataSourceManagementSetupDependencies = {
      management: coreSetup.management,
      indexPatternManagement: coreSetup.indexPatternManagement,
      dataSource: {
        awsSigV4AuthEnabled: true,
        noAuthenticationTypeEnabled: true,
        usernamePasswordAuthEnabled: true,
        hideLocalCluster: false,
      } as any,
    };

    const setup = plugin.setup(coreSetup, setupDeps);
    expect(setup).toBeDefined();
    expect(setup?.registerAuthenticationMethod).toBeInstanceOf(Function);
    expect(setup?.dataSourceSelection).toBeInstanceOf(Object);
    expect(setup?.ui.DataSourceSelector).toBeInstanceOf(Function);
    expect(setup?.ui.getDataSourceMenu).toBeInstanceOf(Function);
  });

  it('should throw error if registering authentication method after startup', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    const setupDeps: DataSourceManagementSetupDependencies = {
      management: coreSetup.management,
      indexPatternManagement: coreSetup.indexPatternManagement,
      dataSource: {
        awsSigV4AuthEnabled: true,
        noAuthenticationTypeEnabled: true,
        usernamePasswordAuthEnabled: true,
        hideLocalCluster: false,
      } as any,
    };

    const setup = plugin.setup(coreSetup, setupDeps);
    plugin.start(coreStart);
    expect(() => {
      setup?.registerAuthenticationMethod(createAuthenticationMethod({ name: 'typeB' }));
    }).toThrow('cannot call `registerAuthenticationMethod` after data source management startup.');
  });

  // TLSOC PROB-26: with multi-data-source DISABLED the plugin must register NO "Data sources"
  // surface at all (management app, nav link, index-pattern column) — a single-cluster SOC would
  // otherwise show an inherently empty page and an always-empty column.
  it('does NOT register the management application when the feature flag is disabled', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    const setupDeps: DataSourceManagementSetupDependencies = {
      management: coreSetup.management,
      indexPatternManagement: coreSetup.indexPatternManagement,
      dataSource: undefined, // Feature flag disabled
    };
    // The registration mocks are shared across this file's tests — drop calls leaked from the
    // enabled-flag cases above so the zero-call assertions below are about THIS setup() only.
    (setupDeps.management.sections.section.opensearchDashboards.registerApp as jest.Mock).mockClear();
    (setupDeps.indexPatternManagement.columns.register as jest.Mock).mockClear();

    plugin.setup(coreSetup, setupDeps);
    expect(
      setupDeps.management.sections.section.opensearchDashboards.registerApp
    ).not.toHaveBeenCalled();
    expect(setupDeps.indexPatternManagement.columns.register).not.toHaveBeenCalled();
  });

  it('registers the management application when the feature flag is enabled', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    const setupDeps: DataSourceManagementSetupDependencies = {
      management: coreSetup.management,
      indexPatternManagement: coreSetup.indexPatternManagement,
      dataSource: {
        awsSigV4AuthEnabled: true,
        noAuthenticationTypeEnabled: true,
        usernamePasswordAuthEnabled: true,
        hideLocalCluster: false,
      } as any,
    };

    plugin.setup(coreSetup, setupDeps);
    expect(
      setupDeps.management.sections.section.opensearchDashboards.registerApp
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        id: DSM_APP_ID,
        title: PLUGIN_NAME,
        order: 1,
        mount: expect.any(Function),
      })
    );
    expect(setupDeps.indexPatternManagement.columns.register).toHaveBeenCalled();
  });

  it('should set and get renderAccelerationDetailsFlyout correctly', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    plugin.setup(coreSetup, {
      management: managementMock,
      indexPatternManagement: indexPatternManagementMock,
      dataSource: {
        awsSigV4AuthEnabled: true,
        noAuthenticationTypeEnabled: true,
        usernamePasswordAuthEnabled: true,
        hideLocalCluster: false,
      } as any,
    });

    plugin.start(coreStart);

    const renderAccelerationDetailsFlyout = getRenderAccelerationDetailsFlyout();
    expect(renderAccelerationDetailsFlyout).toBeInstanceOf(Function);
  });

  it('should set and get renderCreateAccelerationFlyout correctly', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    plugin.setup(coreSetup, {
      management: managementMock,
      indexPatternManagement: indexPatternManagementMock,
      dataSource: {
        awsSigV4AuthEnabled: true,
        noAuthenticationTypeEnabled: true,
        usernamePasswordAuthEnabled: true,
        hideLocalCluster: false,
      } as any,
    });

    plugin.start(coreStart);

    const renderCreateAccelerationFlyout = getRenderCreateAccelerationFlyout();
    expect(renderCreateAccelerationFlyout).toBeInstanceOf(Function);
  });

  it('should set and get renderAssociatedObjectsDetailsFlyout correctly', () => {
    const plugin = new DataSourceManagementPlugin(mockInitializerContext);
    plugin.setup(coreSetup, {
      management: managementMock,
      indexPatternManagement: indexPatternManagementMock,
      dataSource: {
        awsSigV4AuthEnabled: true,
        noAuthenticationTypeEnabled: true,
        usernamePasswordAuthEnabled: true,
        hideLocalCluster: false,
      } as any,
    });

    plugin.start(coreStart);

    const renderAssociatedObjectsDetailsFlyout = getRenderAssociatedObjectsDetailsFlyout();
    expect(renderAssociatedObjectsDetailsFlyout).toBeInstanceOf(Function);
  });
});
