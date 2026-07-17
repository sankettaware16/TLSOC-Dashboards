/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { PluginInitializerContext, PluginConfigDescriptor } from '../../../core/server';
import { TlsocServerPlugin } from './plugin';
import { configSchema, TlsocConfigType } from './config';

export const config: PluginConfigDescriptor<TlsocConfigType> = {
  schema: configSchema,
  exposeToBrowser: {
    overview: true,
  },
};

export function plugin(initializerContext: PluginInitializerContext) {
  return new TlsocServerPlugin(initializerContext);
}
