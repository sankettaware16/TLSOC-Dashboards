/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { TlsocPlugin } from './plugin';

// This exports static code and TypeScript types,
// as well as, OpenSearch Dashboards Platform `plugin()` initializer.
export const plugin = () => new TlsocPlugin();

export { TlsocPlugin } from './plugin';
export type { TlsocSetup, TlsocStart } from './plugin';
