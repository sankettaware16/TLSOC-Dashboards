/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema, TypeOf } from '@osd/config-schema';

/**
 * TLSOC plugin server config. Currently only the Overview page needs settings:
 * which index pattern holds the agentless pipeline's log output. Default catches the
 * three naming conventions in play (live TLSOC `fosstlsoc-logs-*`, reference logstash
 * `all-logs-*`, and the FOSS SOC Engine template `soc-*`).
 */
export const configSchema = schema.object({
  overview: schema.object({
    logIndexPattern: schema.string({
      defaultValue: 'fosstlsoc-logs-*,all-logs-*,soc-*',
    }),
  }),
});

export type TlsocConfigType = TypeOf<typeof configSchema>;
export type OverviewConfig = TlsocConfigType['overview'];
