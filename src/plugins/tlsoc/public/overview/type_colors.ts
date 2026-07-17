/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One categorical color per SIEM source type, shared by the source-type donut, the
 * events-over-time stack, and any type-keyed legend — so a type is the same color everywhere.
 * Uses OUI visualization tokens (dark/light-aware via euiThemeVars).
 */

import { euiThemeVars } from '@osd/ui-shared-deps/theme';
import { SourceType } from '../../common/overview/source_types';

const V = euiThemeVars as unknown as Record<string, string>;

// OUI ships euiColorVis0..euiColorVis9 (theme-aware). Map the 12 types across them.
export const TYPE_COLOR: Record<SourceType, string> = {
  'web-app': V.euiColorVis0 ?? '#54B399',
  'web-proxy': V.euiColorVis1 ?? '#6092C0',
  firewall: V.euiColorVis2 ?? '#D36086',
  auth: V.euiColorVis3 ?? '#9170B8',
  mail: V.euiColorVis4 ?? '#CA8EAE',
  webmail: V.euiColorVis5 ?? '#D6BF57',
  dns: V.euiColorVis6 ?? '#B9A888',
  ids: V.euiColorVis7 ?? '#DA8B45',
  waf: V.euiColorVis8 ?? '#AA6556',
  edr: V.euiColorVis9 ?? '#E7664C',
  erp: V.euiColorVis2 ?? '#D36086',
  other: V.euiColorMediumShade ?? '#98A2B3',
};

export function typeColor(type: string): string {
  return TYPE_COLOR[type as SourceType] ?? (V.euiColorMediumShade ?? '#98A2B3');
}
