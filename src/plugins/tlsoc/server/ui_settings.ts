/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { schema } from '@osd/config-schema';
import { i18n } from '@osd/i18n';
import { UiSettingsParams } from 'opensearch-dashboards/server';
import { ACCENT_SETTING_KEY, isValidAccentHex } from '../common/accent/palette';

/**
 * The universal accent-palette setting (banner-plugin registration precedent). '' means "use the
 * built-in TLSOC purple" — the compiled theme stays byte-untouched until a hex is set. No 'color'
 * UiSettingsType exists in core, so this is a schema-validated 'string'. requiresPageReload is
 * false because the client applies changes live by rewriting the injected override <style>.
 */
export const getAccentSettings = (): Record<string, UiSettingsParams> => {
  return {
    [ACCENT_SETTING_KEY]: {
      name: i18n.translate('tlsoc.uiSettings.accentColorTitle', {
        defaultMessage: 'TLSOC theme color',
      }),
      value: '',
      type: 'string',
      description: i18n.translate('tlsoc.uiSettings.accentColorText', {
        defaultMessage:
          'One accent color re-themes the whole TLSOC UI — links, buttons, focus rings, and ' +
          'selection highlights are recolored from it, with hover and background shades derived ' +
          'automatically. Enter a #RRGGBB hex (e.g. #1D4ED8), or leave empty to use the ' +
          'built-in purple. Applies instantly; no page reload needed.',
      }),
      category: ['appearance'],
      requiresPageReload: false,
      schema: schema.string({
        validate: (value) =>
          isValidAccentHex(value)
            ? undefined
            : 'must be a 6-digit hex color like #7E22CE, or empty for the built-in purple',
      }),
    },
  };
};
