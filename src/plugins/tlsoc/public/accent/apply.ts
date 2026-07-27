/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { IUiSettingsClient } from 'opensearch-dashboards/public';
import {
  ACCENT_SETTING_KEY,
  buildAccentCss,
  buildDefaultPatchCss,
  isValidAccentHex,
} from '../../common/accent/palette';

export const ACCENT_STYLE_ID = 'tlsoc-accent';

/**
 * Dark detection from the boot-time theme tag (theme.ts precedent). Light/dark switches are
 * always full page reloads in OSD, so reading it once per page lifetime is correct — derived
 * shades must never be cached across sessions.
 */
function isDarkMode(): boolean {
  const tag = (window as { __osdThemeTag__?: string }).__osdThemeTag__;
  return typeof tag === 'string' && tag.endsWith('dark');
}

function composeCss(rawValue: unknown, isDark: boolean): string {
  // The default patch is ALWAYS on (CSS vars + the teal obs-nav fix); the full accent override
  // stacks after it only when a valid non-empty hex is set, so its rules win the vars/obs-nav.
  const defaultPatch = buildDefaultPatchCss(isDark);
  const accent =
    isValidAccentHex(rawValue) && rawValue !== '' ? buildAccentCss(rawValue, isDark) : '';
  return accent ? `${defaultPatch}\n${accent}` : defaultPatch;
}

/**
 * Injects the accent override <style> and keeps it live. Called from TlsocPlugin.setup():
 * uiSettings values are synchronously available there from injectedMetadata, and plugin setup
 * runs before bootstrap.js attaches the theme CSS links, so this is effectively pre-first-paint
 * (no FOUC). Appending at document.head END keeps the tag after every theme <link>, so it wins
 * document-order ties; the bootstrap createElement patch stamps the CSP nonce automatically.
 *
 * A theming failure must NEVER break boot: everything is wrapped, and errors only console.warn.
 */
export function applyAccent(core: { uiSettings: IUiSettingsClient }): void {
  try {
    const isDark = isDarkMode();
    const styleEl = document.createElement('style');
    styleEl.id = ACCENT_STYLE_ID;
    styleEl.textContent = composeCss(core.uiSettings.get(ACCENT_SETTING_KEY, ''), isDark);
    document.head.appendChild(styleEl);

    // Live apply/revert: replacing textContent restyles instantly; on '' only the default patch
    // remains, so the compiled TLSOC purple returns with zero reloads. The subscription lives as
    // long as the page (the style tag does too), so it is intentionally never unsubscribed.
    core.uiSettings.get$(ACCENT_SETTING_KEY, '').subscribe({
      next: (value) => {
        try {
          styleEl.textContent = composeCss(value, isDark);
        } catch (err) {
          // eslint-disable-next-line no-console
          console.warn('tlsoc: failed to re-apply accent color', err);
        }
      },
      error: (err) => {
        // eslint-disable-next-line no-console
        console.warn('tlsoc: accent color subscription failed', err);
      },
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('tlsoc: failed to apply accent color', err);
  }
}
