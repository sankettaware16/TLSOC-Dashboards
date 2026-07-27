/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Subject } from 'rxjs';
import { ACCENT_STYLE_ID, applyAccent } from './apply';
import { ACCENT_SETTING_KEY, DEFAULT_ACCENT_DARK, DEFAULT_ACCENT_LIGHT } from '../../common/accent/palette';

function fakeUiSettings(initial: string) {
  const updates$ = new Subject<string>();
  return {
    updates$,
    client: {
      get: jest.fn((key: string, fallback: string) =>
        key === ACCENT_SETTING_KEY ? initial : fallback
      ),
      get$: jest.fn(() => updates$),
    } as any,
  };
}

describe('applyAccent', () => {
  afterEach(() => {
    document.getElementById(ACCENT_STYLE_ID)?.remove();
    delete (window as any).__osdThemeTag__;
  });

  it('always injects the default patch (teal obs-nav fix + CSS vars), light mode', () => {
    (window as any).__osdThemeTag__ = 'v8light';
    applyAccent({ uiSettings: fakeUiSettings('').client });
    const el = document.getElementById(ACCENT_STYLE_ID)!;
    expect(el).not.toBeNull();
    expect(el.textContent).toContain(`--tlsoc-accent: ${DEFAULT_ACCENT_LIGHT}`);
    expect(el.textContent).toContain('.obs-nav-item:hover');
    // Default = unset: the compiled purple stays authoritative — no override rules injected.
    expect(el.textContent).not.toContain('.euiButton--primary');
  });

  it('detects dark mode from __osdThemeTag__ and adds the full override when a hex is set', () => {
    (window as any).__osdThemeTag__ = 'v8dark';
    applyAccent({ uiSettings: fakeUiSettings('#1D4ED8').client });
    const el = document.getElementById(ACCENT_STYLE_ID)!;
    expect(el.textContent).toContain(`--tlsoc-accent: ${DEFAULT_ACCENT_DARK}`); // default patch first
    expect(el.textContent).toContain('--tlsoc-accent: #1D4ED8'); // accent override wins later
    expect(el.textContent).toContain('@keyframes focusRingAnimate');
    // Dark tint of #1D4ED8 = 35% into ink.
    expect(el.textContent).toContain('rgb(17, 39, 93)');
  });

  it('live-applies and live-reverts via the uiSettings subscription without reloads', () => {
    (window as any).__osdThemeTag__ = 'v8light';
    const { client, updates$ } = fakeUiSettings('');
    applyAccent({ uiSettings: client });
    const el = document.getElementById(ACCENT_STYLE_ID)!;
    expect(el.textContent).not.toContain('#B91C1C');

    updates$.next('#B91C1C');
    expect(el.textContent).toContain('--tlsoc-accent: #B91C1C');

    updates$.next(''); // reset to default: only the default patch remains
    expect(el.textContent).not.toContain('#B91C1C');
    expect(el.textContent).toContain(`--tlsoc-accent: ${DEFAULT_ACCENT_LIGHT}`);
  });

  it('ignores invalid stored values (only the default patch is applied)', () => {
    (window as any).__osdThemeTag__ = 'v8light';
    applyAccent({ uiSettings: fakeUiSettings('#nope; } * { display: none').client });
    const el = document.getElementById(ACCENT_STYLE_ID)!;
    expect(el.textContent).toContain(`--tlsoc-accent: ${DEFAULT_ACCENT_LIGHT}`);
    expect(el.textContent).not.toContain('display: none');
  });

  it('never throws, even when uiSettings is broken (a theming failure must not break boot)', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    expect(() =>
      applyAccent({
        uiSettings: {
          get: () => {
            throw new Error('boom');
          },
          get$: () => {
            throw new Error('boom');
          },
        } as any,
      })
    ).not.toThrow();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});
