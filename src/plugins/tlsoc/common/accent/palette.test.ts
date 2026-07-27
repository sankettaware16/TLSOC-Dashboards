/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  ACCENT_FILL_TEXT_GHOST,
  ACCENT_FILL_TEXT_INK,
  DEFAULT_ACCENT_DARK,
  DEFAULT_ACCENT_LIGHT,
  buildAccentCss,
  buildDefaultPatchCss,
  isValidAccentHex,
  pickFillTextColor,
} from './palette';

describe('isValidAccentHex', () => {
  it('accepts the empty string (= use the built-in purple)', () => {
    expect(isValidAccentHex('')).toBe(true);
  });

  it('accepts full 6-digit #RRGGBB hexes in any case', () => {
    for (const v of ['#7E22CE', '#c266ff', '#000000', '#FFFFFF', '#1d4Ed8']) {
      expect(isValidAccentHex(v)).toBe(true);
    }
  });

  it('rejects everything else', () => {
    for (const v of [
      '#FFF', // shorthand
      '#7E22CE00', // 8-digit
      '7E22CE', // missing #
      '#7E22CG', // bad digit
      '#7E22C', // 5 digits
      ' #7E22CE', // padding
      '#7E22CE ',
      'rebeccapurple',
      'rgb(1, 2, 3)',
      '--tlsoc-accent',
      '#7E22CE; } body { display: none', // css injection attempt
    ]) {
      expect(isValidAccentHex(v)).toBe(false);
    }
    expect(isValidAccentHex(undefined)).toBe(false);
    expect(isValidAccentHex(null)).toBe(false);
    expect(isValidAccentHex(7)).toBe(false);
  });
});

describe('pickFillTextColor (relative-luminance flip)', () => {
  it('uses ghost text on dark accents', () => {
    expect(pickFillTextColor('#000000')).toBe(ACCENT_FILL_TEXT_GHOST);
    expect(pickFillTextColor('#1D4ED8')).toBe(ACCENT_FILL_TEXT_GHOST);
    expect(pickFillTextColor('#B91C1C')).toBe(ACCENT_FILL_TEXT_GHOST);
  });

  it('uses ink text on light accents', () => {
    expect(pickFillTextColor('#FFFFFF')).toBe(ACCENT_FILL_TEXT_INK);
    expect(pickFillTextColor('#FDE047')).toBe(ACCENT_FILL_TEXT_INK);
  });

  it('reproduces the compiled defaults: ghost on light-mode purple, ink on dark-mode purple', () => {
    expect(pickFillTextColor(DEFAULT_ACCENT_LIGHT)).toBe(ACCENT_FILL_TEXT_GHOST);
    expect(pickFillTextColor(DEFAULT_ACCENT_DARK)).toBe(ACCENT_FILL_TEXT_INK);
  });
});

describe('buildAccentCss', () => {
  const light = buildAccentCss('#1D4ED8', false);
  const dark = buildAccentCss('#1D4ED8', true);

  it('returns empty for unset or invalid accents (a theming bug must never emit garbage CSS)', () => {
    expect(buildAccentCss('', false)).toBe('');
    expect(buildAccentCss('not-a-hex', false)).toBe('');
    expect(buildAccentCss('#FFF', true)).toBe('');
  });

  it('re-declares BOTH focus-ring keyframes (plus -webkit-), with the accent ring color', () => {
    for (const css of [light, dark]) {
      expect(css).toContain('@keyframes focusRingAnimate {');
      expect(css).toContain('@-webkit-keyframes focusRingAnimate {');
      expect(css).toContain('@keyframes focusRingAnimateLarge {');
      expect(css).toContain('@-webkit-keyframes focusRingAnimateLarge {');
      expect(css).toContain('box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.21)');
      expect(css).toContain('box-shadow: 0 0 0 4px rgba(29, 78, 216, 0.21)');
    }
  });

  it('never puts !important inside keyframes (invalid CSS — the declaration would be dropped)', () => {
    for (const css of [light, dark]) {
      const keyframeBlocks = css.match(/@[^{]*keyframes[^{]*\{[\s\S]*?\}\s*\}/g)!;
      expect(keyframeBlocks.length).toBe(4);
      for (const block of keyframeBlocks) {
        expect(block).not.toContain('!important');
      }
    }
  });

  // The full teal census: every accent-semantic selector the optimizer compiled upstream-teal
  // into a REACHABLE bundle. Must appear in BOTH builders (shared TEAL_CENSUS_RULES table).
  const tealCensusSelectors = [
    '.obs-nav-item:hover, .obs-nav-child-item:hover',
    '.obs-nav-item[data-active="true"]::before, .obs-nav-child-item[data-active="true"]::before',
    '.sidecar-resizableButton:focus:not(:disabled)',
    '.sidecar-resizableButton:focus:not(:disabled)::before, .sidecar-resizableButton:focus:not(:disabled)::after',
    '.variableQueryPanelEditor--focused',
    '.variableSelectorContainer:hover',
    'table th button.fa-sort-asc, table th button.fa-sort-down, table th i.fa-sort-asc, table th i.fa-sort-down, table th button.fa-sort-desc, table th button.fa-sort-up, table th i.fa-sort-desc, table th i.fa-sort-up',
    '.conApp__resizer:focus, .conApp__resizer.active',
    '.osdSavedQueryListItem',
    '.osdSuggestionItem.osdSuggestionItem--operator .osdSuggestionItem__type',
    '.visEditor__resizer:focus, .visEditor__resizer.active',
    '.ouiSaturation:focus .ouiSaturation__indicator',
    '.ouiHue__range:focus::-webkit-slider-thumb',
    '.ouiHue__range:focus::-moz-range-thumb',
    '.ouiHue__range:focus::-ms-thumb',
    '.ouiColorStops:not(.ouiColorStops-isDisabled):focus',
    '.tvbEditorVisualization__draghandle:focus, .tvbEditorVisualization__draghandle.active',
    '.osdUiAceKeyboardHint:focus',
    '.homSolutionPanel__header',
  ];

  it('covers every teal-census selector (SOC nav, sidecar, dashboard, discover, console, data, vis editors, ace hint, home)', () => {
    for (const css of [light, dark]) {
      for (const selector of tealCensusSelectors) {
        expect(css).toContain(`${selector} {`);
      }
    }
  });

  it('recolors the filled-button press shadow with the compiled formula (rgba(HSL darken 10%, 0.28))', () => {
    for (const css of [light, dark]) {
      expect(css).toContain('.euiButton--primary.euiButton--fill:not([class*=isDisabled]):active {');
      expect(css).toContain(
        '.euiButtonIcon--primary.euiButtonIcon--fill:not([class*=isDisabled]):active {'
      );
    }
    // Feeding the defaults back through reproduces the compiled bundles' shadows:
    // light eui_theme_next_light.tlsoc.css:2471 rgba(99.225, 26.775, 162.225, 0.28) and the
    // dark bundle's rgba(173.6666666667, 51, 255, 0.28) (we round to ints).
    expect(buildAccentCss(DEFAULT_ACCENT_LIGHT, false)).toContain(
      'inset 1px 2px 8px rgba(99, 27, 162, 0.28)'
    );
    expect(buildAccentCss(DEFAULT_ACCENT_DARK, true)).toContain(
      'inset 1px 2px 8px rgba(174, 51, 255, 0.28)'
    );
  });

  it('guards EVERY focus-gradient selector with an invalid-state :not() so danger underlines survive', () => {
    for (const css of [light, dark]) {
      // Every rule that paints the accent underline gradient must guard every one of its
      // comma-separated selectors — otherwise a focused-but-invalid field loses its red state.
      const gradientBlocks = css
        .split('\n}')
        .filter((block) => block.includes('background-image: linear-gradient'));
      expect(gradientBlocks.length).toBeGreaterThanOrEqual(4);
      for (const block of gradientBlocks) {
        const selectorList = block.slice(0, block.indexOf('{'));
        for (const selector of selectorList.split(',')) {
          expect(selector).toContain(':not(');
        }
      }
      // The exact invalid classnames, read from the compiled theme bundles.
      expect(css).toContain('.euiFieldText:focus:not(:invalid):not(.euiFieldText-isInvalid)');
      expect(css).toContain(
        '.euiSuperSelectControl:focus:not(:invalid):not(.euiSuperSelectControl-isInvalid)'
      );
      expect(css).toContain(
        '.euiComboBox.euiComboBox-isOpen:not(.euiComboBox-isInvalid) .euiComboBox__inputWrap'
      );
      expect(css).toContain(':not(.euiFilePicker-isInvalid)');
      expect(css).toContain('.euiDatePopoverButton:focus:not(.euiDatePopoverButton-isInvalid)');
      expect(css).toContain(
        ':not(.euiMarkdownEditorDropZone--hasError):not(.euiMarkdownEditorDropZone--isDraggingError)'
      );
    }
  });

  it('publishes the CSS vars for TLSOC components', () => {
    expect(light).toContain('--tlsoc-accent: #1D4ED8 !important;');
    expect(light).toContain(`--tlsoc-accent-fill-text: ${ACCENT_FILL_TEXT_GHOST} !important;`);
  });

  it('derives the fill-hover shade with the compiled formula (HSL darken 5%)', () => {
    // #7E22CE compiled fill-hover is rgb(112.6125, 30.3875, 184.1125); ours rounds to ints.
    expect(buildAccentCss(DEFAULT_ACCENT_LIGHT, false)).toContain('rgb(113, 30, 184)');
    // #C266FF compiled fill-hover is rgb(183.83, 76.5, 255) (float dust rounds g to 76).
    expect(buildAccentCss(DEFAULT_ACCENT_DARK, true)).toContain('rgb(184, 76, 255)');
  });

  it('uses the mode-correct tint base: 10% into ghost for light, 35% into ink for dark', () => {
    // Compiled light tint of #7E22CE is rgb(239.4, 232, 250.1); dark is rgb(74.4, 47.4, 106.15).
    expect(buildAccentCss(DEFAULT_ACCENT_LIGHT, false)).toContain('rgb(239, 232, 250)');
    expect(buildAccentCss(DEFAULT_ACCENT_DARK, true)).toContain('rgb(74, 47, 106)');
    // And the two modes derive DIFFERENT tints from the same accent (#1D4ED8).
    expect(light).toContain('rgb(230, 236, 251)'); // 10% into #FCFEFF
    expect(dark).toContain('rgb(17, 39, 93)'); // 35% into #0A121A
    expect(light).not.toEqual(dark);
  });

  it('marks (nearly) every declaration !important so it beats the compiled bundles', () => {
    // 4 keyframe blocks x 2 declarations are legitimately plain, plus the single bare-`a` rule;
    // everything else must carry !important. Sanity: a large count and only 9 plain declarations.
    for (const css of [light, dark]) {
      const decls = css.match(/;\n/g)!.length;
      const important = css.match(/ !important;/g)!.length;
      expect(important).toBeGreaterThan(150);
      expect(decls - important).toBeLessThanOrEqual(9);
    }
  });

  it('emits well-formed CSS: balanced braces, no undefined/NaN tokens', () => {
    for (const css of [light, dark, buildDefaultPatchCss(false), buildDefaultPatchCss(true)]) {
      expect((css.match(/\{/g) || []).length).toBe((css.match(/\}/g) || []).length);
      expect(css).not.toMatch(/undefined|NaN|null/);
    }
  });

  it('keeps vendor-prefixed slider pseudo selectors in separate rules (one unknown vendor pseudo invalidates a joined list)', () => {
    for (const css of [light, dark]) {
      for (const line of css.split('\n').filter((l) => l.includes('-webkit-slider-thumb'))) {
        expect(line).not.toContain('-moz-');
        expect(line).not.toContain('-ms-');
      }
    }
  });

  it('only overrides form-control inset shadows in light mode (dark form borders are not accent-derived)', () => {
    expect(light).toContain('inset 0 0 0 1px rgba(');
    expect(dark).not.toContain('inset 0 0 0 1px rgba(');
    // The focus gradient itself applies in both modes.
    for (const css of [light, dark]) {
      expect(css).toContain(
        'linear-gradient(to top, #1D4ED8, #1D4ED8 2px, transparent 2px, transparent 100%)'
      );
    }
  });

  it('guards disabled/off states so the blanket !important cannot recolor them', () => {
    for (const css of [light, dark]) {
      expect(css).toContain('.euiCheckbox__input:checked:not([disabled])');
      expect(css).toContain('.euiRadio__input:checked:not([disabled])');
      expect(css).toContain(
        ".euiSwitch--primary .euiSwitch__button[aria-checked=true]:not(:disabled) .euiSwitch__body"
      );
      expect(css).toContain(':not(.euiStepNumber--warning)');
    }
  });
});

describe('buildDefaultPatchCss', () => {
  it('pins the mode-correct default purple as the CSS var', () => {
    expect(buildDefaultPatchCss(false)).toContain(`--tlsoc-accent: ${DEFAULT_ACCENT_LIGHT}`);
    expect(buildDefaultPatchCss(true)).toContain(`--tlsoc-accent: ${DEFAULT_ACCENT_DARK}`);
  });

  it('recolors ONLY the teal-census surfaces + vars — nothing else', () => {
    for (const isDark of [false, true]) {
      const css = buildDefaultPatchCss(isDark);
      expect(css).toContain('.obs-nav-item:hover');
      expect(css).toContain('.obs-nav-child-item[data-active="true"]::before');
      expect(css).toContain('.sidecar-resizableButton:focus:not(:disabled)');
      expect(css).toContain('.variableQueryPanelEditor--focused');
      expect(css).toContain('.conApp__resizer:focus');
      expect(css).toContain('.osdSavedQueryListItem');
      expect(css).toContain('.visEditor__resizer:focus');
      expect(css).toContain('.osdUiAceKeyboardHint:focus');
      expect(css).toContain('.homSolutionPanel__header');
      // Nothing that is correctly purple in the compiled theme may be touched at default.
      expect(css).not.toContain('.euiButton');
      expect(css).not.toContain('@keyframes');
      expect(css).not.toContain('linear-gradient');
      // Exactly :root + the 19 teal-census rules — the patch stays minimal by construction.
      expect((css.match(/\{/g) || []).length).toBe(20);
    }
  });

  it('fixes the teal bug: the patch paints obs-nav with the TLSOC purple, never upstream teal', () => {
    expect(buildDefaultPatchCss(false)).toContain('color: #7E22CE !important;');
    expect(buildDefaultPatchCss(true)).toContain('color: #C266FF !important;');
    for (const isDark of [false, true]) {
      expect(buildDefaultPatchCss(isDark)).not.toMatch(/#07827E|#159D8D/i);
    }
  });
});
