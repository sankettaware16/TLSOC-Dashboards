/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * TLSOC universal accent palette — pure, isomorphic color math + CSS-string builders.
 *
 * The TLSOC theme is COMPILED: the purple accent is baked as literal hexes into the checked-in
 * `packages/osd-ui-shared-deps/tlsoc_themes/eui_theme_next_{light,dark}.tlsoc.css` bundles (light
 * #7E22CE, dark #C266FF). This module builds a runtime override stylesheet from ONE user-chosen
 * hex so the whole UI's accent can be recolored without touching any compiled artifact. The
 * selector inventory below is a hand-maintained mirror of every accent-colored rule in those
 * compiled bundles — if the theme is ever recompiled, re-run the hex census and update this list.
 *
 * Derivations were reverse-engineered from the compiled CSS so that feeding the default purple
 * back through them reproduces the shipped values:
 *  - fill hover/active shade  = HSL darken 5%          (light #7E22CE -> rgb(113,30,184))
 *  - filled press shadow      = rgba(HSL darken 10%, 0.28) (light -> rgba(99, 27, 162, 0.28);
 *                               verified against eui_theme_next_light.tlsoc.css:2471 and the
 *                               dark bundle's rgba(173.67, 51, 255, 0.28))
 *  - tinted hover/selected bg = light: mix(accent 10%, #FCFEFF) / dark: mix(accent 35%, #0A121A)
 *  - focus rings              = rgba(accent, 0.21) — baked into @keyframes (see below)
 *  - text on accent fill      = WCAG relative-luminance pick of ghost #FCFEFF vs ink #0A121A
 *
 * ── TEAL CENSUS (2026-07-27, grep '#07827E|#159D8D' + 'rgba(7, 130, 126|21, 157, 141' over
 *    src/{core,plugins/*}/target/public/*.js — plugin CSS is inlined into the optimizer JS
 *    bundles and compiled against UNPATCHED upstream OUI, so accent-semantic rules there ship
 *    upstream TEAL instead of TLSOC purple) ─────────────────────────────────────────────────
 *
 * PATCHED (surface reachable in the shipped TLSOC distro) — every selector lives in the shared
 * TEAL_CENSUS_RULES table below, so buildDefaultPatchCss (default purple) and buildAccentCss
 * (user accent) recolor exactly the same set and can never drift apart:
 *  - core:               .obs-nav-* SOC nav; .sidecar-resizableButton:focus (bg rgba(accent,.1),
 *                        ::before/::after bg accent)
 *  - dashboard:          .variableQueryPanelEditor--focused; .variableSelectorContainer:hover
 *  - discover:           table th .fa-sort-* sort icons (generic selector — also matches the
 *                        .agentTraces-table-container/.explore-table-container copies)
 *  - console:            .conApp__resizer:focus/.active
 *  - data:               .osdSavedQueryListItem; .osdSuggestionItem--operator __type (tint bg)
 *  - vis_default_editor: .visEditor__resizer:focus/.active
 *  - vis_type_timeseries (ships its own oui-prefixed copies): .ouiSaturation/.ouiHue__range
 *                        focus rings (vendor pseudos in separate rules), .ouiColorStops:focus,
 *                        .tvbEditorVisualization__draghandle
 *  - opensearch_ui_shared: .osdUiAceKeyboardHint:focus
 *  - home (enabled):     .homSolutionPanel__header
 *
 * NOT PATCHED (bundle disabled in the distro, or non-accent semantic) — documented so a future
 * re-enable knows to move these into TEAL_CENSUS_RULES:
 *  - explore (explore.enabled defaults false): .exploreQueryPanelEditor--focused,
 *    .explore-table-container sort icons, .axisSelectorContainer, .pqbQueryPreviewStrip,
 *    .pqbSuggestedBadge:hover/:focus, .metricsEmptyState__sampleTrigger:focus-visible,
 *    .monaco-editor .query-label-gutter::before
 *  - agent_traces (cascade-disabled: requiredPlugins includes explore):
 *    .agentTracesQueryPanelEditor--focused, .agentTracesFlyout__{timelineBar--selected,
 *    flyoutResizer,parentSpanLink,guideLine}, .agentTraces-table-container sort icons, monaco
 *    gutter; --osd-color-type-agent is NON-accent semantic (trace-node category color).
 *  - chat (chat.enabled defaults false): .chatInput:focus/--compressed gradients,
 *    .chat-suggestion-bubble-panel--custom, .slashCommandMenu__item
 */

export const ACCENT_SETTING_KEY = 'tlsoc:accentColor';

export const DEFAULT_ACCENT_LIGHT = '#7E22CE';
export const DEFAULT_ACCENT_DARK = '#C266FF';

/** The theme's "ghost" (lightest) shade — text on dark accent fills, light-mode tint base. */
export const ACCENT_FILL_TEXT_GHOST = '#FCFEFF';
/** The theme's "ink" (darkest) shade — text on light accent fills, dark-mode tint base. */
export const ACCENT_FILL_TEXT_INK = '#0A121A';

/** '' (= use the built-in purple) or a full 6-digit #RRGGBB hex. Nothing else is accepted. */
export function isValidAccentHex(value: unknown): value is string {
  return typeof value === 'string' && (value === '' || /^#[0-9a-fA-F]{6}$/.test(value));
}

interface Rgb {
  r: number;
  g: number;
  b: number;
}

function hexToRgb(hex: string): Rgb {
  return {
    r: parseInt(hex.slice(1, 3), 16),
    g: parseInt(hex.slice(3, 5), 16),
    b: parseInt(hex.slice(5, 7), 16),
  };
}

function rgbString({ r, g, b }: Rgb): string {
  return `rgb(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)})`;
}

/** rgba() string of the accent at the given alpha — the compiled theme's derived-alpha family. */
function alpha(hex: string, a: number): string {
  const { r, g, b } = hexToRgb(hex);
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

interface Hsl {
  h: number;
  s: number;
  l: number;
}

function rgbToHsl({ r, g, b }: Rgb): Hsl {
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const l = (max + min) / 2;
  let h = 0;
  let s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    if (max === rn) h = (gn - bn) / d + (gn < bn ? 6 : 0);
    else if (max === gn) h = (bn - rn) / d + 2;
    else h = (rn - gn) / d + 4;
    h *= 60;
  }
  return { h, s, l };
}

function hslToRgb({ h, s, l }: Hsl): Rgb {
  const hn = ((h % 360) + 360) % 360;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((hn / 60) % 2) - 1));
  const m = l - c / 2;
  let rgb: [number, number, number];
  if (hn < 60) rgb = [c, x, 0];
  else if (hn < 120) rgb = [x, c, 0];
  else if (hn < 180) rgb = [0, c, x];
  else if (hn < 240) rgb = [0, x, c];
  else if (hn < 300) rgb = [x, 0, c];
  else rgb = [c, 0, x];
  return { r: (rgb[0] + m) * 255, g: (rgb[1] + m) * 255, b: (rgb[2] + m) * 255 };
}

/** HSL darken — 5% reproduces the compiled fill-hover shade exactly (verified numerically). */
function darkenHsl(hex: string, amount: number): Rgb {
  const hsl = rgbToHsl(hexToRgb(hex));
  hsl.l = Math.max(0, hsl.l - amount);
  return hslToRgb(hsl);
}

/** Linear mix: `weight` of `fgHex` over `1 - weight` of `bgHex` (the compiled tint formula). */
function mix(fgHex: string, bgHex: string, weight: number): Rgb {
  const fg = hexToRgb(fgHex);
  const bg = hexToRgb(bgHex);
  return {
    r: fg.r * weight + bg.r * (1 - weight),
    g: fg.g * weight + bg.g * (1 - weight),
    b: fg.b * weight + bg.b * (1 - weight),
  };
}

/** WCAG 2.x relative luminance of a #RRGGBB hex (0 = black, 1 = white). */
export function relativeLuminance(hex: string): number {
  const { r, g, b } = hexToRgb(hex);
  const lin = (c: number) => {
    const cn = c / 255;
    return cn <= 0.03928 ? cn / 12.92 : Math.pow((cn + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrastRatio(l1: number, l2: number): number {
  const [hi, lo] = l1 >= l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * Text color for content sitting ON an accent fill: whichever of ghost/ink contrasts better.
 * Reproduces the compiled defaults: #7E22CE -> ghost (#FCFEFF), #C266FF -> ink (#0A121A).
 */
export function pickFillTextColor(hex: string): string {
  const l = relativeLuminance(hex);
  const vsGhost = contrastRatio(l, relativeLuminance(ACCENT_FILL_TEXT_GHOST));
  const vsInk = contrastRatio(l, relativeLuminance(ACCENT_FILL_TEXT_INK));
  return vsGhost >= vsInk ? ACCENT_FILL_TEXT_GHOST : ACCENT_FILL_TEXT_INK;
}

/**
 * The light theme's form-border color is itself accent-derived (OUI: shade(desaturate(
 * adjust-hue(primary, 22deg), 22.95%), 26%)). Approximation is fine here — it is only ever used
 * at alpha 0.07 in inset border shadows. The DARK theme's form border is white-based, NOT
 * accent-derived, so dark mode never overrides these shadows.
 */
function formBorderRgb(hex: string): Rgb {
  const hsl = rgbToHsl(hexToRgb(hex));
  hsl.h += 22;
  hsl.s = Math.max(0, hsl.s - 0.2295);
  const shaded = hslToRgb(hsl);
  return { r: shaded.r * 0.74, g: shaded.g * 0.74, b: shaded.b * 0.74 };
}

function rgbaOf({ r, g, b }: Rgb, a: number): string {
  return `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${a})`;
}

/** One rule with every declaration `!important` (needed to beat the compiled theme bundles). */
function rule(selector: string, decls: Array<[string, string]>): string {
  const body = decls.map(([prop, value]) => `  ${prop}: ${value} !important;`).join('\n');
  return `${selector} {\n${body}\n}`;
}

/** `!important` inside @keyframes bodies is INVALID CSS (the declaration would be dropped). */
function plainRule(selector: string, decls: Array<[string, string]>): string {
  const body = decls.map(([prop, value]) => `  ${prop}: ${value};`).join('\n');
  return `${selector} {\n${body}\n}`;
}

/**
 * The focus-ring trap: ring colors are BAKED into these keyframes, which 64 compiled rules
 * reference via `animation ... !important`. A box-shadow override cannot win against a running
 * animation — but a later-in-cascade @keyframes of the same name replaces the whole animation,
 * so re-declaring both (plus -webkit-) is the only working recolor.
 */
function focusRingKeyframes(hex: string): string {
  const a0 = alpha(hex, 0);
  const a21 = alpha(hex, 0.21);
  const frames = (from: string, to: string) =>
    `  0% {\n    box-shadow: 0 0 0 ${from} ${a0};\n  }\n  100% {\n    box-shadow: 0 0 0 ${to} ${a21};\n  }`;
  return [
    `@-webkit-keyframes focusRingAnimate {\n${frames('6px', '3px')}\n}`,
    `@keyframes focusRingAnimate {\n${frames('6px', '3px')}\n}`,
    `@-webkit-keyframes focusRingAnimateLarge {\n${frames('10px', '4px')}\n}`,
    `@keyframes focusRingAnimateLarge {\n${frames('10px', '4px')}\n}`,
  ].join('\n');
}

/**
 * The FULL accent override stylesheet for one accent hex. Covers every accent surface found in
 * the compiled theme bundles (see the census note in the header) plus the TLSOC SOC-nav rules
 * compiled into core (which come out upstream-TEAL today — the default patch fixes those too).
 */
export function buildAccentCss(hex: string, isDark: boolean): string {
  if (!isValidAccentHex(hex) || hex === '') {
    return '';
  }
  const A = hex;
  const hover = rgbString(darkenHsl(A, 0.05));
  const fillText = pickFillTextColor(A);
  const tint = rgbString(
    isDark ? mix(A, ACCENT_FILL_TEXT_INK, 0.35) : mix(A, ACCENT_FILL_TEXT_GHOST, 0.1)
  );
  const a005 = alpha(A, 0.05);
  const a010 = alpha(A, 0.1);
  const a0105 = alpha(A, 0.105);
  const a020 = alpha(A, 0.2);
  const a021 = alpha(A, 0.21);
  const a030 = alpha(A, 0.3);
  const a050 = alpha(A, 0.5);
  const gradient = `linear-gradient(to top, ${A}, ${A} 2px, transparent 2px, transparent 100%)`;
  const fillPressShadow = `inset 1px 2px 8px ${rgbaOf(darkenHsl(A, 0.1), 0.28)}`;
  const fb07 = rgbaOf(formBorderRgb(A), 0.07);
  const fb10 = rgbaOf(formBorderRgb(A), 0.1);
  // The two non-inset elevation shadows in the light theme's focused-control box-shadow are
  // neutral gray (not accent-derived) but box-shadow is a single property, so they ride along.
  const focusShadowRegular = `0 1px 1px -1px rgba(173, 180, 186, 0.14), 0 4px 4px -2px rgba(173, 180, 186, 0.14), inset 0 0 0 1px ${fb07}`;
  const focusShadowCompressed = `inset 0 0 0 1px ${fb07}`;

  const rules: string[] = [];

  // CSS vars for TLSOC React components (inline styles are unreachable by any stylesheet, so
  // components read var(--tlsoc-accent) instead of hardcoding euiThemeVars.euiColorPrimary).
  rules.push(
    rule(':root', [
      ['--tlsoc-accent', A],
      ['--tlsoc-accent-fill-text', fillText],
    ])
  );

  // Bare links. Deliberately NOT !important: the compiled `a { color }` is a specificity-(0,0,1)
  // rule that hundreds of later component rules legitimately override (danger buttons rendered
  // as <a>, breadcrumbs, ...). Our tag sits after the theme <link>s, so plain source order wins
  // the tie against the compiled rule while preserving every component-level override.
  rules.push(plainRule('a', [['color', A]]));
  rules.push(
    rule(
      '.euiLink.euiLink--primary, .euiText a:not([class]), .euiSuperDatePicker__prettyFormatLink, .euiNotificationEvent__title.euiLink, .euiNotificationEventMessages__accordionButton',
      [['color', A]]
    )
  );
  rules.push(
    rule('.euiLink:focus, .euiHeaderLogo:focus, .euiIcon:focus', [['background', tint]])
  );
  rules.push(
    rule('.euiLink.euiLink--primary:focus, .euiText a:not([class]):focus', [
      ['background-color', tint],
    ])
  );

  // Focus rings (the @keyframes trap — see focusRingKeyframes) + static ring rules.
  rules.push(focusRingKeyframes(A));
  // Vendor-prefixed slider pseudo-elements must stay in SEPARATE rules: one unknown vendor
  // pseudo invalidates an entire comma-joined selector list in other engines.
  for (const thumb of ['::-webkit-slider-thumb', '::-moz-range-thumb', '::-ms-thumb']) {
    rules.push(
      rule(`.euiHue__range:focus${thumb}`, [
        ['box-shadow', `0 0 0 3px ${a021}`],
        ['border-color', A],
      ])
    );
    rules.push(
      rule(`.euiRangeSlider:focus-visible${thumb}, .euiRangeSlider--hasFocus${thumb}`, [
        ['box-shadow', `0 0 0 3px ${a021}`],
      ])
    );
  }
  rules.push(
    rule('.euiSaturation:focus .euiSaturation__indicator', [
      ['box-shadow', `0 0 0 3px ${a021}`],
      ['border-color', A],
    ])
  );
  rules.push(
    rule(
      '.euiDataGridHeaderCell:focus, .euiDataGridHeaderCell:not(.euiDataGridHeaderCell--controlColumn):focus-within, .euiDataGridRowCell:focus',
      [['box-shadow', `0 0 0 2px ${a021}`]]
    )
  );
  rules.push(
    rule(
      '.euiButtonGroup--compressed .euiButtonGroupButton:not([class*=isDisabled]):focus, .euiButtonGroup--compressed .euiButtonGroupButton:not([class*=isDisabled]):focus-within, .euiColorStops:not(.euiColorStops-isDisabled):focus, .euiImage .euiImage__button:focus, .euiFormControlLayout--group .euiButtonIcon:focus-visible',
      [['outline', `2px solid ${a030}`]]
    )
  );

  // Primary button families.
  rules.push(rule('.euiButton--primary', [['color', A], ['border-color', A]]));
  rules.push(
    rule('.euiButton--primary.euiButton--fill', [
      ['background-color', A],
      ['border-color', A],
      ['color', fillText],
    ])
  );
  rules.push(
    rule(
      '.euiButton--primary.euiButton--fill:not([class*=isDisabled]):hover, .euiButton--primary.euiButton--fill:not([class*=isDisabled]):focus, .euiButton--primary.euiButton--fill:not([class*=isDisabled]):focus-within',
      [['background-color', hover], ['border-color', hover]]
    )
  );
  rules.push(
    rule(
      '.euiButton:not([class*=isDisabled]):hover, .euiButton:not([class*=isDisabled]):focus, .euiButton:not([class*=isDisabled]):focus-within',
      [['background-color', a010]]
    )
  );
  rules.push(
    rule('.euiButton--primary:not([class*=isDisabled]):active', [
      ['box-shadow', `inset 1px 2px 8px ${a0105}`],
    ])
  );
  // Filled press shadow — the compiled formula is rgba(HSL darken 10%, 0.28): feeding #7E22CE
  // through reproduces eui_theme_next_light.tlsoc.css:2471's rgba(99.225, 26.775, 162.225, 0.28)
  // and #C266FF the dark bundle's rgba(173.67, 51, 255, 0.28). More specific than the non-fill
  // :active rule above, so it wins the tie between our two !important rules.
  rules.push(
    rule('.euiButton--primary.euiButton--fill:not([class*=isDisabled]):active', [
      ['box-shadow', fillPressShadow],
    ])
  );
  rules.push(
    rule(
      '.euiButton.euiButton-isDisabled .euiButtonContent__spinner, .euiButtonEmpty:disabled .euiButtonContent__spinner, .euiButtonIcon.euiButtonIcon-isDisabled .euiButtonContent__spinner, .euiButtonGroupButton.euiButtonGroupButton-isDisabled .euiButtonContent__spinner',
      [['border-color', `${A} currentColor currentColor currentColor`]]
    )
  );
  rules.push(rule('.euiButtonEmpty--primary', [['color', A]]));
  rules.push(rule('.euiButtonEmpty--primary:focus', [['background-color', a010]]));
  rules.push(rule('.euiButtonIcon--primary', [['color', A], ['border-color', A]]));
  rules.push(
    rule('.euiButtonIcon--primary.euiButtonIcon--fill', [
      ['background-color', A],
      ['border-color', A],
      ['color', fillText],
    ])
  );
  rules.push(
    rule(
      '.euiButtonIcon--primary.euiButtonIcon--fill:not([class*=isDisabled]):hover, .euiButtonIcon--primary.euiButtonIcon--fill:not([class*=isDisabled]):focus, .euiButtonIcon--primary.euiButtonIcon--fill:not([class*=isDisabled]):focus-within',
      [['background-color', hover], ['border-color', hover]]
    )
  );
  rules.push(
    rule(
      '.euiButtonIcon--primary:not([class*=isDisabled]):hover, .euiButtonIcon--primary:not([class*=isDisabled]):focus, .euiButtonIcon--primary:not([class*=isDisabled]):focus-within',
      [['background-color', a010]]
    )
  );
  rules.push(
    rule('.euiButtonIcon--primary:not([class*=isDisabled]):active', [
      ['box-shadow', `inset 1px 2px 8px ${a0105}`],
    ])
  );
  rules.push(
    rule('.euiButtonIcon--primary.euiButtonIcon--fill:not([class*=isDisabled]):active', [
      ['box-shadow', fillPressShadow],
    ])
  );
  rules.push(
    rule(
      '.euiButtonGroupButton:not([class*=isDisabled]):hover, .euiButtonGroupButton:not([class*=isDisabled]):focus, .euiButtonGroupButton:not([class*=isDisabled]):focus-within',
      [['background-color', a010]]
    )
  );
  rules.push(
    rule('.euiButtonGroupButton.euiButtonGroupButton--primary:not([class*=isDisabled])', [
      ['color', A],
    ])
  );
  rules.push(
    rule(
      '.euiButtonGroupButton.euiButtonGroupButton--primary:not([class*=isDisabled]).euiButtonGroupButton-isSelected',
      [['background-color', A], ['border-color', A], ['color', fillText]]
    )
  );
  rules.push(
    rule(
      '.euiButtonGroupButton.euiButtonGroupButton--primary:not([class*=isDisabled]).euiButtonGroupButton-isSelected:hover, .euiButtonGroupButton.euiButtonGroupButton--primary:not([class*=isDisabled]).euiButtonGroupButton-isSelected:focus, .euiButtonGroupButton.euiButtonGroupButton--primary:not([class*=isDisabled]).euiButtonGroupButton-isSelected:focus-within',
      [['background-color', hover], ['border-color', hover]]
    )
  );
  rules.push(
    rule('.euiSplitButton .euiSplitButtonColor--primary', [['color', A], ['border-color', A]])
  );
  rules.push(
    rule('.euiSplitButton .euiSplitButtonColor--primary.euiSplitButtonColor--fill', [
      ['background-color', A],
      ['border-color', A],
      ['color', fillText],
    ])
  );
  rules.push(
    rule(
      '.euiSplitButton .euiSplitButtonColor--primary.euiSplitButtonColor--fill:not([class*=isDisabled]):hover, .euiSplitButton .euiSplitButtonColor--primary.euiSplitButtonColor--fill:not([class*=isDisabled]):focus, .euiSplitButton .euiSplitButtonColor--primary.euiSplitButtonColor--fill:not([class*=isDisabled]):focus-within',
      [['background-color', hover], ['border-color', hover]]
    )
  );
  rules.push(
    rule(
      '.euiSplitButton .euiSplitButtonColor--primary:not([class*=isDisabled]):hover, .euiSplitButton .euiSplitButtonColor--primary:not([class*=isDisabled]):focus, .euiSplitButton .euiSplitButtonColor--primary:not([class*=isDisabled]):focus-within',
      [['background-color', a010]]
    )
  );
  rules.push(
    rule('.euiSplitButton .euiSplitButtonHairline--primary:not([class*=isDisabled])', [
      ['border-right-color', a020],
    ])
  );
  rules.push(rule('.euiSplitButton__item:focus', [['background-color', tint]]));

  // Form control focus gradients (+ light-mode accent-derived inset border shadows; the dark
  // theme's form border is white-based, so dark only swaps the gradient).
  //
  // EVERY selector carries an invalid-state :not() guard: the compiled theme paints invalid
  // controls with a danger-red (#BD271E) underline gradient via `:invalid` (native constraint
  // state on euiFieldText/Number/Password/Search, euiSelect, euiSuperSelectControl, euiTextArea)
  // or a class (`.euiFieldText-isInvalid`, `.euiSuperSelectControl-isInvalid`,
  // `.euiComboBox-isInvalid`, `.euiFilePicker-isInvalid`, `.euiDatePopoverButton-isInvalid`,
  // `.euiMarkdownEditorDropZone--hasError/--isDraggingError` — exact names read from the
  // compiled bundles). Without the guards our !important accent gradient would mask the danger
  // underline on a focused-but-invalid field. Class guards sit on the element that carries the
  // class in the DOM (combo box root, file picker root, markdown drop zone).
  const regularFocus =
    '.euiFieldText:focus:not(:invalid):not(.euiFieldText-isInvalid), .euiFieldNumber:focus:not(:invalid), .euiFieldPassword:focus:not(:invalid), .euiFieldSearch:focus:not(:invalid), .euiSelect:focus:not(:invalid), .euiSuperSelectControl:focus:not(:invalid):not(.euiSuperSelectControl-isInvalid), .euiTextArea:focus:not(:invalid), .euiSuperSelectControl.euiSuperSelect--isOpen__button:not(:invalid):not(.euiSuperSelectControl-isInvalid), .euiComboBox.euiComboBox-isOpen:not(.euiComboBox-isInvalid) .euiComboBox__inputWrap, .euiFilePicker__showDrop:not(.euiFilePicker-isInvalid) .euiFilePicker__prompt, .euiFilePicker:not(.euiFilePicker-isInvalid) .euiFilePicker__input:focus + .euiFilePicker__prompt';
  const compressedFocus =
    '.euiFieldText--compressed:focus:not(:invalid):not(.euiFieldText-isInvalid), .euiFieldNumber--compressed:focus:not(:invalid), .euiFieldPassword--compressed:focus:not(:invalid), .euiFieldSearch--compressed:focus:not(:invalid), .euiSelect--compressed:focus:not(:invalid), .euiSuperSelectControl--compressed:focus:not(:invalid):not(.euiSuperSelectControl-isInvalid), .euiTextArea--compressed:focus:not(:invalid), .euiComboBox.euiComboBox-isOpen:not(.euiComboBox-isInvalid) .euiComboBox__inputWrap--compressed, .euiFilePicker--compressed:not(.euiFilePicker-isInvalid) .euiFilePicker__showDrop .euiFilePicker__prompt, .euiFilePicker--compressed:not(.euiFilePicker-isInvalid) .euiFilePicker__input:focus + .euiFilePicker__prompt';
  rules.push(
    rule(
      regularFocus,
      isDark
        ? [['background-image', gradient]]
        : [['background-image', gradient], ['box-shadow', focusShadowRegular]]
    )
  );
  rules.push(
    rule(
      compressedFocus,
      isDark
        ? [['background-image', gradient]]
        : [['background-image', gradient], ['box-shadow', focusShadowCompressed]]
    )
  );
  // The markdown textarea always sits inside the drop zone (markdown_editor.js renders the
  // TextArea as a DropZone child), so its error classes are guarded at the ancestor. The
  // isDragging accent paint also yields to --hasError/--isDraggingError, whose compiled rules
  // paint the danger drop state.
  const mdDropZoneValid =
    '.euiMarkdownEditorDropZone:not(.euiMarkdownEditorDropZone--hasError):not(.euiMarkdownEditorDropZone--isDraggingError)';
  const mdDragging =
    '.euiMarkdownEditorDropZone--isDragging:not(.euiMarkdownEditorDropZone--hasError):not(.euiMarkdownEditorDropZone--isDraggingError)';
  rules.push(
    rule(
      `.euiDatePopoverButton:focus:not(.euiDatePopoverButton-isInvalid), .euiDatePopoverButton-isSelected:not(.euiDatePopoverButton-isInvalid), ${mdDropZoneValid} .euiMarkdownEditorTextArea:focus, .euiMarkdownEditor:focus-within ${mdDropZoneValid} .euiMarkdownEditorTextArea`,
      [['background-image', gradient]]
    )
  );
  rules.push(
    rule(
      `${mdDragging} .euiMarkdownEditorFooter, ${mdDragging} .euiMarkdownEditorTextArea, ${mdDragging} .euiMarkdownEditorTextArea:focus, ${mdDragging} .euiMarkdownEditor:focus-within .euiMarkdownEditorTextArea`,
      [['background-color', a010]]
    )
  );
  rules.push(
    rule(
      `${mdDragging} .euiMarkdownEditorTextArea, ${mdDragging} .euiMarkdownEditorTextArea:focus`,
      [['background-image', gradient]]
    )
  );
  if (!isDark) {
    rules.push(rule('.euiButtonGroup--compressed .euiButtonGroup__buttons', [
      ['border-color', fb10],
    ]));
  }
  rules.push(rule('.euiFormLabel.euiFormLabel-isFocused', [['color', A]]));

  // Checked controls. `:not([disabled])` guards keep the compiled disabled-gray rules winning
  // (a blanket !important here would otherwise recolor disabled checked controls).
  rules.push(
    rule(
      '.euiCheckbox .euiCheckbox__input:checked:not([disabled]) + .euiCheckbox__square, .euiCheckbox .euiCheckbox__input:indeterminate:not([disabled]) + .euiCheckbox__square',
      [['border-color', A], ['background-color', A]]
    )
  );
  rules.push(
    rule(
      '.euiCheckbox .euiCheckbox__input:focus:not([disabled]) + .euiCheckbox__square, .euiCheckbox .euiCheckbox__input:active:not(:disabled) + .euiCheckbox__square',
      [['border-color', A]]
    )
  );
  rules.push(
    rule('.euiRadio .euiRadio__input:checked:not([disabled]) + .euiRadio__circle', [
      ['border-color', A],
      ['background-color', A],
    ])
  );
  rules.push(
    rule(
      '.euiRadio .euiRadio__input:focus:not([disabled]) + .euiRadio__circle, .euiRadio .euiRadio__input:active:not(:disabled) + .euiRadio__circle',
      [['border-color', A]]
    )
  );
  // The [aria-checked=true]:not(:disabled) guard keeps OFF and disabled switch bodies gray.
  rules.push(
    rule(
      '.euiSwitch--primary .euiSwitch__button[aria-checked=true]:not(:disabled) .euiSwitch__body',
      [['background-color', A]]
    )
  );
  rules.push(
    rule('.euiSwitch .euiSwitch__button:focus .euiSwitch__track', [['border-color', A]])
  );
  rules.push(
    rule(
      '.euiSwitch.euiSwitch--compressed .euiSwitch__button[aria-checked=true] .euiSwitch__thumb, .euiSwitch.euiSwitch--mini .euiSwitch__button[aria-checked=true] .euiSwitch__thumb',
      [['border-color', A]]
    )
  );
  rules.push(rule('.euiSwitch--primary.euiSwitch--base', [['border-color', A], ['color', A]]));
  rules.push(
    rule(
      '.euiSwitch--primary.euiSwitch--base:not([class*=isDisabled]):hover, .euiSwitch--primary.euiSwitch--base:not([class*=isDisabled]):focus, .euiSwitch--primary.euiSwitch--base:not([class*=isDisabled]):focus-within',
      [['background-color', a010]]
    )
  );
  rules.push(
    rule('.euiSwitch--primary.euiSwitch--base:not([class*=isDisabled]):active', [
      ['box-shadow', `inset 1px 2px 8px ${a0105}`],
    ])
  );

  // Selection & navigation.
  rules.push(rule('.euiTab.euiTab-isSelected', [['color', A]]));
  rules.push(rule('.euiTab.euiTab-isSelected::after', [['background-color', A]]));
  rules.push(
    rule('.euiTab:focus, .euiTabs--condensed .euiTab:focus', [['background-color', tint]])
  );
  rules.push(rule('.euiSideNavItemButton.euiSideNavItemButton-isSelected', [['color', A]]));
  rules.push(rule('.euiPaginationButton-isActive.euiPaginationButton-isActive', [['color', A]]));
  rules.push(
    rule('.euiControlBar__tab.euiControlBar__tab--active', [
      ['box-shadow', `inset 0 4px 0 ${A}`],
      ['color', A],
    ])
  );
  rules.push(
    rule(
      '.euiTableHeaderButton:hover .euiTableCellContent__text, .euiTableHeaderButton:focus .euiTableCellContent__text',
      [['color', A]]
    )
  );
  rules.push(
    rule(
      '.euiTableHeaderButton:hover .euiTableSortIcon, .euiTableHeaderButton:focus .euiTableSortIcon',
      [['fill', A]]
    )
  );

  // Tinted hover/selected/focus backgrounds.
  rules.push(
    rule('.euiComboBoxOption.euiComboBoxOption-isFocused', [
      ['color', A],
      ['background-color', tint],
    ])
  );
  rules.push(
    rule('.euiFilterSelectItem:focus, .euiFilterSelectItem-isFocused', [
      ['color', A],
      ['background-color', tint],
    ])
  );
  rules.push(
    rule(
      '.euiSelectableListItem-isFocused:not([aria-disabled=true]), .euiSelectableListItem:hover:not([aria-disabled=true])',
      [['color', A], ['background-color', tint]]
    )
  );
  rules.push(
    rule(
      '.euiContextMenuItem:focus, .euiSuperSelect__item:focus, .euiDataGridColumnSorting__field:focus, .euiToast__closeButton:focus',
      [['background-color', tint]]
    )
  );
  rules.push(
    rule(
      '.euiCommentEvent--regular.euiCommentEvent--regular--primary, .euiDroppable--withPanel.euiDroppable--withPanel--primary, .euiPanel.euiPanel--primary, .euiCardSelect--primary:enabled',
      [['background-color', tint]]
    )
  );
  rules.push(
    rule('.euiFacetButton:focus', [
      ['background-color', tint],
      ['box-shadow', `-4px 0 ${tint}, 4px 0 ${tint}`],
    ])
  );
  rules.push(
    rule(
      '.euiTableRow.euiTableRow-isSelected:hover, .euiTableRow.euiTableRow-isSelected:hover + .euiTableRow.euiTableRow-isExpandedRow .euiTableRowCell, .euiTable.euiTable--responsive .euiTableRow.euiTableRow--primary',
      [['background-color', tint]]
    )
  );
  rules.push(rule('.euiTableRow.euiTableRow-isClickable:hover', [['background-color', a005]]));
  rules.push(rule('.euiTableRow.euiTableRow-isClickable:focus', [['background-color', a010]]));

  // Progress & loading.
  rules.push(
    rule('.euiProgress--primary.euiProgress--native::-webkit-progress-value', [
      ['background-color', A],
    ])
  );
  rules.push(
    rule('.euiProgress--primary.euiProgress--native::-moz-progress-bar', [
      ['background-color', A],
    ])
  );
  rules.push(
    rule('.euiProgress--primary.euiProgress--indeterminate:before', [['background-color', A]])
  );
  rules.push(rule('.euiProgress__data--primary .euiProgress__valueText', [['color', A]]));
  rules.push(rule('.euiBasicTable-loading tbody:before', [['background-color', A]]));
  // Only the spinner's top edge is accent; the other three edges are per-mode grays.
  rules.push(rule('.euiLoadingSpinner', [['border-top-color', A]]));

  // Callout / toast / card / steps / expression / stat / misc.
  rules.push(rule('.euiCallOut--primary', [['border-color', A], ['background-color', tint]]));
  rules.push(
    rule(
      '.euiCallOut--primary .euiCallOutHeader__icon, .euiCallOut--primary .euiCallOut__closeIcon',
      [['fill', A]]
    )
  );
  rules.push(rule('.euiCallOut--primary .euiCallOutHeader__title', [['color', A]]));
  rules.push(rule('.euiToast--primary', [['border-top', `2px solid ${A}`]]));
  rules.push(rule('.euiToast__closeButton:focus svg', [['fill', A]]));
  rules.push(
    rule('.euiCard--isSelectable--primary.euiCard-isSelected:not(.euiCard-isDisabled)', [
      ['border-color', A],
    ])
  );
  rules.push(
    rule('.euiCheckableCard:not(.euiCheckableCard-isDisabled).euiCheckableCard-isChecked', [
      ['border-color', A],
    ])
  );
  // Status/size variants keep their own (warning/danger/disabled/incomplete/loading/hollow)
  // backgrounds — a blanket !important would break them, hence the :not() guards.
  rules.push(
    rule(
      '.euiStepNumber:not(.euiStepNumber--warning):not(.euiStepNumber--danger):not(.euiStepNumber--disabled):not(.euiStepNumber--incomplete):not(.euiStepNumber--loading):not(.euiStepNumber-isHollow)',
      [['background-color', A], ['color', fillText]]
    )
  );
  rules.push(rule('.euiStepNumber.euiStepNumber-isHollow', [['border-color', A]]));
  rules.push(
    rule('.euiStepHorizontal-isComplete::before, .euiStepHorizontal-isComplete::after', [
      ['background-color', A],
    ])
  );
  rules.push(rule('.euiStepHorizontal-isSelected::before', [['background-color', A]]));
  rules.push(rule('.euiExpression--primary:focus', [['background-color', a010]]));
  rules.push(
    rule('.euiExpression--primary.euiExpression-isActive', [
      ['border-bottom-color', A],
      ['border-color', A],
    ])
  );
  rules.push(rule('.euiExpression--primary .euiExpression__description', [['color', A]]));
  rules.push(rule('.euiStat .euiStat__title--primary', [['color', A]]));
  rules.push(
    rule(
      '.euiListGroupItem--primary .euiListGroupItem__text:not(:disabled), .euiListGroupItem--primary .euiListGroupItem__button:not(:disabled)',
      [['color', A]]
    )
  );
  rules.push(rule('.euiIcon--primary', [['color', A]]));
  rules.push(rule('.euiDataGridColumnResizer:after', [['background-color', A]]));
  rules.push(rule('.euiCodeEditorKeyboardHint:focus', [['border-color', A]]));
  rules.push(rule('.euiResizableButton:focus:not(:disabled)', [['background-color', a010]]));
  rules.push(
    rule('.euiResizableButton:focus:not(:disabled):before, .euiResizableButton:focus:not(:disabled):after', [
      ['background-color', A],
    ])
  );
  rules.push(
    rule('.euiAccordion__button:focus .euiAccordion__iconWrapper, .euiAccordion__iconButton:focus', [
      ['color', A],
    ])
  );

  // Range sliders (vendor pseudos in separate rules — see the note above).
  rules.push(rule('.euiRangeHighlight__progress--hasFocus', [['background-color', A]]));
  rules.push(rule('.euiRangeLevel--primary', [['background-color', a030]]));
  for (const track of [
    '::-webkit-slider-runnable-track',
    '::-moz-range-track',
    '::-ms-fill-lower',
    '::-ms-fill-upper',
  ]) {
    rules.push(
      rule(`.euiRangeSlider:focus-visible${track}, .euiRangeSlider--hasFocus${track}`, [
        ['background-color', A],
        ['border-color', A],
      ])
    );
  }
  rules.push(
    rule(
      '.euiRangeSlider:focus-visible ~ .euiRangeHighlight .euiRangeHighlight__progress, .euiRangeSlider--hasFocus ~ .euiRangeHighlight .euiRangeHighlight__progress',
      [['background-color', A]]
    )
  );
  rules.push(rule('.euiRangeThumb:focus', [['border-color', A]]));
  rules.push(
    rule('.euiRangeTick:enabled:hover, .euiRangeTick:focus, .euiRangeTick--selected', [
      ['color', A],
    ])
  );

  // react-datepicker.
  rules.push(
    rule(
      '.react-datepicker__navigation--previous:focus, .react-datepicker__navigation--next:focus',
      [['background-color', tint], ['box-shadow', `0 0 0 2px ${tint}`]]
    )
  );
  rules.push(
    rule(
      '.react-datepicker__time-container .react-datepicker__time .react-datepicker__time-box ul.react-datepicker__time-list li.react-datepicker__time-list-item--selected, .react-datepicker__time-container .react-datepicker__time .react-datepicker__time-box ul.react-datepicker__time-list li.react-datepicker__time-list-item--selected:hover',
      [['background-color', A], ['color', fillText]]
    )
  );
  rules.push(rule('.react-datepicker__day--today', [['color', A]]));
  rules.push(rule('.react-datepicker__day--in-range', [['background-color', a010]]));
  rules.push(
    rule('.react-datepicker__day--selected, .react-datepicker__day--in-selecting-range', [
      ['background-color', A],
      ['border-color', A],
      ['color', fillText],
    ])
  );
  rules.push(
    rule(
      '.react-datepicker__day--selected:hover, .react-datepicker__day--in-selecting-range:hover',
      [['background-color', hover]]
    )
  );
  rules.push(rule('.react-datepicker__day--keyboard-selected', [['border-color', A]]));
  rules.push(
    rule('.react-datepicker__day--keyboard-selected:hover', [
      ['background-color', hover],
      ['color', fillText],
    ])
  );
  rules.push(
    rule(
      '.react-datepicker__day--in-selecting-range:not(.react-datepicker__day--in-range)',
      [['background-color', a050]]
    )
  );
  rules.push(
    rule(
      '.react-datepicker__year-read-view:hover, .react-datepicker__month-read-view:hover, .react-datepicker__month-year-read-view:hover',
      [['color', A]]
    )
  );
  rules.push(
    rule(
      '.react-datepicker__year-option--preselected, .react-datepicker__month-option--preselected, .react-datepicker__time-container--focus, .react-datepicker__month--accessible:focus, .react-datepicker__navigation:focus',
      [['background', tint]]
    )
  );
  rules.push(
    rule(
      '.react-datepicker__year-option--selected_year, .react-datepicker__month-option--selected_month',
      [['background', A], ['color', fillText]]
    )
  );
  rules.push(
    rule(
      '.react-datepicker__month--accessible:focus .react-datepicker__day--in-range:not(.react-datepicker__day--selected)',
      [['border-top-color', tint], ['border-bottom-color', tint]]
    )
  );

  // The teal census: every accent-semantic surface the optimizer compiled upstream-TEAL into a
  // reachable bundle (SOC nav, sidecar, dashboard, discover, console, data, vis editors, ...).
  rules.push(buildTealCensusCss(A, isDark));

  return rules.join('\n');
}

/** The derived shades a teal-census rule may need. Computed once per build, mode-aware. */
interface AccentShades {
  accent: string;
  tint: string;
  a010: string;
  ring3: string;
  outline2: string;
}

/**
 * THE SHARED SELECTOR TABLE for the teal census (see the header docblock). Every rule here is
 * an accent-semantic surface that the optimizer compiled upstream-TEAL into a bundle that IS
 * reachable in the shipped TLSOC distro. Both builders emit this exact table — the default
 * patch with the default purple (fixing the pre-existing teal-at-default bug), the accent
 * override with the user's hex — so the two can never drift apart.
 *
 * Vendor-prefixed pseudo selectors stay in SEPARATE rows (one unknown vendor pseudo invalidates
 * an entire comma-joined selector list in other engines).
 */
const TEAL_CENSUS_RULES: ReadonlyArray<{
  selector: string;
  decls: ReadonlyArray<readonly [string, (s: AccentShades) => string]>;
}> = [
  // core — TLSOC SOC nav (compiled into core.entry.js from collapsible_nav_group_enabled.scss).
  {
    selector: '.obs-nav-item:hover, .obs-nav-child-item:hover',
    decls: [['color', (s) => s.accent]],
  },
  {
    selector:
      '.obs-nav-item[data-active="true"]::before, .obs-nav-child-item[data-active="true"]::before',
    decls: [['background-color', (s) => s.accent]],
  },
  // core — sidecar resizer (overlays/sidecar/components/resizable_button.scss).
  {
    selector: '.sidecar-resizableButton:focus:not(:disabled)',
    decls: [['background-color', (s) => s.a010]],
  },
  {
    selector:
      '.sidecar-resizableButton:focus:not(:disabled)::before, .sidecar-resizableButton:focus:not(:disabled)::after',
    decls: [['background-color', (s) => s.accent]],
  },
  // dashboard.
  {
    selector: '.variableQueryPanelEditor--focused',
    decls: [['border-bottom-color', (s) => s.accent]],
  },
  { selector: '.variableSelectorContainer:hover', decls: [['border-color', (s) => s.accent]] },
  // discover doc-table sort icons. The selector is deliberately container-generic, exactly like
  // the compiled rule, so it also covers the prefixed copies in other bundles.
  {
    selector:
      'table th button.fa-sort-asc, table th button.fa-sort-down, table th i.fa-sort-asc, table th i.fa-sort-down, table th button.fa-sort-desc, table th button.fa-sort-up, table th i.fa-sort-desc, table th i.fa-sort-up',
    decls: [['color', (s) => s.accent]],
  },
  // console.
  {
    selector: '.conApp__resizer:focus, .conApp__resizer.active',
    decls: [['background-color', (s) => s.accent]],
  },
  // data.
  { selector: '.osdSavedQueryListItem', decls: [['color', (s) => s.accent]] },
  {
    selector: '.osdSuggestionItem.osdSuggestionItem--operator .osdSuggestionItem__type',
    decls: [
      ['background-color', (s) => s.tint],
      ['color', (s) => s.accent],
    ],
  },
  // vis_default_editor.
  {
    selector: '.visEditor__resizer:focus, .visEditor__resizer.active',
    decls: [['background-color', (s) => s.accent]],
  },
  // vis_type_timeseries — ships its own oui-prefixed component copies.
  {
    selector: '.ouiSaturation:focus .ouiSaturation__indicator',
    decls: [
      ['box-shadow', (s) => s.ring3],
      ['border-color', (s) => s.accent],
    ],
  },
  {
    selector: '.ouiHue__range:focus::-webkit-slider-thumb',
    decls: [
      ['box-shadow', (s) => s.ring3],
      ['border-color', (s) => s.accent],
    ],
  },
  {
    selector: '.ouiHue__range:focus::-moz-range-thumb',
    decls: [
      ['box-shadow', (s) => s.ring3],
      ['border-color', (s) => s.accent],
    ],
  },
  {
    selector: '.ouiHue__range:focus::-ms-thumb',
    decls: [
      ['box-shadow', (s) => s.ring3],
      ['border-color', (s) => s.accent],
    ],
  },
  {
    selector: '.ouiColorStops:not(.ouiColorStops-isDisabled):focus',
    decls: [['outline', (s) => s.outline2]],
  },
  {
    selector:
      '.tvbEditorVisualization__draghandle:focus, .tvbEditorVisualization__draghandle.active',
    decls: [['background-color', (s) => s.accent]],
  },
  // opensearch_ui_shared (Ace editor keyboard hint, used by console/dev tools).
  { selector: '.osdUiAceKeyboardHint:focus', decls: [['border-color', (s) => s.accent]] },
  // home (enabled in the distro; legacy solution panel header is an accent fill).
  { selector: '.homSolutionPanel__header', decls: [['background-color', (s) => s.accent]] },
];

/** Emits the census table for one accent — the single source both builders share. */
function buildTealCensusCss(accent: string, isDark: boolean): string {
  const shades: AccentShades = {
    accent,
    tint: rgbString(
      isDark ? mix(accent, ACCENT_FILL_TEXT_INK, 0.35) : mix(accent, ACCENT_FILL_TEXT_GHOST, 0.1)
    ),
    a010: alpha(accent, 0.1),
    ring3: `0 0 0 3px ${alpha(accent, 0.3)}`,
    outline2: `2px solid ${alpha(accent, 0.3)}`,
  };
  return TEAL_CENSUS_RULES.map(({ selector, decls }) =>
    rule(
      selector,
      decls.map(([prop, resolve]) => [prop, resolve(shades)] as [string, string])
    )
  ).join('\n');
}

/**
 * The MINIMAL always-on patch applied even when no custom accent is set. It (a) publishes the
 * default purple as CSS vars for TLSOC components, and (b) recolors every TEAL_CENSUS_RULES
 * surface, which the @osd/optimizer compiles against UNPATCHED upstream OUI and therefore ships
 * teal (#07827E/#159D8D) instead of TLSOC purple. It deliberately touches nothing else, so the
 * default look stays exactly the shipped compiled theme.
 */
export function buildDefaultPatchCss(isDark: boolean): string {
  const accent = isDark ? DEFAULT_ACCENT_DARK : DEFAULT_ACCENT_LIGHT;
  return [
    rule(':root', [
      ['--tlsoc-accent', accent],
      ['--tlsoc-accent-fill-text', pickFillTextColor(accent)],
    ]),
    buildTealCensusCss(accent, isDark),
  ].join('\n');
}
