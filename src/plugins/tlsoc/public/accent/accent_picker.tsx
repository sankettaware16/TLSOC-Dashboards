/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiColorPicker,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPopover,
  EuiPopoverTitle,
  EuiSpacer,
  EuiText,
  EuiToolTip,
} from '@elastic/eui';
import { i18n } from '@osd/i18n';
import { CoreStart } from 'opensearch-dashboards/public';
import {
  ACCENT_SETTING_KEY,
  DEFAULT_ACCENT_DARK,
  DEFAULT_ACCENT_LIGHT,
  isValidAccentHex,
  pickFillTextColor,
} from '../../common/accent/palette';

/** Preset swatches after the shipped purple (which is prepended per light/dark mode). */
const PRESET_SWATCHES = [
  '#1D4ED8', // blue
  '#0F766E', // teal
  '#15803D', // green
  '#B45309', // amber
  '#B91C1C', // red
  '#BE185D', // pink
  '#334155', // slate
];

function isDarkMode(): boolean {
  const tag = (window as { __osdThemeTag__?: string }).__osdThemeTag__;
  return typeof tag === 'string' && tag.endsWith('dark');
}

/**
 * TLSOC header control: pick ONE color, Apply, and the whole UI's accent recolors instantly
 * (the live uiSettings subscription in accent/apply.ts does the restyling). "Reset to default"
 * saves '' — the compiled purple returns immediately.
 */
export function AccentPickerNavControl({ core }: { core: CoreStart }) {
  const [isOpen, setIsOpen] = useState(false);
  const [color, setColor] = useState<string>(() => {
    try {
      return core.uiSettings.get<string>(ACCENT_SETTING_KEY, '') || '';
    } catch (err) {
      return '';
    }
  });
  const [isSaving, setIsSaving] = useState(false);

  const currentDefault = isDarkMode() ? DEFAULT_ACCENT_DARK : DEFAULT_ACCENT_LIGHT;
  const swatches = [currentDefault, ...PRESET_SWATCHES];
  const isValid = isValidAccentHex(color) && color !== '';
  const previewHex = isValid ? color : currentDefault;

  const save = async (value: string) => {
    setIsSaving(true);
    try {
      const ok = await core.uiSettings.set(ACCENT_SETTING_KEY, value);
      if (!ok) {
        throw new Error('the settings service rejected the change');
      }
      core.notifications.toasts.addSuccess(
        value === ''
          ? i18n.translate('tlsoc.accent.resetToast', {
              defaultMessage: 'Theme color reset to the default purple',
            })
          : i18n.translate('tlsoc.accent.appliedToast', {
              defaultMessage: 'Theme color applied',
            })
      );
      setIsOpen(false);
      if (value === '') {
        setColor('');
      }
    } catch (err) {
      // Most common cause: the analyst lacks advanced-settings save rights (HTTP 403).
      core.notifications.toasts.addDanger({
        title: i18n.translate('tlsoc.accent.saveFailedTitle', {
          defaultMessage: 'Could not save the theme color',
        }),
        text: i18n.translate('tlsoc.accent.saveFailedText', {
          defaultMessage:
            'Saving the theme color needs permission to change advanced settings. Ask a TLSOC administrator to change it, or to grant you that permission.',
        }),
      });
    } finally {
      setIsSaving(false);
    }
  };

  const button = (
    <EuiToolTip
      content={i18n.translate('tlsoc.accent.buttonTooltip', { defaultMessage: 'Theme color' })}
    >
      <EuiButtonIcon
        aria-label={i18n.translate('tlsoc.accent.buttonAriaLabel', {
          defaultMessage: 'Change theme color',
        })}
        iconType="brush"
        color="text"
        onClick={() => setIsOpen((open) => !open)}
      />
    </EuiToolTip>
  );

  return (
    <EuiPopover
      id="tlsocAccentPickerPopover"
      button={button}
      isOpen={isOpen}
      closePopover={() => setIsOpen(false)}
      anchorPosition="downRight"
      panelPaddingSize="m"
    >
      <EuiPopoverTitle>
        {i18n.translate('tlsoc.accent.popoverTitle', { defaultMessage: 'Theme color' })}
      </EuiPopoverTitle>
      <div style={{ width: 280 }}>
        <EuiText size="xs" color="subdued">
          <p>
            {i18n.translate('tlsoc.accent.popoverHelp', {
              defaultMessage:
                'One color re-themes the whole TLSOC UI. Hover, focus, and background shades are derived automatically.',
            })}
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiColorPicker
          onChange={(text: string) => setColor(text)}
          color={isValid ? color : ''}
          swatches={swatches}
          format="hex"
          isInvalid={color !== '' && !isValidAccentHex(color)}
          secondaryInputDisplay="top"
          placeholder={i18n.translate('tlsoc.accent.placeholder', {
            defaultMessage: 'Default purple',
          })}
        />
        <EuiSpacer size="s" />
        {/* Live preview of the derived fill: chosen accent + auto-picked readable text. */}
        <div
          data-test-subj="tlsocAccentPreview"
          style={{
            backgroundColor: previewHex,
            color: pickFillTextColor(previewHex),
            borderRadius: 4,
            padding: '6px 10px',
            textAlign: 'center',
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          {isValid
            ? i18n.translate('tlsoc.accent.previewCustom', {
                defaultMessage: 'Preview — {hex}',
                values: { hex: color.toUpperCase() },
              })
            : i18n.translate('tlsoc.accent.previewDefault', {
                defaultMessage: 'Default purple',
              })}
        </div>
        <EuiSpacer size="m" />
        <EuiFlexGroup gutterSize="s" responsive={false} justifyContent="spaceBetween">
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              size="s"
              flush="left"
              isDisabled={isSaving}
              onClick={() => save('')}
              data-test-subj="tlsocAccentReset"
            >
              {i18n.translate('tlsoc.accent.resetButton', {
                defaultMessage: 'Reset to default',
              })}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton
              size="s"
              fill
              isDisabled={!isValid || isSaving}
              isLoading={isSaving}
              onClick={() => save(color)}
              data-test-subj="tlsocAccentApply"
            >
              {i18n.translate('tlsoc.accent.applyButton', { defaultMessage: 'Apply' })}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </div>
    </EuiPopover>
  );
}
