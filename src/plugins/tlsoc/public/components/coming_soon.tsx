/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { i18n } from '@osd/i18n';
import {
  EuiPage,
  EuiPageBody,
  EuiPageContent,
  EuiEmptyPrompt,
  EuiText,
  EuiBadge,
  EuiSpacer,
} from '@elastic/eui';

export interface ComingSoonProps {
  /** Section name shown as the heading, e.g. "Overview", "Alerts". */
  title: string;
  /** Optional one-line description of what the section will offer. */
  description?: string;
  /** OUI icon type shown in the prompt. Defaults to the Security Operations mark. */
  iconType?: string;
}

/**
 * Shared, parameterized placeholder for TLSOC SOC sections that are not built yet.
 * Renders a centered, on-brand "Coming soon" page. It is reused for every unbuilt
 * section so the full SOC navigation reads as a complete product from day one
 * (decision D-007); each placeholder is swapped for the real app as that feature lands.
 */
export const ComingSoon: React.FC<ComingSoonProps> = ({
  title,
  description,
  iconType = 'wsSecurityAnalytics',
}) => {
  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        <EuiPageContent verticalPosition="center" horizontalPosition="center" paddingSize="l">
          <EuiEmptyPrompt
            iconType={iconType}
            title={<h1>{title}</h1>}
            body={
              <>
                <EuiBadge color="hollow">
                  {i18n.translate('tlsoc.comingSoon.badge', { defaultMessage: 'Coming soon' })}
                </EuiBadge>
                {description ? (
                  <>
                    <EuiSpacer size="m" />
                    <EuiText color="subdued">
                      <p>{description}</p>
                    </EuiText>
                  </>
                ) : null}
              </>
            }
          />
        </EuiPageContent>
      </EuiPageBody>
    </EuiPage>
  );
};
