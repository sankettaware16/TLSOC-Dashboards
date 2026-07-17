/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useMemo } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCodeBlock,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiHorizontalRule,
  EuiLink,
  EuiLoadingSpinner,
  EuiMarkdownFormat,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import {
  TlsocAlert,
  buildBucketContext,
  buildReason,
  flattenObject,
  getPath,
  substituteFieldPlaceholders,
} from '../../common/alerts';
import { sevColor, stateColor, riskScoreColor } from './format';
import { useRelatedDocs } from './use_related_docs';

interface Props {
  core: CoreStart;
  alert: TlsocAlert;
  onClose: () => void;
  onAcknowledge: () => void;
  canInvestigate: boolean;
  onInvestigate: () => void;
  onCreateCase: () => void;
}

/** Highlighted-fields default set (WS-1 design §4.6) — additive with rule.investigationFields. */
const DEFAULT_HIGHLIGHT_FIELDS = [
  'host.name',
  'user.name',
  'source.ip',
  'source.port',
  'destination.ip',
  'event.action',
  'event.outcome',
  'event.module',
];

/** Cap on the flattened event-details table (avoid dumping a huge doc into the flyout). */
const MAX_EVENT_DETAIL_ROWS = 40;

interface HighlightRow {
  field: string;
  value: string;
}

/** Doc-level: the default set ∪ rule.investigationFields, values via the dot-path getter, hiding
 *  missing values. Bucket-level: rule.groupBy zipped positionally with alert.bucketKeys. */
function buildHighlightRows(alert: TlsocAlert, doc?: Record<string, unknown>): HighlightRow[] {
  if (alert.bucketKeys && alert.bucketKeys.length > 0) {
    const groupBy = alert.rule?.groupBy ?? [];
    return alert.bucketKeys
      .map((value, i) => ({ field: groupBy[i] ?? `group key ${i + 1}`, value }))
      .filter((r) => r.value !== undefined && r.value !== null && r.value !== '');
  }
  if (!doc) return [];
  const fields = Array.from(
    new Set([...DEFAULT_HIGHLIGHT_FIELDS, ...(alert.rule?.investigationFields ?? [])])
  );
  return fields
    .map((field) => ({ field, value: getPath(doc, field) }))
    .filter((r) => r.value !== undefined && r.value !== null && r.value !== '')
    .map((r) => ({
      field: r.field,
      value: Array.isArray(r.value) ? r.value.join(', ') : String(r.value),
    }));
}

interface MitreBadge {
  key: string;
  label: string;
  href: string;
  color: string;
}

/** Flatten a rule's MITRE threat entries into a flat, uniquely-keyed badge list (tactic → technique
 *  → subtechnique), each linking out to attack.mitre.org in a new tab. */
function mitreBadges(
  threat: NonNullable<TlsocAlert['rule']>['threat']
): MitreBadge[] {
  const badges: MitreBadge[] = [];
  (threat ?? []).forEach((entry, ei) => {
    if (entry.tactic) {
      badges.push({
        key: `tactic-${ei}`,
        label: `${entry.tactic.id} · ${entry.tactic.name}`,
        href: entry.tactic.reference,
        color: 'hollow',
      });
    }
    (entry.technique ?? []).forEach((tech, ti) => {
      badges.push({
        key: `tech-${ei}-${ti}`,
        label: `${tech.id} · ${tech.name}`,
        href: tech.reference,
        color: 'primary',
      });
      (tech.subtechnique ?? []).forEach((sub, si) => {
        badges.push({
          key: `sub-${ei}-${ti}-${si}`,
          label: `${sub.id} · ${sub.name}`,
          href: sub.reference,
          color: 'accent',
        });
      });
    });
  });
  return badges;
}

/**
 * The alert detail flyout (WS-1, PROB-1: "an alert carries no event context — an L1 cannot
 * triage"). Extracted out of alerts_app.tsx and enriched top-down: About (reason + description) →
 * Highlighted fields → MITRE ATT&CK → Risk score → Triage runbook → Event details → False
 * positives/References → the original state/severity/times/ids rows + actions.
 *
 * Everything RULE-side (MITRE, runbook, risk score, false positives, references) renders
 * regardless of whether the related-doc fetch succeeds — only the doc-dependent parts (reason's
 * who/what/where, highlighted field VALUES, event details) degrade gracefully on a fetch failure.
 */
export function AlertFlyout({
  core,
  alert,
  onClose,
  onAcknowledge,
  canInvestigate,
  onInvestigate,
  onCreateCase,
}: Props) {
  const { docs, loading, error } = useRelatedDocs(core, alert);
  const isBucket = !!(alert.bucketKeys && alert.bucketKeys.length > 0);

  const foundDocs = useMemo(() => docs.filter((d) => d.found && d.source), [docs]);
  const firstDoc = foundDocs[0]?.source;
  const extraDocCount = Math.max(0, foundDocs.length - 1);

  const reason = useMemo(() => buildReason(alert, firstDoc), [alert, firstDoc]);
  const highlightRows = useMemo(() => buildHighlightRows(alert, firstDoc), [alert, firstDoc]);
  const badges = useMemo(() => mitreBadges(alert.rule?.threat), [alert.rule]);

  const runbookContext = isBucket
    ? buildBucketContext(alert.rule?.groupBy ?? [], alert.bucketKeys ?? [])
    : firstDoc;
  const runbookMarkdown = alert.rule?.note
    ? substituteFieldPlaceholders(alert.rule.note, runbookContext)
    : null;

  const eventOriginal = firstDoc ? getPath(firstDoc, 'event.original') : undefined;
  const eventDetailRows = useMemo(() => {
    if (!firstDoc) return [];
    const flat = flattenObject(firstDoc);
    return Object.keys(flat)
      .filter((k) => flat[k] !== '' && flat[k] !== null && flat[k] !== undefined)
      .sort()
      .slice(0, MAX_EVENT_DETAIL_ROWS)
      .map((k) => ({
        title: k,
        description: Array.isArray(flat[k]) ? (flat[k] as unknown[]).join(', ') : String(flat[k]),
      }));
  }, [firstDoc]);

  return (
    <EuiFlyout onClose={onClose} size="m">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2>{alert.triggerName}</h2>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        {loading ? (
          <>
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size="m" />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="s" color="subdued">
                  Loading event context…
                </EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="m" />
          </>
        ) : null}
        {error ? (
          <>
            <EuiCallOut size="s" color="warning" iconType="alert" title="Could not load related documents">
              <p>{error} — rule details below are still shown.</p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        ) : null}

        {/* About */}
        <EuiText size="s">
          <p>{reason}</p>
          {alert.rule?.description ? <p>{alert.rule.description}</p> : null}
        </EuiText>
        <EuiSpacer size="m" />

        {/* Highlighted fields */}
        {highlightRows.length > 0 ? (
          <>
            <EuiTitle size="xxs">
              <h4>Highlighted fields</h4>
            </EuiTitle>
            <EuiSpacer size="xs" />
            <EuiDescriptionList
              type="column"
              compressed
              listItems={highlightRows.map((r) => ({ title: r.field, description: r.value }))}
            />
            <EuiSpacer size="m" />
          </>
        ) : null}

        {/* MITRE ATT&CK */}
        {badges.length > 0 ? (
          <>
            <EuiTitle size="xxs">
              <h4>MITRE ATT&amp;CK</h4>
            </EuiTitle>
            <EuiSpacer size="xs" />
            <EuiFlexGroup wrap responsive={false} gutterSize="xs">
              {badges.map((b) => (
                <EuiFlexItem grow={false} key={b.key}>
                  <EuiBadge color={b.color} href={b.href} target="_blank" rel="noopener noreferrer">
                    {b.label}
                  </EuiBadge>
                </EuiFlexItem>
              ))}
            </EuiFlexGroup>
            <EuiSpacer size="m" />
          </>
        ) : null}

        {/* Risk score */}
        {alert.rule?.riskScore !== undefined ? (
          <>
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiText size="s">
                  <strong>Risk score</strong>
                </EuiText>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiBadge color={riskScoreColor(alert.rule.riskScore)}>
                  {alert.rule.riskScore} / 100
                </EuiBadge>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="m" />
          </>
        ) : null}

        {/* Triage runbook */}
        {runbookMarkdown ? (
          <>
            <EuiTitle size="xxs">
              <h4>Triage runbook</h4>
            </EuiTitle>
            <EuiSpacer size="xs" />
            <EuiMarkdownFormat>{runbookMarkdown}</EuiMarkdownFormat>
            <EuiSpacer size="m" />
          </>
        ) : null}

        {/* Event details */}
        {eventOriginal != null || eventDetailRows.length > 0 ? (
          <>
            <EuiTitle size="xxs">
              <h4>Event details</h4>
            </EuiTitle>
            <EuiSpacer size="xs" />
            {eventOriginal != null ? (
              <>
                <EuiCodeBlock fontSize="s" paddingSize="s" isCopyable>
                  {String(eventOriginal)}
                </EuiCodeBlock>
                <EuiSpacer size="s" />
              </>
            ) : null}
            {eventDetailRows.length > 0 ? (
              <EuiDescriptionList
                type="column"
                compressed
                textStyle="reverse"
                listItems={eventDetailRows}
              />
            ) : null}
            {extraDocCount > 0 ? (
              <>
                <EuiSpacer size="xs" />
                <EuiText size="xs" color="subdued">
                  <p>+{extraDocCount} more related document(s) not shown.</p>
                </EuiText>
              </>
            ) : null}
            <EuiSpacer size="m" />
          </>
        ) : null}

        {/* False positives / References */}
        {alert.rule?.falsePositives && alert.rule.falsePositives.length > 0 ? (
          <>
            <EuiTitle size="xxs">
              <h4>Known false positives</h4>
            </EuiTitle>
            <EuiSpacer size="xs" />
            <EuiText size="s">
              <ul>
                {alert.rule.falsePositives.map((fp, i) => (
                  <li key={i}>{fp}</li>
                ))}
              </ul>
            </EuiText>
            <EuiSpacer size="m" />
          </>
        ) : null}
        {alert.rule?.references && alert.rule.references.length > 0 ? (
          <>
            <EuiTitle size="xxs">
              <h4>References</h4>
            </EuiTitle>
            <EuiSpacer size="xs" />
            <EuiText size="s">
              <ul>
                {alert.rule.references.map((ref, i) => (
                  <li key={i}>
                    <EuiLink href={ref} target="_blank" rel="noopener noreferrer">
                      {ref}
                    </EuiLink>
                  </li>
                ))}
              </ul>
            </EuiText>
            <EuiSpacer size="m" />
          </>
        ) : null}

        <EuiHorizontalRule margin="s" />

        {/* Original rows */}
        <EuiDescriptionList
          listItems={[
            {
              title: 'Rule',
              description: alert.rule?.name ?? 'Unknown',
            },
            {
              title: 'Type',
              description: alert.rule?.mode ?? '—',
            },
            {
              title: 'Index',
              description: alert.rule?.index ?? '—',
            },
            {
              title: 'Severity',
              description: <EuiBadge color={sevColor(alert.severityLabel)}>{alert.severityLabel}</EuiBadge>,
            },
            {
              title: 'State',
              description: <EuiBadge color={stateColor(alert.state)}>{alert.state}</EuiBadge>,
            },
            {
              title: 'Started',
              description: alert.startTime ? new Date(alert.startTime).toLocaleString() : '—',
            },
            {
              title: 'Acknowledged',
              description: alert.acknowledgedTime
                ? new Date(alert.acknowledgedTime).toLocaleString()
                : '—',
            },
            {
              title: 'Finding IDs',
              description: alert.findingIds.join(', ') || '—',
            },
            {
              title: 'Related docs',
              description: alert.relatedDocIds.join(', ') || '—',
            },
            {
              title: 'Error',
              description: alert.errorMessage ?? '—',
            },
          ]}
        />
        <EuiSpacer size="m" />
        <EuiFlexGroup gutterSize="s">
          <EuiFlexItem grow={false}>
            <EuiButton isDisabled={alert.state !== 'ACTIVE'} onClick={onAcknowledge}>
              Acknowledge
            </EuiButton>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            {canInvestigate ? (
              <EuiButton onClick={onInvestigate}>Investigate in Discover</EuiButton>
            ) : (
              <EuiToolTip
                content={`Create a data view for "${alert.rule?.index ?? 'the alert index'}" to enable investigation`}
              >
                <EuiButtonEmpty isDisabled>Investigate in Discover</EuiButtonEmpty>
              </EuiToolTip>
            )}
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton onClick={onCreateCase}>Create case</EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutBody>
    </EuiFlyout>
  );
}
