/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { useEffect, useState } from 'react';
import {
  EuiAccordion,
  EuiBadge,
  EuiBasicTable,
  EuiBasicTableColumn,
  EuiButton,
  EuiCallOut,
  EuiCodeBlock,
  EuiCommentList,
  EuiComboBox,
  EuiDescriptionList,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiLoadingSpinner,
  EuiMarkdownEditor,
  EuiMarkdownFormat,
  EuiPage,
  EuiPageBody,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiTabbedContent,
  EuiText,
  EuiTextArea,
  EuiTitle,
} from '@elastic/eui';
import { CoreStart } from 'opensearch-dashboards/public';
import { DataPublicPluginStart } from '../../../data/public';
import {
  CaseStatus,
  CaseActivityType,
  nextStatuses,
  CASE_CATEGORIES,
  formatDuration,
  caseOpenDurationMs,
  caseReporter,
  deriveParticipants,
} from '../../common/cases';
import { useCase, useCaseAlerts, HydratedAlert } from './use_cases';
import { sevColor, stateColor, entityOf } from '../alerts/format';
import { InvestigationTab } from './investigation_tab';

interface Props {
  core: CoreStart;
  data: DataPublicPluginStart;
  caseId: string;
  onBack: () => void;
}

function statusColor(s: CaseStatus): string {
  switch (s) {
    case 'New':
      return 'default';
    case 'Assigned':
      return 'primary';
    case 'In Progress':
      return 'accent';
    case 'Contained':
      return 'warning';
    case 'Closed':
      return 'hollow';
    default:
      return 'default';
  }
}

function localSevColor(s: string): string {
  switch (s) {
    case 'critical':
      return 'danger';
    case 'high':
      return 'warning';
    case 'medium':
      return 'default';
    case 'low':
      return 'hollow';
    default:
      return 'hollow';
  }
}

function iconForActivity(type: CaseActivityType): string {
  switch (type) {
    case 'created':
      return 'plusInCircle';
    case 'status_changed':
      return 'check';
    case 'edited':
      return 'pencil';
    case 'alerts_linked':
      return 'link';
    case 'commented':
      return 'quote';
    default:
      return 'dot';
  }
}

export function CaseDetail({ core, data, caseId, onBack }: Props) {
  const { caseItem, loading, error, updateCase, addComment } = useCase(core, caseId);
  const { alerts: linkedAlerts, missingIds, loading: alertsLoading } = useCaseAlerts(core, caseId);
  const [selectedAlert, setSelectedAlert] = useState<HydratedAlert | null>(null);

  // Editable detail fields seeded from caseItem
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [assignee, setAssignee] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [category, setCategory] = useState<string>('');

  // Comment state
  const [newComment, setNewComment] = useState('');

  // Real-user list for the assignee picker (Task 5a.4) — from GET /api/tlsoc/users.
  const [userOptions, setUserOptions] = useState<Array<{ label: string }>>([]);

  useEffect(() => {
    if (caseItem) {
      setTitle(caseItem.title);
      setDescription(caseItem.description);
      setSeverity(caseItem.severity);
      setAssignee(caseItem.assignee ?? '');
      setTags(caseItem.tags ?? []);
      setCategory(caseItem.category ?? '');
    }
  }, [caseItem]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = (await core.http.get('/api/tlsoc/users')) as { users?: Array<{ name: string }> };
        if (!cancelled) setUserOptions((resp?.users ?? []).map((u) => ({ label: u.name })));
      } catch {
        if (!cancelled) setUserOptions([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [core]);

  if (loading) {
    return (
      <EuiPage paddingSize="l">
        <EuiPageBody>
          <EuiFlexGroup justifyContent="center" alignItems="center" gutterSize="s">
            <EuiFlexItem grow={false}>
              <EuiLoadingSpinner size="l" />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="s">Loading case…</EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiPageBody>
      </EuiPage>
    );
  }

  if (error) {
    return (
      <EuiPage paddingSize="l">
        <EuiPageBody>
          <EuiCallOut color="danger" iconType="alert" title="Could not load case">
            <p>{error}</p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          <EuiButton onClick={onBack} iconType="arrowLeft">
            Back to cases
          </EuiButton>
        </EuiPageBody>
      </EuiPage>
    );
  }

  if (!caseItem) {
    return (
      <EuiPage paddingSize="l">
        <EuiPageBody>
          <EuiCallOut color="warning" iconType="alert" title="Case not found">
            <p>The case with ID {caseId} could not be found.</p>
          </EuiCallOut>
          <EuiSpacer size="m" />
          <EuiButton onClick={onBack} iconType="arrowLeft">
            Back to cases
          </EuiButton>
        </EuiPageBody>
      </EuiPage>
    );
  }

  const statusOptions = nextStatuses(caseItem.status).map((s) => ({ value: s, text: s }));

  const alertColumns: Array<EuiBasicTableColumn<HydratedAlert>> = [
    {
      name: 'Severity',
      render: (a: HydratedAlert) => (
        <EuiBadge color={sevColor(a.severityLabel)}>{a.severityLabel}</EuiBadge>
      ),
    },
    {
      name: 'Rule',
      render: (a: HydratedAlert) =>
        a.ruleKnown && a.rule ? (
          <span>{a.rule.name}</span>
        ) : (
          <EuiText color="subdued" size="s">
            Unknown rule ({a.monitorName})
          </EuiText>
        ),
    },
    {
      name: 'State',
      render: (a: HydratedAlert) => (
        <EuiBadge color={stateColor(a.state)}>{a.state}</EuiBadge>
      ),
    },
    {
      field: 'triggerName' as keyof HydratedAlert,
      name: 'Trigger',
      truncateText: true,
    },
    {
      name: 'Entity',
      truncateText: true,
      render: (a: HydratedAlert) => entityOf(a),
    },
    {
      name: 'Time',
      render: (a: HydratedAlert) =>
        a.startTime ? new Date(a.startTime).toLocaleString() : '—',
    },
  ];

  return (
    <EuiPage paddingSize="l">
      <EuiPageBody>
        {/* Header */}
        <EuiFlexGroup alignItems="flexStart" justifyContent="spaceBetween">
          <EuiFlexItem>
            <EuiTitle size="l">
              <h1>{caseItem.title}</h1>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton iconType="arrowLeft" onClick={onBack}>
              Back to cases
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer size="m" />

        {/* Stat-bar — persistent case summary, visible across all tabs */}
        <EuiPanel hasBorder hasShadow={false} paddingSize="m">
          <EuiFlexGroup gutterSize="l" alignItems="center" responsive={false} wrap>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Status</p></EuiText>
              <EuiBadge color={statusColor(caseItem.status)}>{caseItem.status}</EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Severity</p></EuiText>
              <EuiBadge color={localSevColor(caseItem.severity)}>{caseItem.severity}</EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Assignee</p></EuiText>
              <EuiText size="s"><p>{caseItem.assignee || 'Unassigned'}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Reporter</p></EuiText>
              <EuiText size="s"><p>{caseReporter(caseItem) || 'Unknown'}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Category</p></EuiText>
              <EuiText size="s"><p>{caseItem.category || 'Uncategorized'}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Alerts</p></EuiText>
              <EuiText size="s"><p>{caseItem.linkedAlertIds.length}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Comments</p></EuiText>
              <EuiText size="s"><p>{caseItem.comments.length}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Activity</p></EuiText>
              <EuiText size="s"><p>{(caseItem.activity ?? []).length}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Created</p></EuiText>
              <EuiText size="s"><p>{new Date(caseItem.createdAt).toLocaleDateString()}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued"><p>Updated</p></EuiText>
              <EuiText size="s"><p>{new Date(caseItem.updatedAt).toLocaleDateString()}</p></EuiText>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiText size="xs" color="subdued">
                <p>{caseItem.status === 'Closed' ? 'Time to close' : 'Open for'}</p>
              </EuiText>
              <EuiText size="s">
                <p>{formatDuration(caseOpenDurationMs(caseItem.createdAt, caseItem.closedAt, Date.now()))}</p>
              </EuiText>
            </EuiFlexItem>
          </EuiFlexGroup>
          {(() => {
            const participants = deriveParticipants(caseItem);
            return participants.length > 0 ? (
              <>
                <EuiSpacer size="s" />
                <EuiText size="xs" color="subdued"><p>Participants</p></EuiText>
                <EuiSpacer size="xs" />
                <EuiFlexGroup gutterSize="xs" responsive={false} wrap>
                  {participants.map((p) => (
                    <EuiFlexItem grow={false} key={p}>
                      <EuiBadge color="hollow">{p}</EuiBadge>
                    </EuiFlexItem>
                  ))}
                </EuiFlexGroup>
              </>
            ) : null;
          })()}
        </EuiPanel>
        <EuiSpacer size="l" />

        <EuiTabbedContent
          tabs={[
            {
              id: 'overview',
              name: 'Overview',
              content: (
                <>
                  <EuiSpacer size="m" />
        {/* Editable details panel */}
        <EuiPanel hasBorder hasShadow={false}>
          <EuiTitle size="s">
            <h2>Details</h2>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiForm>
            <EuiFormRow label="Title">
              <EuiFieldText
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </EuiFormRow>
            <EuiFormRow label="Description">
              <EuiTextArea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={4}
              />
            </EuiFormRow>
            <EuiFormRow label="Severity">
              <EuiSelect
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                options={[
                  { value: 'low', text: 'Low' },
                  { value: 'medium', text: 'Medium' },
                  { value: 'high', text: 'High' },
                  { value: 'critical', text: 'Critical' },
                ]}
              />
            </EuiFormRow>
            <EuiFormRow label="Assignee">
              <EuiComboBox
                placeholder="Unassigned"
                singleSelection={{ asPlainText: true }}
                isClearable
                options={
                  // fetched users, plus the current assignee if it isn't in the list (legacy / reserved)
                  assignee && !userOptions.some((o) => o.label === assignee)
                    ? [{ label: assignee }, ...userOptions]
                    : userOptions
                }
                selectedOptions={assignee ? [{ label: assignee }] : []}
                onChange={(selected) => setAssignee(selected[0]?.label ?? '')}
              />
            </EuiFormRow>
            <EuiFormRow label="Tags">
              <EuiComboBox
                noSuggestions
                placeholder="Add tags"
                selectedOptions={tags.map((t) => ({ label: t }))}
                onCreateOption={(val) => {
                  const v = val.trim();
                  if (v && !tags.includes(v)) setTags([...tags, v]);
                }}
                onChange={(opts) => setTags(opts.map((o) => o.label))}
              />
            </EuiFormRow>
            <EuiFormRow label="Category">
              <EuiSelect
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                options={[
                  { value: '', text: 'Uncategorized' },
                  ...CASE_CATEGORIES.map((c) => ({ value: c, text: c })),
                ]}
              />
            </EuiFormRow>
            <EuiSpacer size="m" />
            <EuiButton
              fill
              onClick={() =>
                updateCase({
                  title,
                  description,
                  severity,
                  assignee: assignee || null,
                  tags,
                  category,
                })
              }
            >
              Save changes
            </EuiButton>
          </EuiForm>
        </EuiPanel>
        <EuiSpacer size="l" />

        {/* Status panel */}
        <EuiPanel hasBorder hasShadow={false}>
          <EuiTitle size="s">
            <h2>Status</h2>
          </EuiTitle>
          <EuiSpacer size="m" />
          <EuiFlexGroup gutterSize="m" alignItems="center">
            <EuiFlexItem grow={false}>
              <EuiBadge color={statusColor(caseItem.status)}>{caseItem.status}</EuiBadge>
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiSelect
                value={caseItem.status}
                onChange={(e) => {
                  const val = e.target.value as CaseStatus;
                  if (val !== caseItem.status) {
                    updateCase({ status: val });
                  }
                }}
                options={statusOptions}
              />
            </EuiFlexItem>
          </EuiFlexGroup>
          <EuiSpacer size="s" />
          <EuiText size="xs" color="subdued">
            <p>Only valid next states are shown.</p>
          </EuiText>
        </EuiPanel>
                </>
              ),
            },
            {
              id: 'alerts',
              name: 'Alerts',
              content: (
                <>
                  <EuiSpacer size="m" />
        {/* Linked evidence panel */}
        <EuiPanel hasBorder hasShadow={false}>
          <EuiTitle size="s">
            <h2>Linked evidence</h2>
          </EuiTitle>
          <EuiSpacer size="m" />

          <EuiText size="s">
            <strong>Linked alerts</strong>
          </EuiText>
          <EuiSpacer size="s" />
          {alertsLoading ? (
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiLoadingSpinner size="m" />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="s">Loading linked alerts…</EuiText>
              </EuiFlexItem>
            </EuiFlexGroup>
          ) : linkedAlerts.length === 0 ? (
            <EuiText size="s" color="subdued">
              No linked alerts.
            </EuiText>
          ) : (
            <EuiBasicTable
              items={linkedAlerts}
              columns={alertColumns}
              rowProps={(a) => ({
                onClick: () => setSelectedAlert(a),
                style: { cursor: 'pointer' },
              })}
            />
          )}
          {missingIds.length > 0 ? (
            <>
              <EuiSpacer size="s" />
              <EuiText size="xs" color="subdued">
                <p>{missingIds.length} linked alert(s) no longer available.</p>
              </EuiText>
            </>
          ) : null}

          <EuiSpacer size="m" />
          <EuiDescriptionList
            listItems={[
              ...(caseItem.createdFromAlertId
                ? [{ title: 'Seeded from alert', description: caseItem.createdFromAlertId }]
                : []),
              {
                title: 'Linked findings',
                description: caseItem.linkedFindingIds.join(', ') || '—',
              },
            ]}
          />
        </EuiPanel>
                </>
              ),
            },
            {
              id: 'investigate',
              name: 'Investigate',
              content: (
                <InvestigationTab
                  core={core}
                  data={data}
                  alerts={linkedAlerts}
                  alertsLoading={alertsLoading}
                />
              ),
            },
            {
              id: 'activity',
              name: 'Activity',
              content: (
                <>
                  <EuiSpacer size="m" />
        {/* Activity panel */}
        <EuiPanel hasBorder hasShadow={false}>
          <EuiTitle size="s">
            <h2>Activity</h2>
          </EuiTitle>
          <EuiSpacer size="m" />
          {(() => {
            const activity = caseItem.activity ?? [];
            if (activity.length === 0) {
              return (
                <EuiText color="subdued" size="s">
                  <p>No activity recorded yet.</p>
                </EuiText>
              );
            }
            const activityComments = activity.map((a) => ({
              username: a.actor,
              type: 'update' as const,
              timelineIcon: iconForActivity(a.type),
              event: a.summary,
              timestamp: new Date(a.createdAt).toLocaleString(),
            }));
            return <EuiCommentList comments={activityComments} />;
          })()}
        </EuiPanel>
                </>
              ),
            },
            {
              id: 'comments',
              name: 'Comments',
              content: (
                <>
                  <EuiSpacer size="m" />
        {/* Comments panel */}
        <EuiPanel hasBorder hasShadow={false}>
          <EuiTitle size="s">
            <h2>Comments</h2>
          </EuiTitle>
          <EuiSpacer size="m" />
          {caseItem.comments.length === 0 ? (
            <EuiText size="s" color="subdued">
              <p>No comments yet.</p>
            </EuiText>
          ) : (
            caseItem.comments.map((c) => (
              <EuiPanel key={c.id} hasBorder hasShadow={false} paddingSize="s" style={{ marginBottom: 16 }}>
                <EuiText size="xs" color="subdued">
                  <p>
                    {c.author} &middot; {new Date(c.createdAt).toLocaleString()}
                  </p>
                </EuiText>
                <EuiMarkdownFormat>{c.text}</EuiMarkdownFormat>
              </EuiPanel>
            ))
          )}
          <EuiSpacer size="m" />
          <EuiFormRow label="Add a comment" fullWidth>
            <EuiMarkdownEditor
              aria-label="Add a comment"
              value={newComment}
              onChange={setNewComment}
              height={200}
            />
          </EuiFormRow>
          <EuiSpacer size="s" />
          <EuiButton
            isDisabled={!newComment.trim()}
            onClick={async () => {
              await addComment(newComment);
              setNewComment('');
            }}
          >
            Add comment
          </EuiButton>
        </EuiPanel>
                </>
              ),
            },
          ]}
        />
      </EuiPageBody>

      {selectedAlert ? (
        <EuiFlyout onClose={() => setSelectedAlert(null)} size="s">
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size="m">
              <h2>{selectedAlert.triggerName || 'Alert'}</h2>
            </EuiTitle>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <EuiDescriptionList
              listItems={[
                { title: 'Rule', description: selectedAlert.rule?.name ?? 'Unknown' },
                { title: 'Type', description: selectedAlert.rule?.mode ?? '—' },
                { title: 'Index', description: selectedAlert.rule?.index ?? '—' },
                {
                  title: 'Severity',
                  description: (
                    <EuiBadge color={sevColor(selectedAlert.severityLabel)}>
                      {selectedAlert.severityLabel}
                    </EuiBadge>
                  ),
                },
                {
                  title: 'State',
                  description: (
                    <EuiBadge color={stateColor(selectedAlert.state)}>
                      {selectedAlert.state}
                    </EuiBadge>
                  ),
                },
                { title: 'Trigger', description: selectedAlert.triggerName || '—' },
                { title: 'Entity', description: entityOf(selectedAlert) },
                {
                  title: 'Started',
                  description: selectedAlert.startTime
                    ? new Date(selectedAlert.startTime).toLocaleString()
                    : '—',
                },
                {
                  title: 'Finding IDs',
                  description: selectedAlert.findingIds.join(', ') || '—',
                },
                {
                  title: 'Related docs',
                  description: selectedAlert.relatedDocIds.join(', ') || '—',
                },
                { title: 'Error', description: selectedAlert.errorMessage ?? '—' },
              ]}
            />
            <EuiSpacer size="m" />
            <EuiAccordion id="rawjson" buttonContent="Raw JSON">
              <EuiCodeBlock
                language="json"
                fontSize="s"
                paddingSize="s"
                isCopyable
                overflowHeight={400}
              >
                {JSON.stringify(selectedAlert.raw ?? {}, null, 2)}
              </EuiCodeBlock>
            </EuiAccordion>
          </EuiFlyoutBody>
        </EuiFlyout>
      ) : null}
    </EuiPage>
  );
}
