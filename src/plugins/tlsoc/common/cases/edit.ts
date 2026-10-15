/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// assignee/category: '' = none.
export interface CaseEditForm {
  title: string;
  description: string;
  severity: string;
  assignee: string;
  tags: string[];
  category: string;
}

// Loose on purpose: the UI's CaseFull types severity as string.
interface EditableCase {
  title: string;
  description?: string;
  severity: string;
  assignee?: string | null;
  tags?: string[];
  category?: string;
}

const sameTags = (a: string[], b: string[]) =>
  JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

// Only the changed fields: re-sending untouched ones reverts colleagues' edits and 403s non-managers.
export function diffCaseEdit(original: EditableCase, form: CaseEditForm): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  if (form.title !== original.title) patch.title = form.title;
  if (form.description !== (original.description ?? '')) patch.description = form.description;
  if (form.severity !== original.severity) patch.severity = form.severity;
  if ((form.assignee || null) !== (original.assignee ?? null))
    patch.assignee = form.assignee || null;
  if (!sameTags(form.tags, original.tags ?? [])) patch.tags = form.tags;
  if (form.category !== (original.category ?? '')) patch.category = form.category;
  return patch;
}
