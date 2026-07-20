/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { listTypes } from '../../common/detection';
import { findUiType, getUiType, listUiTypes } from './type_registry';

describe('type_registry ⇄ common registry parity', () => {
  it('the UI registry and the execution registry expose the SAME type id set', () => {
    // The two registry layers are split only because React cannot live in common/ — a type
    // registered in one but not the other is a half-wired type (no editor, or no compiler).
    expect(new Set(listUiTypes().map((t) => t.id))).toEqual(new Set(listTypes().map((t) => t.id)));
  });

  it('every UI type carries a complete card, badge, editor, and preview strategy', () => {
    listUiTypes().forEach((t) => {
      expect(t.card.label).toBeTruthy();
      expect(t.card.description).toBeTruthy();
      expect(t.card.icon).toBeTruthy();
      expect(t.listBadge.label).toBeTruthy();
      expect(t.listBadge.color).toBeTruthy();
      expect(t.editor).toBeTruthy();
      expect(['bucket-dryrun', 'search-sample']).toContain(t.previewStrategy);
    });
  });

  it('getUiType throws naming an unknown id; findUiType returns undefined for it', () => {
    expect(() => getUiType('sequence')).toThrow(/"sequence"/);
    expect(findUiType('sequence')).toBeUndefined();
    expect(findUiType('stateful')).toBeDefined();
  });
});
