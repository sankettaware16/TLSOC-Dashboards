/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import { DataPublicPluginStart } from '../../../data/public';

/** A field of the selected data view, reduced to what the builder needs. */
export interface FieldOption {
  name: string;
  type: string;
  /** Aggregatable fields (ip/keyword/numeric…) can be a composite group-by; text fields cannot. */
  aggregatable: boolean;
  /** Filterable fields can appear in a match condition. */
  filterable: boolean;
  /** The raw OpenSearch mapping type(s) of this field, e.g. ['text'] or ['keyword']. */
  esTypes: string[];
}

export interface DataViewRef {
  id: string;
  title: string;
}

/** Load the list of data views the user can pick from. */
export function useDataViews(data: DataPublicPluginStart) {
  const [views, setViews] = useState<DataViewRef[]>([]);
  const [loadingViews, setLoadingViews] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const ids = await data.dataViews.getIdsWithTitle();
        if (active) setViews(ids.map((v) => ({ id: v.id, title: v.title })));
      } catch (e) {
        if (active) setError(`Could not load data views: ${(e as Error)?.message ?? e}`);
      } finally {
        if (active) setLoadingViews(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [data]);

  return { views, loadingViews, error };
}

/** Load the fields (with type + aggregatable/filterable flags) of one data view. */
export function useDataViewFields(data: DataPublicPluginStart, dataViewId: string | undefined) {
  const [fields, setFields] = useState<FieldOption[]>([]);
  const [loadingFields, setLoadingFields] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!dataViewId) {
      setFields([]);
      return;
    }
    let active = true;
    setLoadingFields(true);
    setError(null);
    (async () => {
      try {
        const dataView = await data.dataViews.get(dataViewId);
        // NOTE: dataView.fields is an Array subclass whose .filter()/.map() re-expand to the full
        // field list (predicate ignored) — a known OSD field-list quirk. getAll() returns a plain
        // array, so filtering by aggregatable/filterable actually works.
        const opts: FieldOption[] = dataView.fields
          .getAll()
          .filter((f) => !f.name.startsWith('_'))
          .map((f) => ({
            name: f.name,
            type: f.type,
            aggregatable: !!f.aggregatable,
            filterable: !!f.filterable,
            esTypes: f.esTypes ?? [],
          }));
        if (active) setFields(opts);
      } catch (e) {
        if (active) setError(`Could not load fields: ${(e as Error)?.message ?? e}`);
      } finally {
        if (active) setLoadingFields(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [data, dataViewId]);

  return { fields, loadingFields, error };
}
