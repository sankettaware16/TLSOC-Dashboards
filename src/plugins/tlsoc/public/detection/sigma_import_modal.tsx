/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiFilePicker,
  EuiFormRow,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTextArea,
} from '@elastic/eui';
import {
  DetectionMode,
  MitreCatalogLookup,
  RuleDefinition,
  SigmaImportSuccess,
  ThresholdRuleDefinition,
  parseSigmaImport,
} from '../../common/detection';
import {
  NativeImportResult,
  NativeRuleEnvelope,
  parseNativeImport,
} from '../../common/detection/export';
import { findUiType } from './type_registry';

/**
 * A successfully parsed rule import handed to the caller — the SAME contract for both tabs
 * (detections_app.tsx builds its ImportTarget from exactly these three fields). Sigma imports
 * ({@link SigmaImportSuccess}) are assignable to it; the native tab constructs it directly and
 * can carry ANY registered mode.
 */
export interface ParsedRuleImport {
  mode: DetectionMode;
  rule: RuleDefinition | ThresholdRuleDefinition;
  warnings: string[];
}

interface Props {
  onParsed: (result: ParsedRuleImport) => void;
  onClose: () => void;
}

/**
 * Import a detection rule and preview what was recovered before opening it in the builder.
 * Two tabs (v1.2.3 D8):
 *  - Sigma YAML (paste or upload) via {@link parseSigmaImport} — unchanged behavior.
 *  - Native JSON: the TLSOC `{version, kind, mode, rule}` export envelope, validated against the
 *    type registry (foreign/unknown envelopes rejected BY NAME). This create-route path is the
 *    ONLY blessed native import — a saved-objects-management NDJSON import would re-create the
 *    rule SO with a dangling monitorId (documented unsupported).
 * Wiring the parsed IR into the rule builder is the caller's job (onParsed) — this component
 * only parses and previews.
 */
export function SigmaImportModal({ onParsed, onClose }: Props) {
  const [tab, setTab] = useState<'sigma' | 'native'>('sigma');

  // ---- Sigma tab state (unchanged) ----
  const [yamlText, setYamlText] = useState('');
  const [catalog, setCatalog] = useState<MitreCatalogLookup | undefined>(undefined);
  const [result, setResult] = useState<ReturnType<typeof parseSigmaImport> | undefined>(undefined);

  // ---- Native tab state ----
  const [nativeText, setNativeText] = useState('');
  const [nativeResult, setNativeResult] = useState<NativeImportResult | undefined>(undefined);

  useEffect(() => {
    // The MITRE catalog is optional — the parser degrades gracefully (unresolved-tag warnings)
    // without it, so a missing/not-yet-built module must never break the import flow.
    import('../../common/mitre')
      .then((m) => setCatalog((m as { ATTACK_CATALOG?: MitreCatalogLookup }).ATTACK_CATALOG))
      .catch(() => setCatalog(undefined));
  }, []);

  const handleFile = async (files: FileList | null) => {
    const file = files && files.length > 0 ? files[0] : null;
    if (!file) return;
    const text = await file.text();
    if (tab === 'sigma') {
      setYamlText(text);
      setResult(undefined);
    } else {
      setNativeText(text);
      setNativeResult(undefined);
    }
  };

  const handleParse = () => {
    if (tab === 'sigma') {
      setResult(parseSigmaImport(yamlText, { catalog }));
    } else {
      setNativeResult(parseNativeImport(nativeText));
    }
  };

  /** The single native envelope ready to open, or undefined (errors / bulk array). */
  const nativeReady: NativeRuleEnvelope | undefined =
    nativeResult?.ok && nativeResult.envelopes.length === 1
      ? nativeResult.envelopes[0]
      : undefined;

  const openInBuilder = () => {
    if (tab === 'sigma') {
      if (result && result.ok) onParsed(result as SigmaImportSuccess);
      return;
    }
    if (nativeReady) {
      onParsed({
        mode: nativeReady.mode,
        rule: (nativeReady.rule as unknown) as RuleDefinition | ThresholdRuleDefinition,
        warnings: [],
      });
    }
  };

  const canOpen = tab === 'sigma' ? !!(result && result.ok) : !!nativeReady;
  const currentText = tab === 'sigma' ? yamlText : nativeText;

  const typeBadge = (mode: string) => {
    const badge = findUiType(mode)?.listBadge;
    return <EuiBadge color={badge?.color ?? 'hollow'}>{badge?.label ?? mode}</EuiBadge>;
  };

  return (
    <EuiModal onClose={onClose} style={{ minWidth: 560 }}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Import rule</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiTabs size="s">
          <EuiTab isSelected={tab === 'sigma'} onClick={() => setTab('sigma')}>
            Sigma YAML
          </EuiTab>
          <EuiTab isSelected={tab === 'native'} onClick={() => setTab('native')}>
            Native JSON (TLSOC export)
          </EuiTab>
        </EuiTabs>
        <EuiSpacer size="m" />

        <EuiFormRow
          label={tab === 'sigma' ? 'Upload a Sigma YAML file' : 'Upload a TLSOC export (.json)'}
        >
          <EuiFilePicker
            key={tab} // reset the picker's own file display when the tab flips
            display="default"
            multiple={false}
            accept={tab === 'sigma' ? '.yml,.yaml' : '.json'}
            onChange={(files) => handleFile(files)}
          />
        </EuiFormRow>
        <EuiSpacer size="m" />
        <EuiFormRow label={tab === 'sigma' ? '…or paste Sigma YAML' : '…or paste the export JSON'}>
          <EuiTextArea
            value={currentText}
            onChange={(e) => {
              if (tab === 'sigma') {
                setYamlText(e.target.value);
                setResult(undefined);
              } else {
                setNativeText(e.target.value);
                setNativeResult(undefined);
              }
            }}
            placeholder={
              tab === 'sigma'
                ? 'title: My rule\ndetection:\n  selection:\n    field: value\n  condition: selection'
                : '{\n  "version": "1",\n  "kind": "tlsoc-detection-rule",\n  "mode": "…",\n  "rule": { … }\n}'
            }
            rows={12}
            style={{ fontFamily: 'monospace' }}
          />
        </EuiFormRow>

        <EuiSpacer size="m" />
        <EuiButton onClick={handleParse} isDisabled={!currentText.trim()}>
          Parse
        </EuiButton>

        {tab === 'sigma' && result && !result.ok ? (
          <>
            <EuiSpacer size="m" />
            <EuiCallOut size="s" color="danger" iconType="alert" title="Could not import this rule">
              <ul>
                {result.errors.map((e, i) => (
                  <li key={i}>
                    <strong>{e.construct}</strong>: {e.reason}
                  </li>
                ))}
              </ul>
              {/* v1.2.1 (tester finding): a real import failed because pasting had flattened the
                  YAML indentation/list markers — steer people to the lossless path. */}
              <p>
                Tip: pasting from a browser or chat often mangles YAML indentation — the file
                upload above preserves the rule exactly.
              </p>
            </EuiCallOut>
          </>
        ) : null}

        {tab === 'sigma' && result && result.ok ? (
          <>
            <EuiSpacer size="m" />
            <EuiText size="s">
              <p>
                <strong>{result.rule.name}</strong>{' '}
                <EuiBadge color={result.mode === 'stateful' ? 'accent' : 'hollow'}>
                  {result.mode === 'stateful' ? 'Threshold' : 'Single-event'}
                </EuiBadge>
              </p>
              <p>
                {result.mode === 'stateful'
                  ? `${(result.rule as { filter?: { conditions: unknown[] } }).filter?.conditions.length ?? 0} filter condition(s)`
                  : `${(result.rule as { group?: { conditions: unknown[] } }).group?.conditions.length ?? 0} condition(s)`}
                {' · '}
                index hint: <code>{result.rule.index || '(none — choose a data view in the builder)'}</code>
              </p>
            </EuiText>
            {result.warnings.length > 0 ? (
              <EuiCallOut size="s" color="warning" iconType="alert" title="Imported with warnings">
                <ul>
                  {result.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </EuiCallOut>
            ) : null}
          </>
        ) : null}

        {tab === 'native' && nativeResult && !nativeResult.ok ? (
          <>
            <EuiSpacer size="m" />
            <EuiCallOut size="s" color="danger" iconType="alert" title="Could not import this file">
              <ul>
                {nativeResult.errors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </EuiCallOut>
          </>
        ) : null}

        {tab === 'native' && nativeResult?.ok && nativeResult.envelopes.length > 1 ? (
          <>
            <EuiSpacer size="m" />
            <EuiCallOut
              size="s"
              color="warning"
              iconType="alert"
              title={`This file contains ${nativeResult.envelopes.length} rules`}
            >
              <p>
                The builder opens ONE rule at a time — split the array and import each envelope
                separately. Rules in this file:{' '}
                {nativeResult.envelopes
                  .map((e) => String((e.rule as { name?: unknown }).name ?? '(unnamed)'))
                  .join(', ')}
                .
              </p>
            </EuiCallOut>
          </>
        ) : null}

        {tab === 'native' && nativeReady ? (
          <>
            <EuiSpacer size="m" />
            <EuiText size="s">
              <p>
                <strong>{String((nativeReady.rule as { name?: unknown }).name ?? 'Unnamed rule')}</strong>{' '}
                {typeBadge(nativeReady.mode)}
              </p>
              <p>
                index: <code>{String((nativeReady.rule as { index?: unknown }).index ?? '(none)')}</code>
              </p>
            </EuiText>
          </>
        ) : null}
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
        <EuiButton fill isDisabled={!canOpen} onClick={openInBuilder}>
          Open in builder
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
