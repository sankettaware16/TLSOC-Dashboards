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
  EuiText,
  EuiTextArea,
} from '@elastic/eui';
import { MitreCatalogLookup, parseSigmaImport, SigmaImportSuccess } from '../../common/detection';

interface Props {
  onParsed: (result: SigmaImportSuccess) => void;
  onClose: () => void;
}

/**
 * Import a Sigma YAML rule (paste or upload) and preview what {@link parseSigmaImport} recovered
 * from it. Wiring the successfully-parsed IR into the rule builder is the caller's job (onParsed) —
 * this component only parses and previews.
 */
export function SigmaImportModal({ onParsed, onClose }: Props) {
  const [yamlText, setYamlText] = useState('');
  const [catalog, setCatalog] = useState<MitreCatalogLookup | undefined>(undefined);
  const [result, setResult] = useState<ReturnType<typeof parseSigmaImport> | undefined>(undefined);

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
    setYamlText(text);
    setResult(undefined);
  };

  const handleParse = () => {
    setResult(parseSigmaImport(yamlText, { catalog }));
  };

  return (
    <EuiModal onClose={onClose} style={{ minWidth: 560 }}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Import Sigma rule</EuiModalHeaderTitle>
      </EuiModalHeader>
      <EuiModalBody>
        <EuiFormRow label="Upload a Sigma YAML file">
          <EuiFilePicker
            display="default"
            multiple={false}
            accept=".yml,.yaml"
            onChange={(files) => handleFile(files)}
          />
        </EuiFormRow>
        <EuiSpacer size="m" />
        <EuiFormRow label="…or paste Sigma YAML">
          <EuiTextArea
            value={yamlText}
            onChange={(e) => {
              setYamlText(e.target.value);
              setResult(undefined);
            }}
            placeholder={'title: My rule\ndetection:\n  selection:\n    field: value\n  condition: selection'}
            rows={12}
            style={{ fontFamily: 'monospace' }}
          />
        </EuiFormRow>

        <EuiSpacer size="m" />
        <EuiButton onClick={handleParse} isDisabled={!yamlText.trim()}>
          Parse
        </EuiButton>

        {result && !result.ok ? (
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

        {result && result.ok ? (
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
      </EuiModalBody>
      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
        <EuiButton fill isDisabled={!result || !result.ok} onClick={() => result && result.ok && onParsed(result)}>
          Open in builder
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
