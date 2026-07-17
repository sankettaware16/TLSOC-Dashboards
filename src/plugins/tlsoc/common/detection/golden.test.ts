/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { load } from 'js-yaml';
import { compileToDocLevelMonitor, compileToSigma } from './index';
import { ALL_DETECTION_OPERATORS, Condition, DetectionOperator, RuleDefinition } from './types';

/**
 * Golden, realistic SOC detections. Each fixture asserts BOTH compile outputs for the SAME rule, so
 * the Sigma export and the executable doc-level monitor can never silently drift (the D-008 sync rule).
 * The fixtures deliberately exercise AND + OR, negation, ranges, lists and regex — not toy cases.
 */
describe('golden: realistic SOC detections compile to BOTH Sigma and a doc-level monitor', () => {
  it('1. Failed SSH login from a watchlisted source IP (AND · equals · is_one_of)', () => {
    const rule: RuleDefinition = {
      id: '2b6e1f8c-0a2d-4c6e-9b21-failedsshlogin',
      name: 'Failed SSH login from a watchlisted source IP',
      description: 'A failed SSH authentication originating from a known-suspicious source address.',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      logSource: { category: 'authentication', product: 'linux', service: 'auth' },
      author: 'TLSOC',
      date: '2026/06/22',
      references: ['https://attack.mitre.org/techniques/T1110/'],
      group: {
        logic: 'AND',
        conditions: [
          { field: 'event.outcome', operator: 'equals', value: 'failure' },
          { field: 'event.module', operator: 'equals', value: 'ssh' },
          { field: 'source.ip', operator: 'is_one_of', values: ['198.51.100.23', '203.0.113.7'] },
        ],
      },
    };

    expect(load(compileToSigma(rule))).toEqual({
      title: 'Failed SSH login from a watchlisted source IP',
      id: '2b6e1f8c-0a2d-4c6e-9b21-failedsshlogin',
      status: 'experimental',
      description: 'A failed SSH authentication originating from a known-suspicious source address.',
      references: ['https://attack.mitre.org/techniques/T1110/'],
      author: 'TLSOC',
      date: '2026/06/22',
      logsource: { category: 'authentication', product: 'linux', service: 'auth' },
      detection: {
        sel0: { 'event.outcome': 'failure' },
        sel1: { 'event.module': 'ssh' },
        sel2: { 'source.ip': ['198.51.100.23', '203.0.113.7'] },
        condition: 'sel0 and sel1 and sel2',
      },
      level: 'high',
    });

    expect(compileToDocLevelMonitor(rule)).toEqual({
      type: 'monitor',
      name: 'Failed SSH login from a watchlisted source IP',
      monitor_type: 'doc_level_monitor',
      enabled: true,
      schedule: { period: { interval: 1, unit: 'MINUTES' } },
      inputs: [
        {
          doc_level_input: {
            description:
              'A failed SSH authentication originating from a known-suspicious source address.',
            indices: ['fosstlsoc-logs-*'],
            queries: [
              {
                id: 'failed_ssh_login_from_a_watchlisted_source_ip',
                name: 'failed_ssh_login_from_a_watchlisted_source_ip',
                query:
                  '(event.outcome:"failure") AND (event.module:"ssh") AND (source.ip:"198.51.100.23" OR source.ip:"203.0.113.7")',
                tags: ['tlsoc', 'high'],
              },
            ],
          },
        },
      ],
      triggers: [
        {
          document_level_trigger: {
            name: 'Failed SSH login from a watchlisted source IP matched',
            severity: '2',
            condition: {
              script: {
                source: 'query[name=failed_ssh_login_from_a_watchlisted_source_ip]',
                lang: 'painless',
              },
            },
          },
        },
      ],
    });
  });

  it('2. HTTP 5xx from GET excluding health checks (AND · equals · gte range · not_contains negation)', () => {
    const rule: RuleDefinition = {
      name: 'Repeated HTTP server errors excluding health checks',
      description: 'GET requests returning 5xx, ignoring the health-check endpoint.',
      severity: 'medium',
      index: 'fosstlsoc-logs-reverse-proxy-*',
      logSource: { category: 'webserver' },
      group: {
        logic: 'AND',
        conditions: [
          { field: 'http.request.method', operator: 'equals', value: 'GET' },
          { field: 'http.response.status_code', operator: 'gte', value: 500 },
          { field: 'url.path', operator: 'not_contains', value: '/health' },
        ],
      },
    };

    expect(load(compileToSigma(rule))).toEqual({
      title: 'Repeated HTTP server errors excluding health checks',
      status: 'experimental',
      description: 'GET requests returning 5xx, ignoring the health-check endpoint.',
      logsource: { category: 'webserver' },
      detection: {
        sel0: { 'http.request.method': 'GET' },
        sel1: { 'http.response.status_code|gte': 500 },
        sel2: { 'url.path|contains': '/health' },
        condition: 'sel0 and sel1 and not sel2',
      },
      level: 'medium',
    });

    const monitor = compileToDocLevelMonitor(rule);
    expect(monitor.inputs[0].doc_level_input.queries[0].query).toBe(
      '(http.request.method:"GET") AND (http.response.status_code:>=500) AND (NOT url.path:*\\/health*)'
    );
    expect(monitor.triggers[0].document_level_trigger.severity).toBe('3');
    expect(monitor.inputs[0].doc_level_input.indices).toEqual(['fosstlsoc-logs-reverse-proxy-*']);
  });

  it('3. Web attack signature in request URL (OR · contains · contains · matches_regex)', () => {
    const rule: RuleDefinition = {
      name: 'Web attack signature in request URL',
      severity: 'critical',
      index: 'fosstlsoc-logs-reverse-proxy-*',
      logSource: { category: 'webserver', service: 'modsecurity' },
      group: {
        logic: 'OR',
        conditions: [
          {
            field: 'url.query',
            operator: 'contains',
            value: 'union select',
            fieldType: 'match_only_text',
          },
          { field: 'url.query', operator: 'contains', value: '<script>' },
          { field: 'url.original', operator: 'matches_regex', value: '(?i)etc/passwd' },
        ],
      },
    };

    expect(load(compileToSigma(rule))).toEqual({
      title: 'Web attack signature in request URL',
      status: 'experimental',
      logsource: { category: 'webserver', service: 'modsecurity' },
      detection: {
        sel0: { 'url.query|contains': 'union select' },
        sel1: { 'url.query|contains': '<script>' },
        sel2: { 'url.original|re': '(?i)etc/passwd' },
        condition: 'sel0 or sel1 or sel2',
      },
      level: 'critical',
    });

    // url.query's `contains` carries fieldType 'match_only_text' (an analyzed text field, like the
    // real event.original) → it compiles to a quoted phrase (PROB-4 fix), not a substring wildcard.
    expect(compileToDocLevelMonitor(rule).inputs[0].doc_level_input.queries[0].query).toBe(
      '(url.query:"union select") OR (url.query:*<script>*) OR (url.original:/(?i)etc\\/passwd/)'
    );
  });

  it('4. Suspicious PowerShell execution with a configured run-every cadence (WS-20 / PROB-20)', () => {
    const rule: RuleDefinition = {
      name: 'Suspicious PowerShell execution',
      description: 'PowerShell invoked with an encoded command argument.',
      severity: 'high',
      index: 'fosstlsoc-logs-*',
      logSource: { category: 'process_creation', product: 'windows' },
      runEvery: { value: 10, unit: 'MINUTES' },
      group: {
        logic: 'AND',
        conditions: [
          { field: 'process.name', operator: 'equals', value: 'powershell.exe' },
          { field: 'process.command_line', operator: 'contains', value: '-enc' },
        ],
      },
    };

    expect(compileToDocLevelMonitor(rule)).toEqual({
      type: 'monitor',
      name: 'Suspicious PowerShell execution',
      monitor_type: 'doc_level_monitor',
      enabled: true,
      schedule: { period: { interval: 10, unit: 'MINUTES' } },
      inputs: [
        {
          doc_level_input: {
            description: 'PowerShell invoked with an encoded command argument.',
            indices: ['fosstlsoc-logs-*'],
            queries: [
              {
                id: 'suspicious_powershell_execution',
                name: 'suspicious_powershell_execution',
                query: '(process.name:"powershell.exe") AND (process.command_line:*\\-enc*)',
                tags: ['tlsoc', 'high'],
              },
            ],
          },
        },
      ],
      triggers: [
        {
          document_level_trigger: {
            name: 'Suspicious PowerShell execution matched',
            severity: '2',
            condition: {
              script: {
                source: 'query[name=suspicious_powershell_execution]',
                lang: 'painless',
              },
            },
          },
        },
      ],
    });
  });
});

describe('operator sync — every v1 operator compiles to BOTH targets', () => {
  const sample = (operator: DetectionOperator): Condition => {
    if (operator === 'is_one_of' || operator === 'is_not_one_of') {
      return { field: 'source.ip', operator, values: ['10.0.0.1', '10.0.0.2'] };
    }
    if (operator === 'exists' || operator === 'not_exists') {
      return { field: 'user.name', operator };
    }
    if (operator === 'gt' || operator === 'gte' || operator === 'lt' || operator === 'lte') {
      return { field: 'http.response.status_code', operator, value: 500 };
    }
    return { field: 'event.action', operator, value: 'logon' };
  };

  it.each([...ALL_DETECTION_OPERATORS])(
    'operator "%s" → Sigma + doc-level monitor both reference the field',
    (operator) => {
      const condition = sample(operator as DetectionOperator);
      const rule: RuleDefinition = {
        name: `op ${operator}`,
        severity: 'medium',
        index: 'fosstlsoc-logs-*',
        group: { logic: 'AND', conditions: [condition] },
      };
      const sigma = compileToSigma(rule);
      const monitor = compileToDocLevelMonitor(rule);
      expect(sigma).toContain(condition.field);
      expect(monitor.inputs[0].doc_level_input.queries[0].query).toContain(condition.field);
    }
  );
});
