/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { classifySource, foldProgramsToTypes, SOURCE_TYPES, TYPE_QUERY_STRING } from './source_types';

describe('classifySource', () => {
  it('classifies the real TLSOC demo programs correctly', () => {
    expect(classifySource('nginx_app_moodle')).toBe('web-app');
    expect(classifySource('nginx_app_results')).toBe('web-app');
    expect(classifySource('apache_access')).toBe('web-app');
    expect(classifySource('web-proxy')).toBe('web-proxy');
    expect(classifySource('squid')).toBe('web-proxy');
    expect(classifySource('postfix')).toBe('mail');
    expect(classifySource('roundcube')).toBe('webmail');
    expect(classifySource('modsecurity')).toBe('waf');
    expect(classifySource('suricata')).toBe('ids');
    expect(classifySource('firewall')).toBe('firewall');
    expect(classifySource('fw-01')).toBe('firewall');
    expect(classifySource('sshd')).toBe('auth');
    expect(classifySource('pam')).toBe('auth');
    expect(classifySource('wazuh')).toBe('edr');
    expect(classifySource('erp_app')).toBe('erp');
    expect(classifySource('dns')).toBe('dns');
    expect(classifySource('unbound')).toBe('dns');
  });

  it('handles ambiguous ordering (webmail before mail, edr before auth)', () => {
    expect(classifySource('roundcube_webmail')).toBe('webmail'); // not mail
    expect(classifySource('wazuh-agent')).toBe('edr'); // not auth via generic
  });

  it('falls back to other and tolerates null/empty', () => {
    expect(classifySource('some_custom_app')).toBe('other');
    expect(classifySource('')).toBe('other');
    expect(classifySource(null)).toBe('other');
    expect(classifySource(undefined)).toBe('other');
  });
});

describe('foldProgramsToTypes', () => {
  it('sums events per type, counts sources, and collects other programs', () => {
    const { byType, otherPrograms } = foldProgramsToTypes([
      { program: 'nginx_app_moodle', events: 100, endpoints: 1 },
      { program: 'nginx_app_library', events: 60, endpoints: 1 },
      { program: 'squid', events: 200, endpoints: 3 },
      { program: 'sshd', events: 40, endpoints: 2 },
      { program: 'weird_custom', events: 5, endpoints: 1 },
    ]);
    const webApp = byType.find((t) => t.type === 'web-app')!;
    expect(webApp.events).toBe(160);
    expect(webApp.sources).toBe(2);
    expect(webApp.endpoints).toBe(2);
    // sorted by events desc → web-proxy (200) first
    expect(byType[0].type).toBe('web-proxy');
    expect(otherPrograms).toEqual(['weird_custom']);
  });

  it('produces an empty result for no input', () => {
    expect(foldProgramsToTypes([]).byType).toEqual([]);
  });
});

describe('TYPE_QUERY_STRING', () => {
  it('has a pattern for every non-other type', () => {
    SOURCE_TYPES.filter((t) => t !== 'other').forEach((t) => {
      expect(typeof (TYPE_QUERY_STRING as Record<string, string>)[t]).toBe('string');
    });
  });
});
