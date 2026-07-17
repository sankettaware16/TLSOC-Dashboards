/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLSOC Security Logs sample dataset — explicit ECS index mapping.
 * Every aggregation-bearing field is keyword/ip/long/geo_point on purpose: the whole point of
 * this dataset is exercising TLSOC detections/visualizations on CORRECTLY-typed security data
 * (the moodle test index is only partially ECS and stays untouched as the verification baseline).
 *
 * v2 (multi-source SIEM rewrite): extended with the full campus "estate" (observer.*), ingest-lag
 * fields (event.ingested/timestamp_source, ecs.version), and per-source-type fields (email, dns,
 * erp, rule/threat, source/destination bytes+AS) needed by the new generator (./generate_data.js).
 */

export const fieldMappings = {
  '@timestamp': { type: 'date' },
  message: { type: 'text' },
  ecs: {
    properties: {
      version: { type: 'keyword' },
    },
  },
  event: {
    properties: {
      module: { type: 'keyword' },
      dataset: { type: 'keyword' },
      kind: { type: 'keyword' },
      category: { type: 'keyword' },
      action: { type: 'keyword' },
      outcome: { type: 'keyword' },
      type: { type: 'keyword' },
      reason: { type: 'keyword' },
      severity: { type: 'long' },
      ingested: { type: 'date' },
      timestamp_source: { type: 'keyword' },
    },
  },
  observer: {
    properties: {
      org: { type: 'keyword' },
      dept: { type: 'keyword' },
      env: { type: 'keyword' },
      server: { type: 'keyword' },
      source_host: { type: 'keyword' },
      source_program: { type: 'keyword' },
      type: { type: 'keyword' },
      vendor: { type: 'keyword' },
      product: { type: 'keyword' },
    },
  },
  source: {
    properties: {
      ip: { type: 'ip' },
      port: { type: 'long' },
      bytes: { type: 'long' },
      geo: {
        properties: {
          country_iso_code: { type: 'keyword' },
          country_name: { type: 'keyword' },
          city_name: { type: 'keyword' },
          location: { type: 'geo_point' },
        },
      },
      as: {
        properties: {
          number: { type: 'long' },
          organization: {
            properties: {
              name: { type: 'keyword' },
            },
          },
        },
      },
    },
  },
  destination: {
    properties: {
      ip: { type: 'ip' },
      port: { type: 'long' },
      bytes: { type: 'long' },
    },
  },
  host: {
    properties: {
      name: { type: 'keyword' },
      risk_score: { type: 'float' },
    },
  },
  user: {
    properties: {
      name: { type: 'keyword' },
    },
  },
  url: {
    properties: {
      domain: { type: 'keyword' },
      path: { type: 'keyword' },
      query: { type: 'keyword' },
      original: {
        type: 'text',
        fields: { keyword: { type: 'keyword', ignore_above: 1024 } },
      },
    },
  },
  http: {
    properties: {
      request: {
        properties: {
          method: { type: 'keyword' },
          referrer: { type: 'keyword' },
        },
      },
      response: {
        properties: {
          status_code: { type: 'long' },
          body: {
            properties: {
              bytes: { type: 'long' },
            },
          },
        },
      },
    },
  },
  user_agent: {
    properties: {
      original: {
        type: 'text',
        fields: { keyword: { type: 'keyword', ignore_above: 1024 } },
      },
    },
  },
  network: {
    properties: {
      protocol: { type: 'keyword' },
      transport: { type: 'keyword' },
    },
  },
  process: {
    properties: {
      name: { type: 'keyword' },
    },
  },
  rule: {
    properties: {
      id: { type: 'keyword' },
      name: { type: 'keyword' },
      ruleset: { type: 'keyword' },
      category: { type: 'keyword' },
    },
  },
  threat: {
    properties: {
      name: { type: 'keyword' },
    },
  },
  email: {
    properties: {
      from: {
        properties: {
          address: { type: 'keyword' },
        },
      },
      to: {
        properties: {
          address: { type: 'keyword' },
        },
      },
      sender_domain: { type: 'keyword' },
      recipient_domain: { type: 'keyword' },
      message_id: { type: 'keyword' },
    },
  },
  dns: {
    properties: {
      question: {
        properties: {
          name: { type: 'keyword' },
          type: { type: 'keyword' },
        },
      },
      response_code: { type: 'keyword' },
    },
  },
  erp: {
    properties: {
      module: { type: 'keyword' },
      txn_id: { type: 'keyword' },
      record_id: { type: 'keyword' },
      amount: { type: 'double' },
    },
  },
  tlsoc: {
    properties: {
      story: { type: 'keyword' },
    },
  },
};
