/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  EuiTabbedContent,
  EuiSteps,
  EuiCodeBlock,
  EuiAccordion,
  EuiText,
  EuiSpacer,
  EuiCallOut,
  EuiBadge,
} from '@elastic/eui';

/**
 * The "onboard your first source" guide — authentic TLSOC agentless flow, drawn from the
 * TLSOCDockerDeploy (rsyslog + omkafka → Kafka) and foss-soc-engine (parser) docs. Reused by the
 * empty-state page AND the live cockpit's "add a source" info flyout. Agentless-only.
 *
 * Two things a SIEM owner onboards:
 *   1. an ENDPOINT — forward its logs to the collector,
 *   2. a new LOG-SOURCE TYPE — make sure the parsing engine understands it.
 */

const MANUAL_RSYSLOG = `# /etc/rsyslog.d/tlsoc_logfwd.conf   (validate:  sudo rsyslogd -N1)
module(load="imfile" mode="inotify")
module(load="omkafka")

template(name="KafkaProxyEnvelope" type="list") {
  constant(value="{\\"meta\\":{")
    constant(value="\\"org\\":\\"your_org\\",")
    constant(value="\\"dept\\":\\"your_dept\\",")
    constant(value="\\"env\\":\\"production\\",")
    constant(value="\\"server\\":\\"web_server_1\\",")
    constant(value="\\"source_host\\":\\"") property(name="hostname") constant(value="\\",")
    constant(value="\\"source_program\\":\\"") property(name="programname") constant(value="\\"")
  constant(value="},\\"raw\\":\\"") property(name="msg" format="json") constant(value="\\"}\\n")
}

ruleset(name="toKafka") {
  action(type="omkafka" topic="your_logs" broker=["<TLSOC-COLLECTOR-IP>:9094"]
         key="%programname%" template="KafkaProxyEnvelope"
         action.resumeRetryCount="-1")   # buffer + retry forever if broker is down
  stop
}

# one input() per log file — its Tag becomes the source_program
input(type="imfile" File="/var/log/nginx/access.log" Tag="nginx_access"
      ruleset="toKafka" reopenOnTruncate="on" freshStartTail="on")`;

const endpointSteps = [
  {
    title: 'Install the log forwarder on the endpoint',
    children: (
      <>
        <EuiText size="s">
          <p>
            TLSOC is <strong>agentless</strong> — you only add the standard rsyslog Kafka module.
            No software runs on your endpoints beyond the forwarder.
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiCodeBlock language="bash" fontSize="m" paddingSize="m" isCopyable>
          sudo apt install -y rsyslog-kafka
        </EuiCodeBlock>
      </>
    ),
  },
  {
    title: 'Run the one-command onboarding script',
    children: (
      <>
        <EuiText size="s">
          <p>
            It asks for org / department / environment / server-id, auto-discovers logs under{' '}
            <code>/var/log</code> (auth, nginx, apache, mail, ufw, auditd…), configures forwarding,
            and verifies delivery to Kafka for you.
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiCodeBlock language="bash" fontSize="m" paddingSize="m" isCopyable>
          {`curl -fsSL http://<TLSOC-COLLECTOR-IP>/tlsoc-onboard.sh -o tlsoc-onboard.sh\nsudo bash tlsoc-onboard.sh`}
        </EuiCodeBlock>
        <EuiSpacer size="s" />
        <EuiAccordion id="tlsoc-onboard-noninteractive" buttonContent="Non-interactive (scripted rollout)">
          <EuiSpacer size="s" />
          <EuiCodeBlock language="bash" fontSize="s" paddingSize="m" isCopyable>
            {`TLSOC_IP=<collector-ip> TLSOC_TOPIC=<topic> TLSOC_ORG=<org> TLSOC_DEPT=<dept> \\\n  TLSOC_ENV=production TLSOC_SERVERID=<server-id> sudo bash tlsoc-onboard.sh`}
          </EuiCodeBlock>
        </EuiAccordion>
        <EuiSpacer size="s" />
        <EuiAccordion id="tlsoc-onboard-manual" buttonContent="Advanced: configure rsyslog by hand">
          <EuiSpacer size="s" />
          <EuiText size="s">
            <p>
              Create <code>/etc/rsyslog.d/tlsoc_logfwd.conf</code> — set your org/dept/env/server,
              the Kafka topic, and the collector broker at <code>&lt;TLSOC-COLLECTOR-IP&gt;:9094</code>.
              Add one <code>input()</code> per log file; its <code>Tag</code> becomes the source program.
            </p>
          </EuiText>
          <EuiSpacer size="s" />
          <EuiCodeBlock language="text" fontSize="s" paddingSize="m" isCopyable overflowHeight={300}>
            {MANUAL_RSYSLOG}
          </EuiCodeBlock>
        </EuiAccordion>
      </>
    ),
  },
  {
    title: 'Restart the forwarder and confirm logs reach Kafka',
    children: (
      <>
        <EuiCodeBlock language="bash" fontSize="m" paddingSize="m" isCopyable>
          sudo rsyslogd -N1 &amp;&amp; sudo systemctl restart rsyslog
        </EuiCodeBlock>
        <EuiSpacer size="s" />
        <EuiText size="s">
          <p>On the collector, watch the topic receive events:</p>
        </EuiText>
        <EuiSpacer size="xs" />
        <EuiCodeBlock language="bash" fontSize="s" paddingSize="m" isCopyable>
          {`docker exec -it kafka /opt/kafka/bin/kafka-console-consumer.sh \\\n  --bootstrap-server kafka:9092 --topic <topic>`}
        </EuiCodeBlock>
      </>
    ),
  },
];

const parserSteps = [
  {
    title: 'Common log types work out of the box',
    children: (
      <EuiText size="s">
        <p>
          The FOSS SOC Engine ships parsers for common sources — nginx, apache, sshd/auth, postfix,
          ModSecurity, Suricata and more. If your source is one of these, it is normalized to ECS
          automatically and will appear in the cockpit. Only a brand-new/custom log type needs the
          steps below.
        </p>
      </EuiText>
    ),
  },
  {
    title: 'Point the new source at a parser',
    children: (
      <>
        <EuiText size="s">
          <p>
            Map the forwarder Tag (source_program) to a parsing rule in the engine's{' '}
            <code>config.yaml</code>:
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiCodeBlock language="yaml" fontSize="m" paddingSize="m" isCopyable>
          {`program_mapping:\n  my_new_source: "nginx_access"   # reuse an existing rule\n  modsec_audit:  "modsec"`}
        </EuiCodeBlock>
      </>
    ),
  },
  {
    title: 'Or generate a parser for a custom log',
    children: (
      <>
        <EuiText size="s">
          <p>
            No matching rule? Paste 5–20 raw log lines into the engine's AI master prompt (see
            <code> WRITING_RULES.md</code>), save the returned YAML as <code>rules/&lt;name&gt;.yaml</code>,
            then validate the ECS fields:
          </p>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiCodeBlock language="bash" fontSize="s" paddingSize="m" isCopyable>
          {`python3 ecs_helper.py check rules/<name>.yaml   # spell-checks fields\npython3 test_file.py sample.log AUTO           # dry-run parse`}
        </EuiCodeBlock>
      </>
    ),
  },
  {
    title: 'Reload the engine',
    children: (
      <EuiText size="s">
        <p>
          Rule edits hot-reload within ~10 seconds — no restart needed. To apply config changes:
        </p>
      </EuiText>
    ),
  },
];

interface OnboardingGuideProps {
  /** show the intro callout (empty-state) vs a tighter version (flyout) */
  withIntro?: boolean;
}

export const OnboardingGuide: React.FC<OnboardingGuideProps> = ({ withIntro = true }) => {
  const tabs = [
    {
      id: 'endpoint',
      name: 'Forward an endpoint',
      content: (
        <>
          <EuiSpacer size="m" />
          <EuiSteps steps={endpointSteps} titleSize="xs" />
        </>
      ),
    },
    {
      id: 'parser',
      name: 'Add a log-source parser',
      content: (
        <>
          <EuiSpacer size="m" />
          <EuiSteps steps={parserSteps} titleSize="xs" />
          <EuiCodeBlock language="bash" fontSize="m" paddingSize="m" isCopyable>
            sudo systemctl restart foss-soc
          </EuiCodeBlock>
        </>
      ),
    },
  ];

  return (
    <>
      {withIntro && (
        <>
          <EuiCallOut
            size="s"
            title="Two steps to see data: forward an endpoint's logs, and make sure its log type is parsed."
            iconType="namespace"
          />
          <EuiSpacer size="m" />
        </>
      )}
      <EuiTabbedContent tabs={tabs} initialSelectedTab={tabs[0]} />
      <EuiSpacer size="s" />
      <EuiText size="xs" color="subdued">
        <p>
          Pipeline: <EuiBadge color="hollow">Endpoint</EuiBadge> →{' '}
          <EuiBadge color="hollow">Kafka</EuiBadge> → <EuiBadge color="hollow">FOSS SOC Engine</EuiBadge> →{' '}
          <EuiBadge color="hollow">OpenSearch</EuiBadge> → <EuiBadge color="primary">TLSOC</EuiBadge>
        </p>
      </EuiText>
    </>
  );
};
