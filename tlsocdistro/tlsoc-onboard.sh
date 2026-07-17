#!/usr/bin/env bash
###############################################################################
# TLSOC Agentless Log Onboarding  (rsyslog + omkafka  →  Kafka)
#
#   Run on ANY Ubuntu/Linux server you want to forward logs from.
#
#   One command:
#     bash <(curl -fsSL https://raw.githubusercontent.com/sankettaware16/TLSOCDockerDeploy/main/tlsoc-onboard.sh)
#   or:
#     curl -fsSL <url> -o tlsoc-onboard.sh && sudo bash tlsoc-onboard.sh
#
#   What it does, with NO manual editing:
#     1. Installs the omkafka module (rsyslog-kafka) if missing
#     2. Asks for the TLSOC server IP  and TCP-tests port 9094 before continuing
#     3. Asks for the Kafka topic + envelope metadata (org/dept/env/server id)
#     4. Auto-discovers common /var/log sources (auth, kern, ufw, dpkg, apt,
#        nginx, apache, mail, fail2ban, auditd ...), skipping binary/rotated files
#     5. Lets you drop any auto-picked source, and add custom log paths
#        (each custom path is verified to exist AND be readable first)
#     6. Warns about anything the rsyslog user cannot read (permissions)
#     7. Generates a HARDENED config (see "why" notes inside the file):
#          ruleset="toKafka"      -> lines go straight to Kafka, never swallowed
#          reopenOnTruncate="on"  -> survives copytruncate log rotation
#          freshStartTail="on"    -> no multi-GB replay burst on first start
#          persistStateInterval   -> crash-safe read offsets
#          mode="inotify"         -> follows rename-style rotation
#     8. Ensures global maxMessageSize is large enough (long URLs/UA strings)
#     9. Validates config (rsyslogd -N1) BEFORE restarting  (never breaks logging)
#    10. Restarts, then verifies: broker TCP established + no omkafka errors,
#        writes a unique marker, and prints the ONE reliable command to confirm
#        arrival on the TLSOC server.
#
#   Non-interactive mode (optional): pre-set any of these env vars to skip prompts
#     TLSOC_IP=10.0.0.5 TLSOC_TOPIC=cse_logs TLSOC_ORG=iitb TLSOC_DEPT=cse \
#     TLSOC_ENV=production TLSOC_SERVERID=web1 bash tlsoc-onboard.sh
###############################################################################

set -uo pipefail

# ---------- pretty output ----------
if [ -t 1 ]; then
  B=$'\e[1m'; R=$'\e[0m'; GRN=$'\e[32m'; YLW=$'\e[33m'; RED=$'\e[31m'; CYN=$'\e[36m'
else
  B=""; R=""; GRN=""; YLW=""; RED=""; CYN=""
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s[*]%s %s\n' "$CYN" "$R" "$*"; }
ok()   { printf '%s[OK]%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '%s[!]%s %s\n'  "$YLW" "$R" "$*"; }
die()  { printf '%s[X]%s %s\n'  "$RED" "$R" "$*" >&2; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------"; }

# read that works even under  bash <(curl ...)  by reading the terminal directly
TTY=/dev/tty
ask() { # ask "Prompt" VARNAME "default"
  local prompt="$1" __var="$2" def="${3:-}" ans=""
  if [ -n "$def" ]; then prompt="$prompt [$def]"; fi
  printf '%s%s:%s ' "$B" "$prompt" "$R" > "$TTY"
  IFS= read -r ans < "$TTY" || true
  [ -z "$ans" ] && ans="$def"
  printf -v "$__var" '%s' "$ans"
}

CONF=/etc/rsyslog.d/tlsoc_logfwd.conf
MAINCONF=/etc/rsyslog.conf
RSYSLOG_USER="syslog"   # this stack drops privileges to 'syslog' (see main rsyslog.conf)

hr; say "${B}TLSOC Agentless Log Onboarding${R}"; hr

# ---------- 0. root ----------
[ "$(id -u)" -eq 0 ] || die "Please run as root:  sudo bash $0"

# ---------- 1. OS sanity ----------
if [ -r /etc/os-release ]; then . /etc/os-release; info "Detected: ${PRETTY_NAME:-unknown}"; fi
command -v rsyslogd >/dev/null 2>&1 || die "rsyslog is not installed. Install it first: apt install -y rsyslog"

# ---------- 2. ensure omkafka (rsyslog-kafka) ----------
if rsyslogd -N1 2>&1 | grep -qi "could not load module.*omkafka" \
   || ! find /usr/lib*/rsyslog /lib*/rsyslog -name 'omkafka.so' 2>/dev/null | grep -q . ; then
  info "omkafka module not found — installing rsyslog-kafka ..."
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog-kafka >/dev/null 2>&1 \
      || die "Failed to install rsyslog-kafka. Install it manually and re-run."
    ok "rsyslog-kafka installed."
  else
    die "omkafka missing and this isn't apt-based. Install the rsyslog kafka module manually."
  fi
else
  ok "omkafka module present."
fi

# ---------- 3. TLSOC server IP + reachability ----------
TLSOC_IP="${TLSOC_IP:-}"
while :; do
  [ -z "$TLSOC_IP" ] && ask "TLSOC server IP (Kafka broker)" TLSOC_IP
  [ -z "$TLSOC_IP" ] && { warn "IP required."; continue; }
  info "Testing TCP connectivity to ${TLSOC_IP}:9094 ..."
  if timeout 4 bash -c ">/dev/tcp/${TLSOC_IP}/9094" 2>/dev/null; then
    ok "Reachable: ${TLSOC_IP}:9094 is open."
    break
  else
    warn "Could NOT open TCP ${TLSOC_IP}:9094."
    ping -c1 -W2 "$TLSOC_IP" >/dev/null 2>&1 && warn "(host pings, but port 9094 is closed/filtered — check firewall & that Kafka is up)" \
                                              || warn "(host does not even respond to ping)"
    local_retry=""; ask "Continue anyway? (y/N)" local_retry "N"
    case "$local_retry" in y|Y) break;; *) TLSOC_IP=""; ;; esac
  fi
done

# ---------- 4. topic + envelope metadata ----------
ask "Kafka topic name"                       TLSOC_TOPIC    "${TLSOC_TOPIC:-cse_logs}"
ask "Org identifier"                         TLSOC_ORG      "${TLSOC_ORG:-my_org}"
ask "Department"                             TLSOC_DEPT     "${TLSOC_DEPT:-general}"
ask "Environment (production/testing/dev)"   TLSOC_ENV      "${TLSOC_ENV:-production}"
ask "Unique server identifier"               TLSOC_SERVERID "${TLSOC_SERVERID:-$(hostname -s)}"

# ---------- 5. auto-discover candidate log sources ----------
# format: "path|tag|description"   (tags become source_program + must be unique)
CANDIDATES=(
  "/var/log/auth.log|auth|SSH / sudo / logins (high value)"
  "/var/log/kern.log|kern|Kernel messages"
  "/var/log/ufw.log|ufw|UFW firewall"
  "/var/log/dpkg.log|dpkg|Package install/remove"
  "/var/log/apt/history.log|apt_history|APT command history"
  "/var/log/fail2ban.log|fail2ban|Fail2ban bans"
  "/var/log/nginx/access.log|nginx_access|Nginx access"
  "/var/log/nginx/error.log|nginx_error|Nginx errors"
  "/var/log/apache2/access.log|apache_access|Apache access"
  "/var/log/apache2/error.log|apache_error|Apache errors"
  "/var/log/mail.log|mail|Mail / postfix"
  "/var/log/mysql/error.log|mysql_error|MySQL errors"
  "/var/log/audit/audit.log|auditd|auditd (needs root read)"
  "/var/log/syslog|syslog|Catch-all (LARGE, opt-in)"
)

is_text() { # returns 0 if file looks like text (avoid binary logs: wtmp/btmp/lastlog)
  local f="$1"
  [ -s "$f" ] || return 0                      # empty file: allow (will fill later)
  if command -v file >/dev/null 2>&1; then
    file -b --mime-encoding "$f" 2>/dev/null | grep -qiv binary && return 0 || return 1
  fi
  return 0
}

declare -a SEL_PATH SEL_TAG SEL_DESC
info "Scanning /var/log for known sources ..."
for entry in "${CANDIDATES[@]}"; do
  p="${entry%%|*}"; rest="${entry#*|}"; t="${rest%%|*}"; d="${rest#*|}"
  [ -f "$p" ] || continue
  if ! is_text "$p"; then warn "Skipping $p (binary)"; continue; fi
  SEL_PATH+=("$p"); SEL_TAG+=("$t"); SEL_DESC+=("$d")
done

if [ "${#SEL_PATH[@]}" -eq 0 ]; then
  warn "No known log files auto-discovered. You can still add custom paths next."
else
  hr; say "${B}Auto-discovered sources:${R}"
  for i in "${!SEL_PATH[@]}"; do
    # readability check as the rsyslog user
    rd="ok"; sudo -u "$RSYSLOG_USER" test -r "${SEL_PATH[$i]}" 2>/dev/null || rd="NO-READ"
    if [ "$rd" = "NO-READ" ]; then
      printf "  %s%2d)%s %-32s -> %-13s %s(user '%s' cannot read!)%s\n" \
        "$B" "$((i+1))" "$R" "${SEL_PATH[$i]}" "${SEL_TAG[$i]}" "$YLW" "$RSYSLOG_USER" "$R"
    else
      printf "  %s%2d)%s %-32s -> %-13s %s\n" \
        "$B" "$((i+1))" "$R" "${SEL_PATH[$i]}" "${SEL_TAG[$i]}" "${SEL_DESC[$i]}"
    fi
  done
  hr
  REMOVE=""
  ask "Enter numbers to REMOVE (space-separated), or Enter to keep all" REMOVE ""
  if [ -n "$REMOVE" ]; then
    for n in $REMOVE; do
      idx=$((n-1))
      if [ "$idx" -ge 0 ] 2>/dev/null && [ "$idx" -lt "${#SEL_PATH[@]}" ]; then
        SEL_PATH[$idx]=""; SEL_TAG[$idx]=""
      fi
    done
  fi
fi

# ---------- 6. custom paths ----------
say ""; info "Add custom log paths (press Enter on an empty prompt to finish)."
while :; do
  CP=""; ask "Custom log path" CP ""
  [ -z "$CP" ] && break
  if [ ! -f "$CP" ]; then warn "Not found: $CP — skipped."; continue; fi
  if ! is_text "$CP"; then warn "$CP looks binary — skipped."; continue; fi
  CT=""; ask "  Tag/source_program for $CP" CT "$(basename "${CP%.*}" | tr -cs 'A-Za-z0-9' '_' )"
  sudo -u "$RSYSLOG_USER" test -r "$CP" 2>/dev/null || warn "  '$RSYSLOG_USER' cannot read $CP — fix perms or run rsyslog as root, or it won't ship."
  SEL_PATH+=("$CP"); SEL_TAG+=("$CT")
done

# collapse selections, ensure unique tags
declare -a F_PATH F_TAG; declare -A SEENTAG
for i in "${!SEL_PATH[@]}"; do
  p="${SEL_PATH[$i]}"; t="${SEL_TAG[$i]}"
  [ -z "$p" ] && continue
  t="$(printf '%s' "$t" | tr -cs 'A-Za-z0-9_' '_' )"          # sanitize
  base="$t"; k=2; while [ -n "${SEENTAG[$t]:-}" ]; do t="${base}_${k}"; k=$((k+1)); done
  SEENTAG[$t]=1
  F_PATH+=("$p"); F_TAG+=("$t")
done

[ "${#F_PATH[@]}" -gt 0 ] || die "No log sources selected. Nothing to onboard."

say ""; ok "Will forward ${#F_PATH[@]} source(s) to topic '${TLSOC_TOPIC}' at ${TLSOC_IP}:9094:"
for i in "${!F_PATH[@]}"; do printf "     %-34s  (source_program=%s)\n" "${F_PATH[$i]}" "${F_TAG[$i]}"; done
CONFIRM=""; ask "Proceed and write config? (Y/n)" CONFIRM "Y"
case "$CONFIRM" in n|N) die "Aborted by user.";; esac

# ---------- 7. backup existing conf ----------
if [ -f "$CONF" ]; then
  bak="${CONF}.bak.$(date +%Y%m%d_%H%M%S)"; cp -a "$CONF" "$bak"; ok "Backed up existing config -> $bak"
fi

# ---------- 8. write hardened config ----------
# NOTE: unquoted heredoc — ${VARS} expand, and \" sequences pass through literally
{
cat <<RSYSLOG_HEAD
############################################################
# TLSOC Log Forwarding  (auto-generated $(date -u +%FT%TZ))
# File: $CONF
# Regenerate with tlsoc-onboard.sh — manual edits may be overwritten.
#
# WHY THE RULESET (do not remove): imfile re-injects each line it reads back
# into the rsyslog engine. By default those lines traverse EVERY *.conf rule
# (e.g. 50-default.conf's *.* catch-all) and can be silently swallowed into
# /var/log/syslog BEFORE this forwarder runs. Binding each input to the private
# "toKafka" ruleset sends its lines STRAIGHT to Kafka and stops them.
############################################################

module(load="imfile" mode="inotify")
module(load="omkafka")

template(name="KafkaProxyEnvelope" type="list") {
  constant(value="{\"meta\":{")
    constant(value="\"org\":\"${TLSOC_ORG}\",")
    constant(value="\"dept\":\"${TLSOC_DEPT}\",")
    constant(value="\"env\":\"${TLSOC_ENV}\",")
    constant(value="\"server\":\"${TLSOC_SERVERID}\",")
    constant(value="\"source_host\":\"")
      property(name="hostname")
    constant(value="\",")
    constant(value="\"source_program\":\"")
      property(name="programname")
    constant(value="\",")
    constant(value="\"source_timestamp\":\"")
      property(name="timereported" dateFormat="rfc3339")
    constant(value="\"")
  constant(value="},\"raw\":\"")
    property(name="msg" format="json")
  constant(value="\"}\n")
}

ruleset(name="toKafka") {
  action(
    type="omkafka"
    topic="${TLSOC_TOPIC}"
    broker=["${TLSOC_IP}:9094"]
    key="%programname%"
    template="KafkaProxyEnvelope"
    confParam=[
      "compression.codec=snappy",
      "linger.ms=50",
      "batch.num.messages=1000"
    ]
    action.resumeRetryCount="-1"
  )
  stop
}

# ---- inputs ----
RSYSLOG_HEAD

for i in "${!F_PATH[@]}"; do
cat <<RSYSLOG_INPUT
input(type="imfile"
      File="${F_PATH[$i]}"
      Tag="${F_TAG[$i]}"
      Severity="info"
      Facility="local4"
      ruleset="toKafka"
      reopenOnTruncate="on"
      freshStartTail="on"
      persistStateInterval="200")

RSYSLOG_INPUT
done
} > "$CONF"
ok "Wrote $CONF"

# ---------- 9. ensure maxMessageSize is adequate (long access-log lines) ----------
if ! grep -qiE 'maxMessageSize' "$MAINCONF"; then
  warn "maxMessageSize not set in $MAINCONF (default 8k can truncate long URLs/UA)."
  FIXMSG=""; ask "Add global(maxMessageSize=\"64k\") to $MAINCONF? (Y/n)" FIXMSG "Y"
  case "$FIXMSG" in n|N) : ;; *) sed -i '1i global(maxMessageSize="64k")' "$MAINCONF"; ok "Added maxMessageSize=64k.";; esac
else
  ok "maxMessageSize already configured."
fi

# ---------- 9b. warn about RepeatedMsgReduction (silently drops repeat lines) ----------
if grep -qiE '^\s*\$RepeatedMsgReduction\s+on' "$MAINCONF"; then
  warn "\$RepeatedMsgReduction is ON in $MAINCONF — it collapses identical consecutive"
  warn "log lines into 'last message repeated N times', i.e. it DROPS real lines."
  warn "For a SOC feed you usually want every line. Consider setting it 'off'."
fi

# ---------- 10. validate BEFORE restart ----------
info "Validating configuration (rsyslogd -N1) ..."
if ! rsyslogd -N1 2>/tmp/tlsoc_rsyslog_validate.log; then
  cat /tmp/tlsoc_rsyslog_validate.log
  die "Config validation FAILED. Your previous logging is untouched (not restarted). Fix and re-run."
fi
grep -qiE 'error|warning' /tmp/tlsoc_rsyslog_validate.log && cat /tmp/tlsoc_rsyslog_validate.log
ok "Configuration is valid."

# ---------- 11. restart ----------
info "Restarting rsyslog ..."
systemctl restart rsyslog || die "rsyslog failed to restart. Check: journalctl -u rsyslog -n50"
sleep 3
systemctl is-active --quiet rsyslog && ok "rsyslog is running." || die "rsyslog is not active after restart."

# ---------- 12. client-side verification ----------
hr; say "${B}Verifying pipeline (client side)${R}"; hr

# 12a broker connection established?
if ss -tnp 2>/dev/null | grep -qE "${TLSOC_IP}:9094.*rsyslog"; then
  ok "TCP session to broker ${TLSOC_IP}:9094 is ESTABLISHED."
else
  warn "No established session to ${TLSOC_IP}:9094 yet (may connect on first message; recheck with: ss -tnp | grep 9094)."
fi

# 12b any omkafka errors?
if journalctl -u rsyslog --since "1 min ago" --no-pager 2>/dev/null | grep -iE 'omkafka|kafka.*(fail|error|suspend|unknown)'; then
  warn "^ omkafka reported issues above — review them."
else
  ok "No omkafka errors in the last minute."
fi

# 12c write a UNIQUE marker to the first source, then give the reliable server-side check
if command -v uuidgen >/dev/null 2>&1; then MARK="$(uuidgen)"; \
elif [ -r /proc/sys/kernel/random/uuid ]; then MARK="$(cat /proc/sys/kernel/random/uuid)"; \
else MARK="$(date +%s)-$RANDOM$RANDOM"; fi
MARKER="TLSOC-ONBOARD-VERIFY-${MARK}"
FIRST="${F_PATH[0]}"
printf '%s %s tlsoc_onboard: %s\n' "$(date -u +%FT%T+00:00)" "$(hostname -s)" "$MARKER" >> "$FIRST" 2>/dev/null \
  && ok "Wrote a unique marker into $FIRST" \
  || warn "Could not append marker to $FIRST (perms) — pick another source to test."

hr
say "${B}FINAL CONFIRMATION — run this ONE command on the TLSOC (Docker) server:${R}"
say ""
say "${GRN}  sudo docker exec tlsoc-kafka /opt/kafka/bin/kafka-console-consumer.sh \\"
say "    --bootstrap-server kafka:9092 --topic ${TLSOC_TOPIC} \\"
say "    --from-beginning --timeout-ms 15000 2>/dev/null | grep ${MARKER}${R}"
say ""
say "  If that prints a line containing the marker, end-to-end delivery is CONFIRMED."
say "  (We use --from-beginning + a unique grep on purpose: the plain live consumer"
say "   reads only NEW messages and can falsely show 'nothing'.)"
hr
ok "Onboarding complete. Config: $CONF"
say "  Sources forwarded:"
for i in "${!F_PATH[@]}"; do say "    - ${F_PATH[$i]}  (source_program=${F_TAG[$i]})"; done
say ""
say "  To add more later: re-run this script, or add another input() block bound to"
say "  ruleset=\"toKafka\" in $CONF and: sudo rsyslogd -N1 && sudo systemctl restart rsyslog"
