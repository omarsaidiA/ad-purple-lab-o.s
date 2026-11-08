#!/usr/bin/env bash
# Replay the test cases through a real Wazuh manager and check which rules fire.
#
#   detections/tests/run.sh [archives_output.json]
#
# Needs Docker and Python 3. Starts a throwaway wazuh-manager container, loads
# local_rules.xml, injects the events from cases.py and compares archives.json
# with the expected rule IDs. The container is removed at the end.
set -euo pipefail

WAZUH_IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.5}"
CONTAINER="ad-purple-lab-rules-$$"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
# Git Bash on Windows: give docker.exe Windows paths, and stop MSYS from
# rewriting the container paths (/var/ossec/...).
if command -v cygpath >/dev/null; then
  HERE="$(cygpath -m "$HERE")"
  WORK="$(cygpath -m "$WORK")"
  export MSYS_NO_PATHCONV=1
fi
RULES="$HERE/../wazuh/local_rules.xml"
OUT="${1:-$WORK/archives.json}"

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    # Keep the manager's own view of the failure before the container goes away.
    docker exec "$CONTAINER" tail -n 40 /var/ossec/logs/ossec.log 2>/dev/null \
      | sed 's/^/ossec.log: /' || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

python3 "$HERE/cases.py" build "$WORK"

docker run -d --name "$CONTAINER" "$WAZUH_IMAGE" >/dev/null
docker cp "$RULES" "$CONTAINER:/var/ossec/etc/rules/local_rules.xml"
docker cp "$HERE/inject.py" "$CONTAINER:/tmp/inject.py"
docker cp "$WORK/events.jsonl" "$CONTAINER:/tmp/events.jsonl"

docker exec "$CONTAINER" bash -c '
  set -e
  chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
  /var/ossec/bin/wazuh-analysisd -t
  # Archive every event (alert or not) so each case can be checked.
  sed -i "s|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|" /var/ossec/etc/ossec.conf
  # Wait for the first start of the image, then restart with the new config.
  for _ in $(seq 60); do [ -S /var/ossec/queue/sockets/queue ] && break; sleep 2; done
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
  for _ in $(seq 60); do
    /var/ossec/bin/wazuh-control status | grep -q "wazuh-analysisd is running" \
      && [ -S /var/ossec/queue/sockets/queue ] && break
    sleep 2
  done
  sleep 5
  : > /var/ossec/logs/archives/archives.json
  /var/ossec/framework/python/bin/python3 /tmp/inject.py /tmp/events.jsonl
  # Wait until every injected event is archived (slow CI runners need more
  # than a fixed sleep).
  expected=$(grep -c . /tmp/events.jsonl)
  for _ in $(seq 60); do
    got=$(grep -c "\"location\":\"EventChannel\"" /var/ossec/logs/archives/archives.json || true)
    [ "$got" -ge "$expected" ] && break
    sleep 2
  done
  # The last line can still be half-written: wait until the file stops growing.
  size=-1
  until [ "$size" = "$(stat -c %s /var/ossec/logs/archives/archives.json)" ]; do
    size=$(stat -c %s /var/ossec/logs/archives/archives.json)
    sleep 2
  done
  echo "archived $got/$expected events"
'
docker exec "$CONTAINER" cat /var/ossec/logs/archives/archives.json > "$OUT"
python3 "$HERE/cases.py" check "$OUT"
