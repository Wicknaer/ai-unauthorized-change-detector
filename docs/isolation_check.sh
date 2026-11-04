#!/usr/bin/env bash
# Checks that the lab matches the isolation requirements (Section 8, SR-02, SR-03).
# Run from the repository root after `docker compose -f docker/docker-compose.yml up -d`.
set -u
DC="docker compose -f docker/docker-compose.yml"
pass=0; fail=0

check() { # check <description> <expected: ok|fail> <service> <command...>
  local desc="$1" expect="$2" svc="$3"; shift 3
  if $DC exec -T "$svc" sh -c "$*" >/dev/null 2>&1; then got=ok; else got=fail; fi
  if [ "$got" = "$expect" ]; then
    printf '  PASS  %-60s (%s)\n' "$desc" "$got"; pass=$((pass+1))
  else
    printf '  FAIL  %-60s (expected %s, got %s)\n' "$desc" "$expect" "$got"; fail=$((fail+1))
  fi
}

echo "Network: no internet access on the lab network"
for svc in ai-app agent attacker; do
  check "$svc cannot reach the internet" fail "$svc" \
    "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 443), 3)' 2>/dev/null || (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null"
done

echo "Volumes"
check "agent cannot write ai-data (read-only, SR-03)" fail agent "touch /data/models/.probe"
check "agent can write its own state" ok agent "touch /var/lib/fimagent/.probe && rm /var/lib/fimagent/.probe"
check "ai-app has no agent-state mount (SR-02)" fail ai-app "test -e /var/lib/fimagent/baseline.json"
check "attacker has no agent-state mount (SR-02)" fail attacker "test -e /var/lib/fimagent/baseline.json"
check "attacker can write ai-data (threat model)" ok attacker "touch /data/models/.probe && rm /data/models/.probe"

echo "Agent"
check "agent has a valid signed baseline" ok agent "fimagent status | grep -q 'signature OK'"

echo; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
