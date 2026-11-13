#!/usr/bin/env bash
# Wazuh server health check - run on the Wazuh VM over SSH.
# Usage: sudo bash scripts/server-healthcheck.sh
set -u

echo "== Host =="
hostname
ip -4 -brief addr show | grep -v '^lo'

echo
echo "== Wazuh services =="
for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
  printf '%-18s %s\n' "$svc" "$(systemctl is-active "$svc")"
done

echo
echo "== Listening ports (22 SSH, 443 dashboard, 1514 agent data, 1515 enrollment) =="
ss -tlnp | grep -E ':(22|443|1514|1515)\b' || echo "None of the expected ports are listening"

echo
echo "== Host firewall =="
ufw status 2>/dev/null || echo "ufw not installed"

echo
echo "== Registered agents =="
/var/ossec/bin/agent_control -l 2>/dev/null || echo "agent_control not available (run with sudo)"

echo
echo "== Resources =="
free -h | head -2
df -h / | tail -1
