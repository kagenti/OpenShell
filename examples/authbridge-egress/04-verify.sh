#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Verify the AuthBridge integration end-to-end:
#   1. supervisor is in External mode
#   2. AuthBridge sidecar is listening
#   3. claude reaches the LLM through AuthBridge (credential injected)
#   4. the sandbox holds only the placeholder, never the real token
#   5. direct egress is blocked (containment)
#   6. the session API has parsed traffic
#
# Usage: 04-verify.sh <sandbox-name> [namespace]
set -u

SB="${1:?usage: 04-verify.sh <sandbox-name> [namespace]}"
NS="${2:-${NS:-team1}}"

# Run a command inside the sandbox; return stdout+stderr with the supervisor's
# seccomp debug lines stripped.
sbx() { openshell sandbox exec -n "$SB" -- "$@" 2>&1 | grep -av "seccomp"; }

echo "== 1. supervisor External mode =="
if kubectl logs "$SB" -n "$NS" -c agent 2>/dev/null | grep -q "External network mode enabled"; then
  echo "  PASS — External network mode enabled"
else
  echo "  FAIL — not in External mode"
fi

echo "== 2. AuthBridge listeners =="
ab=$(kubectl logs "$SB" -n "$NS" -c authbridge-proxy 2>/dev/null \
  | grep -E "tls-bridge enabled|forward-proxy|session API")
if [ -n "$ab" ]; then echo "$ab" | sed 's/^/  /'; else echo "  FAIL — no AuthBridge listeners"; fi

echo "== 3. claude -> LLM through AuthBridge =="
reply=$(sbx sh -c 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 claude --print "Reply with exactly: AUTHBRIDGE_OK"' | tail -1)
if [ "$reply" = "AUTHBRIDGE_OK" ]; then echo "  PASS — $reply"; else echo "  FAIL — got: '$reply'"; fi

echo "== 4. sandbox holds only the placeholder (NOT the real token) =="
tok=$(sbx printenv ANTHROPIC_AUTH_TOKEN | head -1)
case "$tok" in
  openshell:resolve:env:*) echo "  PASS — placeholder only: $tok" ;;
  *) echo "  FAIL — unexpected ANTHROPIC_AUTH_TOKEN value (real token exposed?)" ;;
esac

echo "== 5. egress containment (direct egress must be blocked) =="
rc=$(sbx sh -c 'for v in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy grpc_proxy; do unset $v; done; curl -sS --max-time 6 -k -o /dev/null https://1.1.1.1; echo "rc=$?"' | grep -o 'rc=[0-9]*' | head -1)
if [ "$rc" = "rc=0" ]; then echo "  FAIL — direct egress NOT blocked"; else echo "  PASS — direct egress blocked ($rc)"; fi

echo "== 6. session API (parsed traffic for abctl) =="
sessions=$(kubectl exec "$SB" -n "$NS" -c authbridge-proxy -- \
  wget -qO- http://127.0.0.1:9094/v1/sessions 2>/dev/null)
if [ -n "$sessions" ]; then echo "  $sessions"; else echo "  (no session API response)"; fi
