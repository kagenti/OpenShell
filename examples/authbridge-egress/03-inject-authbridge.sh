#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Patch a sandbox's podTemplate to route its egress through the AuthBridge sidecar
# (NetworkMode::External), then recreate the pod. Run AFTER 01/02 and after creating
# a provider-bound sandbox (openshell sandbox create --provider <p> -- sleep infinity).
#
# Usage:   03-inject-authbridge.sh <sandbox-name> <llm-url> [namespace]
# Example: 03-inject-authbridge.sh settling-blesbok https://my-litellm.example.com team1
#
# Env knobs:
#   AUTHBRIDGE_IMAGE  sidecar image (default: localhost/authbridge-proxy:dev)
set -euo pipefail

SB="${1:?usage: 03-inject-authbridge.sh <sandbox-name> <llm-url> [namespace]}"
LLM_URL="${2:?usage: 03-inject-authbridge.sh <sandbox-name> <llm-url> [namespace]}"
NS="${3:-${NS:-team1}}"
AUTHBRIDGE_IMAGE="${AUTHBRIDGE_IMAGE:-localhost/authbridge-proxy:dev}"

echo "==> Discovering the ANTHROPIC_BASE_URL env index (order is non-deterministic)..."
IDX=$(kubectl get sandbox "$SB" -n "$NS" -o json \
  | jq '.spec.podTemplate.spec.containers[0].env | map(.name) | index("ANTHROPIC_BASE_URL")')
if [ "$IDX" = "null" ] || [ -z "$IDX" ]; then
  echo "ERROR: ANTHROPIC_BASE_URL not found in the agent container env." >&2
  exit 1
fi

echo "==> Reading the provider's revision-keyed credential placeholder..."
KEY=$(openshell sandbox exec -n "$SB" -- printenv ANTHROPIC_AUTH_TOKEN 2>/dev/null \
  | grep -o 'openshell:resolve:env:[^[:space:]]*' | sed 's/openshell:resolve:env://' | head -1)
if [ -z "$KEY" ]; then
  echo "ERROR: could not read the ANTHROPIC_AUTH_TOKEN placeholder." >&2
  echo "       Is the sandbox provider-bound (created with --provider ...)?" >&2
  exit 1
fi
echo "    placeholder key: $KEY"

echo "==> Patching sandbox '$SB' (External mode + AuthBridge sidecar + volumes)..."
kubectl patch sandbox "$SB" -n "$NS" --type=json -p "$(cat <<JSON
[
  {"op":"replace","path":"/spec/podTemplate/spec/containers/0/env/${IDX}/value","value":"${LLM_URL}"},
  {"op":"add","path":"/spec/podTemplate/spec/containers/0/env/-","value":{"name":"OPENSHELL_EXTERNAL_PROXY","value":"10.200.0.1:3128"}},
  {"op":"add","path":"/spec/podTemplate/spec/containers/0/env/-","value":{"name":"OPENSHELL_EXTERNAL_CA","value":"/etc/authbridge-ext-ca/tls.crt"}},
  {"op":"add","path":"/spec/podTemplate/spec/containers/0/volumeMounts/-","value":{"name":"authbridge-ca","mountPath":"/etc/authbridge-ext-ca","readOnly":true}},
  {"op":"add","path":"/spec/podTemplate/spec/containers/-","value":{
    "name":"authbridge-proxy",
    "image":"${AUTHBRIDGE_IMAGE}",
    "imagePullPolicy":"Never",
    "args":["--config","/etc/authbridge/config.yaml"],
    "volumeMounts":[
      {"name":"authbridge-sidecar-config","mountPath":"/etc/authbridge","readOnly":true},
      {"name":"authbridge-ca","mountPath":"/etc/authbridge-ca","readOnly":true},
      {"name":"authbridge-cred","mountPath":"/etc/authbridge-cred","readOnly":true}
    ]
  }},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-sidecar-config","configMap":{"name":"authbridge-sidecar-config"}}},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-ca","secret":{"secretName":"authbridge-ca"}}},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-cred","secret":{"secretName":"authbridge-cred","items":[{"key":"ANTHROPIC_AUTH_TOKEN","path":"${KEY}"}]}}}
]
JSON
)"

echo "==> Recreating the pod (force-delete; the supervisor's SIGTERM teardown is slow)..."
kubectl delete pod "$SB" -n "$NS" --grace-period=0 --force >/dev/null 2>&1 || true

echo "==> Waiting for the recreated pod to be 2/2 Ready..."
for _ in $(seq 1 90); do
  ready=$(kubectl get pod "$SB" -n "$NS" -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null || true)
  if [ "$ready" = "true true" ]; then
    echo "    ready: $(kubectl get pod "$SB" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" "}{end}')"
    echo "==> Done. Verify with: ./04-verify.sh $SB $NS"
    exit 0
  fi
  sleep 2
done

echo "ERROR: pod did not reach 2/2 Ready in time; check 'kubectl describe pod $SB -n $NS'." >&2
exit 1
