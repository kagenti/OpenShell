#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Patch a sandbox's podTemplate to route its egress through the AuthBridge sidecar
# (NetworkMode::External), then recreate the pod. Run AFTER 01/02 and after creating
# a provider-bound sandbox (openshell sandbox create --provider <p> -- sleep infinity).
#
# The sidecar uses the placeholder-resolve plugin's `gateway` source: it authenticates
# to the OpenShell gateway AS the sandbox (mounting the pod's projected SA token) and
# fetches the real credential, then substitutes it for the openshell:resolve:env:<KEY>
# placeholder. No mounted credential Secret — the real token lives only in the gateway.
#
# Usage:   03-inject-authbridge.sh <sandbox-name> <llm-url> [namespace]
# Example: 03-inject-authbridge.sh authbridge-egress https://my-litellm.example.com team1
#
# Env knobs:
#   AUTHBRIDGE_IMAGE  sidecar image (default: localhost/authbridge-proxy:dev)
set -euo pipefail

SB="${1:?usage: 03-inject-authbridge.sh <sandbox-name> <llm-url> [namespace]}"
LLM_URL="${2:?usage: 03-inject-authbridge.sh <sandbox-name> <llm-url> [namespace]}"
NS="${3:-${NS:-team1}}"
AUTHBRIDGE_IMAGE="${AUTHBRIDGE_IMAGE:-localhost/authbridge-proxy:dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Read the sandbox's gateway identity from the running pod (driver-injected) ---
echo "==> Reading the gateway endpoint + sandbox id from pod '$SB'..."
ENDPOINT=$(kubectl get pod "$SB" -n "$NS" -o jsonpath='{.spec.containers[0].env[?(@.name=="OPENSHELL_ENDPOINT")].value}' 2>/dev/null || true)
SBID=$(kubectl get pod "$SB" -n "$NS" -o jsonpath='{.spec.containers[0].env[?(@.name=="OPENSHELL_SANDBOX_ID")].value}' 2>/dev/null || true)
if [ -z "$ENDPOINT" ] || [ -z "$SBID" ]; then
  echo "ERROR: could not read OPENSHELL_ENDPOINT / OPENSHELL_SANDBOX_ID from pod '$SB'." >&2
  echo "       Is the sandbox running? (openshell sandbox create --provider <p> -- sleep infinity)" >&2
  exit 1
fi
# Scheme decides transport: https:// -> mTLS (needs the client-tls volume); else plaintext.
case "$ENDPOINT" in
  https://*) MTLS=1; INSECURE=false ;;
  *)         MTLS=0; INSECURE=true  ;;
esac
echo "    endpoint=$ENDPOINT  sandbox_id=$SBID  $([ "$MTLS" = 1 ] && echo '(mTLS)' || echo '(plaintext)')"

# --- The sidecar mounts the same pod-level gateway-identity volumes the driver injects ---
VOLS=$(kubectl get pod "$SB" -n "$NS" -o jsonpath='{.spec.volumes[*].name}' 2>/dev/null || true)
case " $VOLS " in
  *" openshell-sa-token "*) ;;
  *) echo "ERROR: pod '$SB' has no 'openshell-sa-token' volume; the sidecar cannot authenticate to the gateway." >&2; exit 1 ;;
esac
if [ "$MTLS" = 1 ]; then
  case " $VOLS " in
    *" openshell-client-tls "*) ;;
    *) echo "ERROR: endpoint is https:// (mTLS) but pod '$SB' has no 'openshell-client-tls' volume." >&2
       echo "       The tenant gateway must be deployed with client mTLS enabled (client_tls_secret_name set)." >&2
       exit 1 ;;
  esac
fi

# --- Render the sidecar config from the template and (re)create the ConfigMap ---
echo "==> Rendering config.yaml + applying the authbridge-sidecar-config ConfigMap..."
RENDERED=$(mktemp); trap 'rm -f "$RENDERED"' EXIT
sed -e "s|__GATEWAY_ENDPOINT__|${ENDPOINT}|" \
    -e "s|__SANDBOX_ID__|${SBID}|" \
    -e "s|__INSECURE__|${INSECURE}|" \
    "$SCRIPT_DIR/config.yaml" > "$RENDERED"
kubectl create configmap authbridge-sidecar-config -n "$NS" \
  --from-file=config.yaml="$RENDERED" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- Discover the ANTHROPIC_BASE_URL env index (order is non-deterministic) ---
echo "==> Discovering the ANTHROPIC_BASE_URL env index..."
IDX=$(kubectl get sandbox "$SB" -n "$NS" -o json \
  | jq '.spec.podTemplate.spec.containers[0].env | map(.name) | index("ANTHROPIC_BASE_URL")')
if [ "$IDX" = "null" ] || [ -z "$IDX" ]; then
  echo "ERROR: ANTHROPIC_BASE_URL not found in the agent container env." >&2
  exit 1
fi

# mTLS certs mount is added only for https:// gateways (plaintext ignores mtls_cert_dir).
TLS_MOUNT=""
if [ "$MTLS" = 1 ]; then
  TLS_MOUNT=',{"name":"openshell-client-tls","mountPath":"/etc/openshell-tls/client","readOnly":true}'
fi

echo "==> Patching sandbox '$SB' (External mode + AuthBridge sidecar)..."
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
      {"name":"openshell-sa-token","mountPath":"/var/run/secrets/openshell","readOnly":true}${TLS_MOUNT}
    ]
  }},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-sidecar-config","configMap":{"name":"authbridge-sidecar-config"}}},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-ca","secret":{"secretName":"authbridge-ca"}}}
]
JSON
)"
# Note: the openshell-sa-token (and openshell-client-tls) volumes are injected by the
# OpenShell k8s driver at pod build, so the sidecar mounts them without re-declaring
# them here. If a recreated pod reports an unbound volume, this PoC isn't merging
# driver volumes — add those two volumes to /spec/podTemplate/spec/volumes above.

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
