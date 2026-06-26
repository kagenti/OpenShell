#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Patch a sandbox's podTemplate to route its egress through the AuthBridge sidecar
# (NetworkMode::External), then recreate the pod. Run AFTER 01/02 and after creating
# a provider-bound sandbox (openshell sandbox create --provider <p> -- sleep infinity).
#
# The sidecar uses the placeholder-resolve plugin's `gateway` source: it authenticates
# to the OpenShell gateway AS the sandbox (mounting the pod's projected SA token, and —
# for an https:// gateway — the same client mTLS cert + CA the supervisor uses) and
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

POD_JSON=$(kubectl get pod "$SB" -n "$NS" -o json 2>/dev/null || true)
if [ -z "$POD_JSON" ]; then
  echo "ERROR: pod '$SB' not found in namespace '$NS'. Create the sandbox first." >&2
  exit 1
fi
penv() { echo "$POD_JSON" | jq -r --arg n "$1" '.spec.containers[0].env[]|select(.name==$n)|.value // empty'; }

# --- The sandbox's gateway identity, read from the running supervisor (driver-injected) ---
ENDPOINT=$(penv OPENSHELL_ENDPOINT)
SBID=$(penv OPENSHELL_SANDBOX_ID)
if [ -z "$ENDPOINT" ] || [ -z "$SBID" ]; then
  echo "ERROR: could not read OPENSHELL_ENDPOINT / OPENSHELL_SANDBOX_ID from pod '$SB'." >&2
  exit 1
fi
# Scheme decides transport: https:// -> mTLS (client cert + CA); else plaintext.
case "$ENDPOINT" in
  https://*) MTLS=1; INSECURE=false ;;
  *)         MTLS=0; INSECURE=true  ;;
esac
echo "==> Gateway: endpoint=$ENDPOINT  sandbox_id=$SBID  $([ "$MTLS" = 1 ] && echo '(mTLS)' || echo '(plaintext)')"

# The SA token (gateway bootstrap) is a pod-level volume the driver always injects.
case " $(echo "$POD_JSON" | jq -r '.spec.volumes[].name' | tr '\n' ' ') " in
  *" openshell-sa-token "*) ;;
  *) echo "ERROR: pod '$SB' has no 'openshell-sa-token' volume; the sidecar cannot authenticate to the gateway." >&2; exit 1 ;;
esac

# --- For an https:// gateway, combine the supervisor's client cert/key + CA into one dir ---
# The plugin's gateway client loads tls.crt/tls.key/ca.crt from a single mtls_cert_dir, but
# the driver splits them (OPENSHELL_TLS_CERT/KEY vs OPENSHELL_TLS_CA). Build a projected volume
# from the same Secrets the supervisor mounts, remapped into /etc/authbridge-gw-tls.
TLS_MOUNT=""        # extra sidecar volumeMount (leading comma) on the mTLS path
TLS_VOLUME_OP=""    # extra podTemplate volume patch op (leading comma) on the mTLS path
if [ "$MTLS" = 1 ]; then
  TLS_CERT=$(penv OPENSHELL_TLS_CERT); TLS_KEY=$(penv OPENSHELL_TLS_KEY); TLS_CA=$(penv OPENSHELL_TLS_CA)
  if [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ] || [ -z "$TLS_CA" ]; then
    echo "ERROR: https:// gateway but OPENSHELL_TLS_CERT/KEY/CA are not all set on the supervisor." >&2
    exit 1
  fi
  CERT_DIR=$(dirname "$TLS_CERT"); CA_DIR=$(dirname "$TLS_CA")
  CERT_KEY=$(basename "$TLS_CERT"); KEY_KEY=$(basename "$TLS_KEY"); CA_KEY=$(basename "$TLS_CA")
  vol_at() { echo "$POD_JSON" | jq -r --arg d "$1" '.spec.containers[0].volumeMounts[]|select(.mountPath==$d)|.name' | head -1; }
  secret_of() { echo "$POD_JSON" | jq -r --arg v "$1" '.spec.volumes[]|select(.name==$v)|.secret.secretName // empty'; }
  CERT_SECRET=$(secret_of "$(vol_at "$CERT_DIR")"); CA_SECRET=$(secret_of "$(vol_at "$CA_DIR")")
  if [ -z "$CERT_SECRET" ] || [ -z "$CA_SECRET" ]; then
    echo "ERROR: could not resolve the gateway client-cert / CA Secrets backing $CERT_DIR and $CA_DIR." >&2
    exit 1
  fi
  echo "    mTLS: client cert from Secret '$CERT_SECRET', CA from Secret '$CA_SECRET' -> /etc/authbridge-gw-tls"
  TLS_MOUNT=',{"name":"authbridge-gw-tls","mountPath":"/etc/authbridge-gw-tls","readOnly":true}'
  TLS_VOLUME_OP=$(cat <<JSON
,{"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-gw-tls","projected":{"sources":[
  {"secret":{"name":"${CERT_SECRET}","items":[{"key":"${CERT_KEY}","path":"tls.crt"},{"key":"${KEY_KEY}","path":"tls.key"}]}},
  {"secret":{"name":"${CA_SECRET}","items":[{"key":"${CA_KEY}","path":"ca.crt"}]}}
]}}}
JSON
)
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
IDX=$(echo "$POD_JSON" | jq '.spec.containers[0].env | map(.name) | index("ANTHROPIC_BASE_URL")')
if [ "$IDX" = "null" ] || [ -z "$IDX" ]; then
  echo "ERROR: ANTHROPIC_BASE_URL not found in the agent container env." >&2
  exit 1
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
    "securityContext":{"runAsUser":0},
    "args":["--config","/etc/authbridge/config.yaml"],
    "volumeMounts":[
      {"name":"authbridge-sidecar-config","mountPath":"/etc/authbridge","readOnly":true},
      {"name":"authbridge-ca","mountPath":"/etc/authbridge-ca","readOnly":true},
      {"name":"openshell-sa-token","mountPath":"/var/run/secrets/openshell","readOnly":true}${TLS_MOUNT}
    ]
  }},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-sidecar-config","configMap":{"name":"authbridge-sidecar-config"}}},
  {"op":"add","path":"/spec/podTemplate/spec/volumes/-","value":{"name":"authbridge-ca","secret":{"secretName":"authbridge-ca"}}}${TLS_VOLUME_OP}
]
JSON
)"
# The openshell-sa-token volume is injected by the OpenShell k8s driver at pod build, so the
# sidecar mounts it without re-declaring it. authbridge-gw-tls (mTLS only) is a new projected
# volume this script adds, combining the supervisor's client cert/key + CA into one dir.

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
