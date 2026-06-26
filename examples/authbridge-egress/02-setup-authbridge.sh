#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Generate the TLS-bridge CA and create the AuthBridge objects in the tenant namespace:
#   - Secret    authbridge-ca              (tls.crt + tls.key, the forge CA)
#   - ConfigMap authbridge-sidecar-config  (config.yaml in this directory)
#   - Secret    authbridge-cred            (the real LLM token; only if $LLM_TOKEN is set)
#
# Env knobs:
#   NS         tenant namespace                                   (default: team1)
#   CA_DIR     where the CA is generated/reused                   (default: /tmp/authbridge-egress-ca)
#   CONFIG     AuthBridge config file                             (default: ./config.yaml)
#   LLM_TOKEN  real LLM token. If set, the authbridge-cred Secret is created from it
#              (passed via a 0600 temp file, never on the command line). If unset,
#              the script prints the command for you to run yourself.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${NS:-team1}"
CA_DIR="${CA_DIR:-/tmp/authbridge-egress-ca}"
CONFIG="${CONFIG:-$SCRIPT_DIR/config.yaml}"

# 1. CA (idempotent — reuse if present so it stays consistent across re-runs)
if [ ! -f "$CA_DIR/tls.crt" ]; then
  mkdir -p "$CA_DIR"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CA_DIR/tls.key" -out "$CA_DIR/tls.crt" -days 30 \
    -subj "/CN=AuthBridge Demo CA/O=kagenti" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  echo "==> Generated CA at $CA_DIR"
else
  echo "==> Reusing existing CA at $CA_DIR"
fi

# 2. CA Secret + config ConfigMap (apply = create-or-update)
kubectl create secret generic authbridge-ca -n "$NS" \
  --from-file=tls.crt="$CA_DIR/tls.crt" --from-file=tls.key="$CA_DIR/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap authbridge-sidecar-config -n "$NS" \
  --from-file=config.yaml="$CONFIG" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Credential Secret (token kept out of the process args via a temp file)
if [ -n "${LLM_TOKEN:-}" ]; then
  tmp="$(mktemp)"; chmod 600 "$tmp"; printf '%s' "$LLM_TOKEN" > "$tmp"
  kubectl create secret generic authbridge-cred -n "$NS" \
    --from-file=ANTHROPIC_AUTH_TOKEN="$tmp" \
    --dry-run=client -o yaml | kubectl apply -f -
  rm -f "$tmp"
  echo "==> Created Secret authbridge-cred from \$LLM_TOKEN"
else
  echo "==> LLM_TOKEN not set — create the credential Secret yourself:"
  echo "      kubectl create secret generic authbridge-cred -n $NS \\"
  echo "        --from-literal=ANTHROPIC_AUTH_TOKEN='<your real LLM token>'"
fi

echo "==> Setup complete in namespace '$NS'."
