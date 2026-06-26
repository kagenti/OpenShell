#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Generate the TLS-bridge CA and create the AuthBridge CA Secret in the tenant namespace:
#   - Secret  authbridge-ca  (tls.crt + tls.key, the forge CA the sidecar presents)
#
# The sidecar config ConfigMap (authbridge-sidecar-config) is rendered per-sandbox by
# 03-inject-authbridge.sh, which fills in the gateway endpoint + sandbox id. There is no
# credential Secret: with source: gateway the real token lives only in the OpenShell
# gateway and the sidecar fetches it as the sandbox.
#
# Env knobs:
#   NS      tenant namespace                     (default: team1)
#   CA_DIR  where the CA is generated/reused      (default: /tmp/authbridge-egress-ca)
set -euo pipefail

NS="${NS:-team1}"
CA_DIR="${CA_DIR:-/tmp/authbridge-egress-ca}"

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

# 2. CA Secret (apply = create-or-update)
kubectl create secret generic authbridge-ca -n "$NS" \
  --from-file=tls.crt="$CA_DIR/tls.crt" --from-file=tls.key="$CA_DIR/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Setup complete in namespace '$NS' (CA ready; 03-inject renders the sidecar config)."
