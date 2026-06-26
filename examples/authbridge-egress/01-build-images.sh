#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Build the External-capable supervisor image and the AuthBridge proxy image,
# then load both into the kind cluster.
#
# Env knobs (all optional except EXT_DIR):
#   EXT_DIR           kagenti-extensions checkout (feat/placeholder-resolve-plugin)   [required]
#   OPENSHELL_DIR     OpenShell checkout (default: repo root, derived from this script)
#   ARCH              target arch: arm64 | amd64                                       (default: arm64)
#   CLUSTER           kind cluster name                                                (default: kagenti)
#   SUPERVISOR_IMAGE  supervisor image tag    (default: localhost/openshell/supervisor:dev)
#   AUTHBRIDGE_IMAGE  authbridge image tag    (default: localhost/authbridge-proxy:dev)
#   OUT               build output dir (must be shared with the podman VM)            (default: $HOME/openshell-out)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSHELL_DIR="${OPENSHELL_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
EXT_DIR="${EXT_DIR:?set EXT_DIR to your kagenti-extensions checkout (feat/placeholder-resolve-plugin)}"
ARCH="${ARCH:-arm64}"
CLUSTER="${CLUSTER:-kagenti}"
SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE:-localhost/openshell/supervisor:dev}"
AUTHBRIDGE_IMAGE="${AUTHBRIDGE_IMAGE:-localhost/authbridge-proxy:dev}"
OUT="${OUT:-$HOME/openshell-out}"
GATEWAY_TAG="${GATEWAY_TAG:-mvp-v2-7784be8}"   # gateway image matching feat/authbridge-egress's base
case "$ARCH" in
  arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;;
  amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;;
  *) echo "unsupported ARCH '$ARCH' (use arm64 or amd64)" >&2; exit 1 ;;
esac

# The supporting commits are NOT merged to mainline — fail fast if the checkouts
# don't actually contain them, rather than silently building feature-less images.
if ! grep -rqs "OPENSHELL_EXTERNAL_PROXY" "$OPENSHELL_DIR/crates/openshell-sandbox/src/"; then
  echo "ERROR: $OPENSHELL_DIR has no NetworkMode::External." >&2
  echo "       Check out the OpenShell 'feat/authbridge-egress' branch, or set OPENSHELL_DIR." >&2
  exit 1
fi
if [ ! -d "$EXT_DIR/authbridge/authlib/plugins/placeholderresolve" ]; then
  echo "ERROR: $EXT_DIR has no placeholder-resolve plugin." >&2
  echo "       Check out the kagenti-extensions 'feat/placeholder-resolve-plugin' branch, or set EXT_DIR." >&2
  exit 1
fi

mkdir -p "$OUT"

echo "==> [1/4] Compiling the supervisor binary ($RUST_TARGET) in a builder container..."
podman run --rm \
  -v "$OPENSHELL_DIR":/src:ro -w /src \
  -v "$OUT":/out \
  -v openshell-cargo:/usr/local/cargo/registry \
  -v openshell-target:/target -e CARGO_TARGET_DIR=/target \
  docker.io/library/rust:1.95-bookworm bash -c "
    set -e
    rustup target add $RUST_TARGET
    apt-get update -qq && apt-get install -y -qq --no-install-recommends musl-tools >/dev/null
    cargo build --release --target $RUST_TARGET \
      -p openshell-sandbox --bin openshell-sandbox --features openshell-core/dev-settings
    cp /target/$RUST_TARGET/release/openshell-sandbox /out/openshell-sandbox"

echo "==> [2/4] Wrapping the binary in a scratch image: $SUPERVISOR_IMAGE"
printf 'FROM scratch\nCOPY --chmod=0550 openshell-sandbox /openshell-sandbox\nENTRYPOINT ["/openshell-sandbox"]\n' \
  > "$OUT/Dockerfile.supervisor"
podman build -t "$SUPERVISOR_IMAGE" -f "$OUT/Dockerfile.supervisor" "$OUT"

echo "==> [3/4] Building the AuthBridge proxy image: $AUTHBRIDGE_IMAGE"
podman build --platform "linux/$ARCH" -t "$AUTHBRIDGE_IMAGE" \
  -f "$EXT_DIR/authbridge/cmd/authbridge-proxy/Dockerfile" "$EXT_DIR/authbridge"

echo "==> [4/4] Loading both images into kind cluster '$CLUSTER'..."
for img in "$SUPERVISOR_IMAGE" "$AUTHBRIDGE_IMAGE"; do
  tar="$OUT/$(echo "$img" | tr '/:' '__').tar"
  podman save -o "$tar" "$img"
  KIND_EXPERIMENTAL_PROVIDER=podman kind load image-archive "$tar" --name "$CLUSTER"
done

cat <<EOF

==> Done. Both images are loaded into kind cluster '$CLUSTER':
      supervisor: $SUPERVISOR_IMAGE
      authbridge: $AUTHBRIDGE_IMAGE

    Next, point the tenant gateway at the supervisor image (Kagenti repo script).
    NOTE: also pin the gateway tag — feat/authbridge-egress is based on commit 7784be8,
    whose gateway image is '$GATEWAY_TAG'; the chart default (v0.0.56-rc.3) lacks the
    inference-scoped-provider-lookup fix and breaks 'openshell inference/provider'.
      scripts/openshell/deploy-tenant.sh team1 \\
        --set supervisorImage.repository=${SUPERVISOR_IMAGE%:*} \\
        --set supervisorImage.tag=${SUPERVISOR_IMAGE##*:} \\
        --set images.gateway.tag=$GATEWAY_TAG \\
        --set sandboxImagePullPolicy=Never
    (the gateway restart expires your CLI token — re-run 'openshell gateway login').
EOF
