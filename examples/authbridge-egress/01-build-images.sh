#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Build the External-capable supervisor image and the AuthBridge proxy image,
# load both into the kind cluster, and (optionally) point the tenant gateway at
# them with the gateway tag correctly pinned.
#
# Env knobs (all optional):
#   EXT_DIR           Local kagenti-extensions checkout (feat/placeholder-resolve-plugin).
#                     Used as-is if set; if unset, the script clones EXT_REPO @ EXT_REF.
#   EXT_REPO          Repo to clone the plugin from when EXT_DIR is unset
#                     (default: https://github.com/huang195/kagenti-extensions; switch to
#                      https://github.com/kagenti/kagenti-extensions once PR #626 merges).
#   EXT_REF           Branch/ref to clone (default: feat/placeholder-resolve-plugin; 'main' post-merge).
#   KAGENTI_DIR       kagenti repo checkout. If set, this script also runs
#                     deploy-tenant.sh to redeploy the gateway with the new
#                     supervisor image and the pinned gateway tag. If unset, it
#                     prints the deploy command for you to run.
#   OPENSHELL_DIR     OpenShell checkout (default: repo root, derived from this script)
#   NS                tenant namespace for the gateway redeploy                        (default: team1)
#   ARCH              target arch: arm64 | amd64                                       (default: arm64)
#   CLUSTER           kind cluster name                                                (default: kagenti)
#   GATEWAY_TAG       gateway image tag (must match this branch's base)   (default: mvp-v2-7784be8)
#   SUPERVISOR_IMAGE  supervisor image tag    (default: localhost/openshell/supervisor:dev)
#   AUTHBRIDGE_IMAGE  authbridge image tag    (default: localhost/authbridge-proxy:dev)
#   OUT               build output dir (must be shared with the podman VM)            (default: $HOME/openshell-out)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSHELL_DIR="${OPENSHELL_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
EXT_DIR="${EXT_DIR:-}"
EXT_REPO="${EXT_REPO:-https://github.com/huang195/kagenti-extensions}"
EXT_REF="${EXT_REF:-feat/placeholder-resolve-plugin}"
ARCH="${ARCH:-arm64}"
CLUSTER="${CLUSTER:-kagenti}"
NS="${NS:-team1}"
SUPERVISOR_IMAGE="${SUPERVISOR_IMAGE:-localhost/openshell/supervisor:dev}"
AUTHBRIDGE_IMAGE="${AUTHBRIDGE_IMAGE:-localhost/authbridge-proxy:dev}"
OUT="${OUT:-$HOME/openshell-out}"
GATEWAY_TAG="${GATEWAY_TAG:-mvp-v2-7784be8}"   # gateway image matching feat/authbridge-egress's base
case "$ARCH" in
  arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;;
  amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;;
  *) echo "unsupported ARCH '$ARCH' (use arm64 or amd64)" >&2; exit 1 ;;
esac

mkdir -p "$OUT"

# Resolve the kagenti-extensions source for the AuthBridge image: use EXT_DIR if
# given, otherwise clone EXT_REPO @ EXT_REF (the plugin is on an unmerged branch).
if [ -z "$EXT_DIR" ]; then
  EXT_DIR="$OUT/kagenti-extensions"
  if [ -d "$EXT_DIR/.git" ]; then
    echo "==> Updating $EXT_DIR ($EXT_REF from $EXT_REPO)..."
    git -C "$EXT_DIR" fetch --depth 1 "$EXT_REPO" "$EXT_REF" && git -C "$EXT_DIR" checkout -f FETCH_HEAD
  else
    echo "==> Cloning $EXT_REPO ($EXT_REF) -> $EXT_DIR..."
    git clone --depth 1 --branch "$EXT_REF" "$EXT_REPO" "$EXT_DIR"
  fi
fi

# The supporting commits are NOT merged to mainline — fail fast if the checkouts
# don't actually contain them, rather than silently building feature-less images.
if ! grep -rqs "OPENSHELL_EXTERNAL_PROXY" "$OPENSHELL_DIR/crates/openshell-sandbox/src/"; then
  echo "ERROR: $OPENSHELL_DIR has no NetworkMode::External." >&2
  echo "       Check out the OpenShell 'feat/authbridge-egress' branch, or set OPENSHELL_DIR." >&2
  exit 1
fi
if [ ! -d "$EXT_DIR/authbridge/authlib/plugins/placeholderresolve" ]; then
  echo "ERROR: $EXT_DIR has no placeholder-resolve plugin." >&2
  echo "       Check EXT_REPO/EXT_REF, or point EXT_DIR at a checkout that has it." >&2
  exit 1
fi

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

echo
echo "==> Images loaded into kind '$CLUSTER':  supervisor=$SUPERVISOR_IMAGE  authbridge=$AUTHBRIDGE_IMAGE"

if [ -n "${KAGENTI_DIR:-}" ]; then
  echo "==> Redeploying the '$NS' gateway (supervisor=$SUPERVISOR_IMAGE, gateway pinned to $GATEWAY_TAG)..."
  "$KAGENTI_DIR/scripts/openshell/deploy-tenant.sh" "$NS" \
    --set supervisorImage.repository="${SUPERVISOR_IMAGE%:*}" \
    --set supervisorImage.tag="${SUPERVISOR_IMAGE##*:}" \
    --set images.gateway.tag="$GATEWAY_TAG" \
    --set sandboxImagePullPolicy=Never
  echo "==> Done. The gateway restart expired your CLI token — run:  openshell gateway login"
else
  cat <<EOF
==> Next, point the '$NS' gateway at these images. Set KAGENTI_DIR=<your kagenti repo>
    and re-run this script to do it automatically, or run it yourself. The gateway tag
    MUST be pinned to '$GATEWAY_TAG' — the chart default (v0.0.56-rc.3) predates the
    inference-scoped-provider-lookup fix and breaks 'openshell inference/provider':
      \$KAGENTI_DIR/scripts/openshell/deploy-tenant.sh $NS \\
        --set supervisorImage.repository=${SUPERVISOR_IMAGE%:*} \\
        --set supervisorImage.tag=${SUPERVISOR_IMAGE##*:} \\
        --set images.gateway.tag=$GATEWAY_TAG \\
        --set sandboxImagePullPolicy=Never
    Then re-run 'openshell gateway login' (the gateway restart expires your token).
EOF
fi
