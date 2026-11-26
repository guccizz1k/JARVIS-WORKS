#!/usr/bin/env bash
# Synthetic CI only: prefetch runtime, then verify package in networkless container.
set -Eeuo pipefail
test "${GITHUB_ACTIONS:-}" = true
test -n "${RUNNER_TEMP:-}"
W=$(mktemp -d "$RUNNER_TEMP/naruv-offline.XXXXXX")
trap 'rm -rf "$W"' EXIT
SHA=$(git rev-parse HEAD)
python -m scripts.naruv_offline_recovery_package build . "$SHA" "$W/recovery.zip"
cp scripts/naruv_offline_recovery_package.py "$W/verify.py"
PIN=$(sha256sum "$W/recovery.zip" | cut -d' ' -f1)
docker pull python:3.11-slim
PY_IMAGE=$(docker image inspect python:3.11-slim --format '{{.Id}}')
PG_IMAGE=$(docker image inspect postgres:17 --format '{{.Id}}')
mkdir "$W/wheels"
# Resolve only binary dependencies, in the target runtime architecture.
docker run --rm --pull=never -v "$W/wheels:/wheels" "$PY_IMAGE" python -m pip download --only-binary=:all: --dest /wheels 'cryptography>=43,<47'
sudo chown -R "$(id -u):$(id -g)" "$W"
(cd "$W" && sha256sum wheels/*.whl > wheels.sha256 && sha256sum -c wheels.sha256)
# Install verified binary wheels into a dedicated immutable image layer.
# Keep /tmp noexec in runtime; shared object executable mappings come from image.
RUNTIME_TAG="naruv-offline-ci:$SHA"
trap 'docker image rm "$RUNTIME_TAG" >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
cat > "$W/Dockerfile" <<'DOCKER'
ARG BASE
FROM ${BASE}
COPY wheels /bundle/wheels
COPY wheels.sha256 /bundle/wheels.sha256
RUN cd /bundle && sha256sum -c wheels.sha256 && python -m pip install --disable-pip-version-check --no-cache-dir --no-index --find-links=/bundle/wheels 'cryptography>=43,<47' && python -c 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM'
DOCKER
# Docker build accepts a locally available tag; verify the tag remains pinned
# to the inspected ID, and never allow networking during the wheel install.
test "$(docker image inspect python:3.11-slim --format '{{.Id}}')" = "$PY_IMAGE"
docker build --network none --pull=false --build-arg BASE=python:3.11-slim --tag "$RUNTIME_TAG" "$W"
RUNTIME_ID=$(docker image inspect "$RUNTIME_TAG" --format '{{.Id}}')
docker run --rm --pull=never --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m \
  --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
  -v "$W:/bundle:ro" -e PYTHONDONTWRITEBYTECODE=1 -e HOME=/tmp "$RUNTIME_ID" \
  sh -ec '
    cd /bundle
    sha256sum -c wheels.sha256
    python /bundle/verify.py verify /bundle/recovery.zip "$1" "$2"
    mkdir /tmp/recovery
    cd /tmp/recovery
    python -c "import zipfile; zipfile.ZipFile(\"/bundle/recovery.zip\").extractall()"
    python -c "from scripts import p1_external_custodian_pg17_v223 as e; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; k=AESGCM.generate_key(bit_length=256); a=AESGCM(k); n=b\"0\"*12; assert a.decrypt(n,a.encrypt(n,b\"synthetic\",None),None)==b\"synthetic\"; assert e.B2_ACK; print(\"OFFLINE_RUNTIME_IMPORT_AES=PASS\")"
  ' sh "$SHA" "$PIN"
# Exercise exact cached PG17 image in a separate networkless container.
docker run --rm --pull=never --network none "$PG_IMAGE" postgres --version | grep -E 'PostgreSQL\) 17\.'
printf 'OFFLINE_BASE_IMAGE=%s\nOFFLINE_RUNTIME_IMAGE=%s\nOFFLINE_PG17_IMAGE=%s\nSOURCE_PACKAGE_SHA256=%s\nOFFLINE_RUNTIME_CI=PASS\n' "$PY_IMAGE" "$RUNTIME_ID" "$PG_IMAGE" "$PIN"
