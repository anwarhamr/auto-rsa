#!/bin/sh
set -eu

: "${RSA_TEST_APP_IMAGE:?Set RSA_TEST_APP_IMAGE to a locally available application image}"
: "${RSA_TEST_EGRESS_IMAGE:?Set RSA_TEST_EGRESS_IMAGE to a locally available gateway image}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_NAME="rsa-egress-test-$$"
BUILD_DIR=$(mktemp -d "$SCRIPT_DIR/.build.XXXXXX")
RSA_TEST_PROBE_IMAGE="rsa-egress-probe-test:$$"
RSA_TEST_GATEWAY_IMAGE="rsa-egress-gateway-test:$$"
export RSA_TEST_PROBE_IMAGE RSA_TEST_GATEWAY_IMAGE

cleanup() {
    docker compose -p "$PROJECT_NAME" -f "$SCRIPT_DIR/docker-compose.yml" down --volumes --remove-orphans >/dev/null 2>&1 || true
    docker image rm "$RSA_TEST_PROBE_IMAGE" "$RSA_TEST_GATEWAY_IMAGE" >/dev/null 2>&1 || true
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT HUP INT TERM

for image in "$RSA_TEST_APP_IMAGE" "$RSA_TEST_EGRESS_IMAGE"; do
    docker image inspect "$image" >/dev/null
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$BUILD_DIR/key.pem" \
    -out "$BUILD_DIR/cert.pem" \
    -subj /CN=api.robinhood.com \
    -addext subjectAltName=DNS:api.robinhood.com \
    >/dev/null 2>&1
chmod 0644 "$BUILD_DIR/cert.pem" "$BUILD_DIR/key.pem"
cp "$SCRIPT_DIR/probe.py" "$SCRIPT_DIR/Dockerfile.probe-test" "$BUILD_DIR/"

docker build \
    --build-arg "BASE_IMAGE=$RSA_TEST_APP_IMAGE" \
    --file "$BUILD_DIR/Dockerfile.probe-test" \
    --tag "$RSA_TEST_PROBE_IMAGE" \
    "$BUILD_DIR" >/dev/null

docker build \
    --build-arg "BASE_IMAGE=$RSA_TEST_EGRESS_IMAGE" \
    --file "$SCRIPT_DIR/Dockerfile.gateway-test" \
    --tag "$RSA_TEST_GATEWAY_IMAGE" \
    "$SCRIPT_DIR" >/dev/null

if [ "$(uname -s)" != Linux ]; then
    echo "warning: this exercises a Linux Docker VM, not the native-Linux appliance kernel" >&2
fi

set +e
output=$(docker compose \
    -p "$PROJECT_NAME" \
    -f "$SCRIPT_DIR/docker-compose.yml" \
    up --abort-on-container-exit --exit-code-from trader 2>&1)
status=$?
set -e
printf '%s\n' "$output"

[ "$status" -eq 0 ] || exit "$status"
printf '%s\n' "$output" | grep -F "offline egress probes passed" >/dev/null || {
    echo "Offline egress probe did not reach its success boundary" >&2
    exit 1
}
trader_id=$(docker compose -p "$PROJECT_NAME" -f "$SCRIPT_DIR/docker-compose.yml" ps -aq trader)
[ -n "$trader_id" ] && [ "$(docker inspect --format '{{.State.ExitCode}}' "$trader_id")" -eq 0 ] || {
    echo "Offline egress probe container did not exit cleanly" >&2
    exit 1
}
