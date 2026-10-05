#!/usr/bin/env bash
# Real Delta Chat RPC + cmlxc relay_minitest, on two disposable Docker relays.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
MINI=1
MINI_ONLY=0
TEST_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --mini-only) MINI_ONLY=1 ;;
        --no-mini) MINI=0 ;;
        --test-10|--test-18|--test-20|--test-21|--lxc|--keep-lxc)
            echo "Not supported by the Docker harness: $arg (see docs/guide/docker.md)" >&2
            exit 2 ;;
        *) TEST_ARGS+=("$arg") ;;
    esac
done
set -- "${TEST_ARGS[@]}"
if [[ $MINI -eq 0 && $MINI_ONLY -eq 1 ]]; then
    echo '--mini-only and --no-mini cannot be combined' >&2
    exit 2
fi
command -v timeout >/dev/null || { echo 'GNU timeout is required' >&2; exit 1; }
docker info >/dev/null
[[ -f tests/cmlxc/src/relay_minitest/test_relay.py ]] || {
    echo 'Initialize the test submodule: git submodule update --init tests/cmlxc' >&2
    exit 1
}
mkdir -p target/docker-deltachat-tests
WORK="$(mktemp -d "$ROOT/target/docker-deltachat-tests/run-XXXXXXXX")"
NAME="madmail-dc-$(basename "$WORK")"
IMAGE="${MADMAIL_DOCKER_TEST_IMAGE:-madmail-local:test-docker}"
RELAY_IMAGE="${IMAGE}-dc-relay"
CLIENT_IMAGE="${IMAGE}-dc-client"
cleanup() {
    local result=$?
    trap - EXIT
    docker rm -f "${NAME}-client" >/dev/null 2>&1 || true
    for i in 1 2; do
        docker logs "${NAME}-$i" > "$WORK/relay$i.log" 2>&1 || true
        docker rm -fv "${NAME}-$i" >/dev/null 2>&1 || true
    done
    docker network rm "$NAME" >/dev/null 2>&1 || true
    echo "Delta Chat Docker logs: $WORK"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo "Building Delta Chat Docker images (log: $WORK/build.log)"
if ! docker build -t "$IMAGE" . > "$WORK/build.log" 2>&1 ||
    ! docker build -f tests/deltachat.Dockerfile --target relay \
    --build-arg "RELAY_IMAGE=$IMAGE" -t "$RELAY_IMAGE" . >> "$WORK/build.log" 2>&1 ||
    ! docker build -f tests/deltachat.Dockerfile --build-arg "RELAY_IMAGE=$IMAGE" \
    -t "$CLIENT_IMAGE" . >> "$WORK/build.log" 2>&1; then
    tail -60 "$WORK/build.log" >&2
    exit 1
fi
docker network create "$NAME" >/dev/null
REMOTES=()
for i in 1 2; do
    docker run -d --name "${NAME}-$i" --network "$NAME" --cap-add NET_ADMIN \
        --entrypoint sh "$RELAY_IMAGE" -c \
        'while [ ! -f /run/docker-test-ready ]; do sleep 1; done; exec /bin/madmail --config /etc/madmail/madmail.conf run --libexec /var/lib/madmail' >/dev/null
    IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${NAME}-$i")"
    REMOTES+=("$IP")
    docker exec "${NAME}-$i" madmail install --simple --ip "$IP" --tls-mode self_signed \
        --enable-chatmail --enable-iroh --skip-systemd --skip-user --non-interactive \
        > "$WORK/install$i.log" 2>&1
    docker exec "${NAME}-$i" sh -c \
        "sed -i 's/^log off$/log stderr/' /etc/madmail/madmail.conf; touch /run/docker-test-ready"
done
MAPPING="{\"${REMOTES[0]}\":\"${NAME}-1\",\"${REMOTES[1]}\":\"${NAME}-2\"}"
CLIENT=(timeout --foreground "${MADMAIL_DOCKER_DC_TIMEOUT:-1800}" \
    docker run --rm --init --name "${NAME}-client" --network "$NAME"
    -v /var/run/docker.sock:/var/run/docker.sock -v "$WORK:/results"
    -e "REMOTE1=${REMOTES[0]}" -e "REMOTE2=${REMOTES[1]}"
    -e "DELTACHAT_DOCKER_RELAYS=$MAPPING" -e "BIGFILE_E2E_MB=${BIGFILE_E2E_MB:-5}")
# Network readiness before the real clients register.
"${CLIENT[@]}" --entrypoint python "$CLIENT_IMAGE" -c '
import os, socket, time
for host in (os.environ["REMOTE1"], os.environ["REMOTE2"]):
    for attempt in range(60):
        try:
            with socket.create_connection((host, 993), timeout=1):
                break
        except OSError:
            time.sleep(1)
    else:
        raise SystemExit(f"Relay not ready: {host}")
'
if [[ $MINI -eq 1 ]]; then
echo "Running cmlxc relay_minitest in Docker (log: $WORK/mini.log)"
if ! "${CLIENT[@]}" --entrypoint python "$CLIENT_IMAGE" -m pytest -p mini_compat \
    /app/tests/relay_minitest -v --relay1 "${REMOTES[0]}" --relay2 "${REMOTES[1]}" \
    > "$WORK/mini.log" 2>&1; then
    tail -80 "$WORK/mini.log" >&2
    exit 1
fi
tail -2 "$WORK/mini.log"
fi
if [[ $MINI_ONLY -eq 1 ]]; then
    exit 0
fi
if [[ $# -eq 0 ]]; then
    # Signing-key and Go-only camouflage tests are not portable; exchangers own LXC.
    set -- --all --no-test 10,18 --color
fi
echo "Running extensive Delta Chat scenarios in Docker (log: $WORK/deltachat.log)"
if ! "${CLIENT[@]}" "$CLIENT_IMAGE" "$@" > "$WORK/deltachat.log" 2>&1; then
    tail -100 "$WORK/deltachat.log" >&2
    exit 1
fi
grep -E 'PASSED|SELECTED TESTS' "$WORK/deltachat.log" || true
echo 'Delta Chat Docker tests passed.'
