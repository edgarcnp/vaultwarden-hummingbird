#!/usr/bin/env bash
# Smoke tests for a locally built image: the entrypoint actually runs in
# the runtime image, and every fail-closed config path refuses with the
# message that names the problem. No credentials, no network.
#
# Usage: scripts/smoke-image.sh [image]   (default: vaultwarden-hummingbird:local)
#
# This is what the Image workflow runs on every build-context change; run
# it locally after `podman build --format docker -t vaultwarden-hummingbird:local .`
set -u
IMAGE=${1:-vaultwarden-hummingbird:local}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

# run NAME EXPECTED_EXIT PATTERN -- podman-run-args...
# Runs the image networkless with a tmpfs /tmp (the compose posture),
# checks the exit code, and greps the log for PATTERN.
run() {
  local name=$1 expected=$2 pattern=$3
  shift 3
  [ "$1" = "--" ] && shift
  local log="$WORK/$name.log"
  timeout 180 podman run --rm --network none --tmpfs /tmp "$@" >"$log" 2>&1
  local code=$?
  if [ "$code" = "$expected" ] && grep -qF "$pattern" "$log"; then
    echo "PASS  $name (exit $code, found: $pattern)"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $name (exit $code, wanted $expected; pattern: $pattern)"
    sed -n '1,12p' "$log" | sed 's/^/      | /'
    FAIL=$((FAIL + 1))
  fi
}

echo "== image =="
podman image inspect "$IMAGE" --format 'id={{.Id}}
user={{.User}}
healthcheck={{.HealthCheck.Test}}' | sed 's/^/      /'
USER_ID=$(podman image inspect "$IMAGE" --format '{{.User}}')
CHECK=$(podman image inspect "$IMAGE" --format '{{json .HealthCheck.Test}}')
if [ "$USER_ID" = "65532:0" ] && [ "$CHECK" = '["CMD","/entrypoint","--healthcheck"]' ]; then
  echo "PASS  image-shape (non-root user, exec healthcheck present)"
  PASS=$((PASS + 1))
else
  echo "FAIL  image-shape (user=$USER_ID healthcheck=$CHECK)"
  FAIL=$((FAIL + 1))
fi

# Fixtures: each file isolates one refusal path.
printf 'DATABASE_URL=x\n' >"$WORK/bare.env"
printf 'SUPERVISOR_DB_BACKUP_RESTOR=true\nTAILSCALE_AUTHKEY=tskey-smoke\n' >"$WORK/supervisor.env"
printf 'TAILSCALE_STATE_FILE=state/tailscaled.state\nTAILSCALE_AUTHKEY=tskey-smoke\n' >"$WORK/relative.env"
printf 'TAILSCALE_AUTHKEY=tskey-invalid-smoke\nVAULTWARDEN_DOMAIN=https://smoke.example\n' >"$WORK/fake-auth.env"

# 1. One-shot healthcheck with no config: the supervisor refuses at config
#    resolution before probing, and exit 1 proves the binary runs here.
run healthcheck-no-config 1 "refusing" -- --entrypoint /entrypoint "$IMAGE" --healthcheck

# 2. No config at all: fail closed naming the missing key.
run no-config 1 "TAILSCALE_AUTHKEY is required" -- "$IMAGE"

# 3. Strict dotenv: a bare upstream key refuses, naming it.
run bare-key 1 "unrecognized dotenv file keys (DATABASE_URL)" -- \
  -e SUPERVISOR_ENV_FILE=/config/.env -v "$WORK/bare.env:/config/.env:ro,z" "$IMAGE"

# 4. An unknown supervisor-namespace key refuses, naming it.
run unknown-supervisor-key 1 "SUPERVISOR_DB_BACKUP_RESTOR" -- \
  -e SUPERVISOR_ENV_FILE=/config/.env -v "$WORK/supervisor.env:/config/.env:ro,z" "$IMAGE"

# 5. A relative state file refuses (it anchors the identity and statedir).
run relative-state 1 "must be an absolute path" -- \
  -e SUPERVISOR_ENV_FILE=/config/.env -v "$WORK/relative.env:/config/.env:ro,z" "$IMAGE"

# 6. With a bogus auth key and no network, tailscaled must come up and the
#    CLI must actually run and fail ("authenticating tailscale node..." is
#    logged only after the daemon socket is ready), and the supervisor must
#    refuse to run the vault (fail closed) rather than keep a vault nobody
#    can reach.
run tailscale-fails-closed 1 "authenticating tailscale node" -- \
  -e SUPERVISOR_ENV_FILE=/config/.env -v "$WORK/fake-auth.env:/config/.env:ro,z" "$IMAGE"

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = 0 ]
