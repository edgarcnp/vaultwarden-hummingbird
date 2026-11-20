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
VOL=
DVOL=
trap 'rm -rf "$WORK"; [ -n "$VOL" ] && podman volume rm -f "$VOL" >/dev/null 2>&1; [ -n "$DVOL" ] && podman volume rm -f "$DVOL" >/dev/null 2>&1' EXIT
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
if [ "$USER_ID" = "65532:65532" ] && [ "$CHECK" = '["CMD","/entrypoint","--healthcheck"]' ]; then
  echo "PASS  image-shape (non-root user, exec healthcheck present)"
  PASS=$((PASS + 1))
else
  echo "FAIL  image-shape (user=$USER_ID healthcheck=$CHECK)"
  FAIL=$((FAIL + 1))
fi

# The base runtime ships a shell (and the openssl/coreutils CLI set); the
# Containerfile removes it. Create (do not start) a container and inspect
# the exported root filesystem without executing anything in the image.
if cid=$(podman create "$IMAGE" 2>/dev/null); then
  listing=$(podman export "$cid" 2>/dev/null | tar -tv 2>/dev/null)
  podman rm -f "$cid" >/dev/null 2>&1 || true
  if printf '%s\n' "$listing" | awk '{print $NF}' | grep -Eq '^(usr/)?bin/(bash|sh)$'; then
    echo "FAIL  no-shell (a shell binary is present in the runtime image)"
    FAIL=$((FAIL + 1))
  else
    echo "PASS  no-shell (no bash/sh binary in the runtime image)"
    PASS=$((PASS + 1))
  fi
  # /state must be a private supervisor-only directory; /data is shared
  # with the vault's group (0770).
  state_mode=$(printf '%s\n' "$listing" |
    awk '{ p=$NF; sub("^\\./", "", p); if (p == "state/") { print $1; exit } }')
  state_ts_mode=$(printf '%s\n' "$listing" |
    awk '{ p=$NF; sub("^\\./", "", p); if (p == "state/tailscale/") { print $1; exit } }')
  data_mode=$(printf '%s\n' "$listing" |
    awk '{ p=$NF; sub("^\\./", "", p); if (p == "data/") { print $1; exit } }')
  if [ "$state_mode" = "drwx--s---" ] && [ "$state_ts_mode" = "drwxrws---" ] \
    && [ "$data_mode" = "drwxrwx---" ]; then
    echo "PASS  volume-modes (/state 2710, /state/tailscale 2770, /data 0770)"
    PASS=$((PASS + 1))
  else
    echo "FAIL  volume-modes (state='$state_mode' tailscale='$state_ts_mode' data='$data_mode')"
    FAIL=$((FAIL + 1))
  fi
else
  echo "FAIL  no-shell (podman create failed)"
  FAIL=$((FAIL + 1))
fi

# Fixtures: each file isolates one refusal path. SUPERVISOR_ENV_FILE must
# live under /state; anything else is refused before it is read.
printf 'DATABASE_URL=x\n' >"$WORK/bare.env"
printf 'SUPERVISOR_DB_BACKUP_RESTOR=true\nTAILSCALE_AUTHKEY=tskey-smoke\n' >"$WORK/supervisor.env"
printf 'TAILSCALE_STATE_FILE=state/tailscaled.state\nTAILSCALE_AUTHKEY=tskey-smoke\n' >"$WORK/relative.env"
printf 'TAILSCALE_AUTHKEY=tskey-invalid-smoke\nVAULTWARDEN_DOMAIN=https://smoke.example\n' >"$WORK/fake-auth.env"

# 1. One-shot healthcheck with no config: the supervisor refuses at config
#    resolution before probing, and exit 1 proves the binary runs here.
run healthcheck-no-config 1 "refusing" -- --entrypoint /entrypoint "$IMAGE" --healthcheck

# Boot cases need the deployment capabilities: PID 1 joins the tailscale
# group, spawns children under separate uids, and reads tailscaled's 0600
# identity/cert files (Tailscale writes them 0600 by design).
CAPS=(--cap-add=SETUID --cap-add=SETGID --cap-add=KILL --cap-add=DAC_READ_SEARCH)

# 2. No config at all: fail closed naming the missing key.
run no-config 1 "no identity source" -- "${CAPS[@]}" "$IMAGE"

# 3. Strict dotenv: a bare upstream key refuses, naming it.
run bare-key 1 "unrecognized dotenv file keys (DATABASE_URL)" -- \
  "${CAPS[@]}" -e SUPERVISOR_ENV_FILE=/state/.env \
  -v "$WORK/bare.env:/state/.env:ro,z" "$IMAGE"

# 4. An unknown supervisor-namespace key refuses, naming it.
run unknown-supervisor-key 1 "SUPERVISOR_DB_BACKUP_RESTOR" -- \
  "${CAPS[@]}" -e SUPERVISOR_ENV_FILE=/state/.env \
  -v "$WORK/supervisor.env:/state/.env:ro,z" "$IMAGE"

# 5. A relative state file refuses (it anchors the identity and statedir).
run relative-state 1 "must be 'mem:' or a direct child" -- \
  "${CAPS[@]}" -e SUPERVISOR_ENV_FILE=/state/.env \
  -v "$WORK/relative.env:/state/.env:ro,z" "$IMAGE"

# 6. A dotenv file outside /state is refused: the vault uid could read it.
run env-outside-state 1 "must live under /state" -- \
  "${CAPS[@]}" -e SUPERVISOR_ENV_FILE=/config/.env \
  -v "$WORK/fake-auth.env:/config/.env:ro,z" "$IMAGE"

# 7. With a bogus auth key and no network, tailscaled must come up and the
#    CLI must actually run and fail ("authenticating tailscale node..." is
#    logged only after the daemon socket is ready), and the supervisor must
#    refuse to run the vault (fail closed) rather than keep a vault nobody
#    can reach.
run tailscale-fails-closed 1 "authenticating tailscale node" -- \
  "${CAPS[@]}" -e SUPERVISOR_ENV_FILE=/state/.env \
  -v "$WORK/fake-auth.env:/state/.env:ro,z" "$IMAGE"

# 8. Run the vault binary directly under its production uid. It must write
#    its signing key on /data (the shared data group), then stop on the
#    deliberately broken TLS config — proof the data volume is usable.
run vault-writes-data 101 "Private key '/data/rsa_key.pem' created correctly" -- \
  --user 65533:65532 --entrypoint /vaultwarden \
  -e DATA_FOLDER=/data -e WEB_VAULT_FOLDER=/web-vault \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true -e ROCKET_TLS='{certs,key}.pem' "$IMAGE"

# 9. The same uid must not be able to traverse /state (2710, owner 65532,
#    group tailscale), even when it is told to use it as its data folder.
run vault-cannot-reach-state 1 "Permission denied" -- \
  --user 65533:65532 --entrypoint /vaultwarden \
  -e DATA_FOLDER=/state -e WEB_VAULT_FOLDER=/web-vault \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true "$IMAGE"

# 10. TUN mode keeps NET_ADMIN/NET_RAW across the tailscaled uid change
#     (PR_SET_KEEPCAPS). Rootless podman cannot create a TUN in its user
#     namespace, so this runs only on a rootful host with a TUN device;
#     the image still exercises userspace mode above.
ROOTLESS=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)
if [ -e /dev/net/tun ] && [ "$ROOTLESS" != "true" ]; then
  run tailscale-tun-fails-closed 1 "authenticating tailscale node" -- \
    "${CAPS[@]}" --cap-add=NET_ADMIN --cap-add=NET_RAW --device /dev/net/tun \
    -e TAILSCALE_USERSPACE=false -e SUPERVISOR_ENV_FILE=/state/.env \
    -v "$WORK/fake-auth.env:/state/.env:ro,z" "$IMAGE"
else
  echo "SKIP  tailscale-tun-fails-closed (rootless=$ROOTLESS or no /dev/net/tun)"
fi

# 11. A restart must survive files tailscaled created under its own uid.
#     The daemon owns the state/cert tree and cannot be told to widen its
#     modes; the supervisor must skip those files instead of failing the boot
#     (it reads them for sync through DAC_READ_SEARCH). The runtime has no
#     shell, so the vault binary itself creates a daemon-owned file as uid
#     65531; its exit 101 on the deliberately broken TLS config is expected.
VOL="vw-smoke-state-$$"
DVOL="vw-smoke-data-$$"
podman volume create "$VOL" >/dev/null
podman volume create "$DVOL" >/dev/null
timeout 30 podman run --rm --network none --tmpfs /tmp --user 65531:65531 \
  -e DATA_FOLDER=/state/tailscale -e WEB_VAULT_FOLDER=/web-vault \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true -e ROCKET_TLS='{certs,key}.pem' \
  -v "$VOL:/state:z" --entrypoint /vaultwarden "$IMAGE" \
  >"$WORK/daemon-owned-file.log" 2>&1 || true
if grep -qF "Private key '/state/tailscale/rsa_key.pem' created correctly" \
  "$WORK/daemon-owned-file.log"; then
  run restart-with-daemon-file 1 "authenticating tailscale node" -- \
    "${CAPS[@]}" -e SUPERVISOR_ENV_FILE=/state/.env \
    -v "$WORK/fake-auth.env:/state/.env:ro,z" \
    -v "$VOL:/state:z" -v "$DVOL:/data:z" "$IMAGE"
else
  echo "FAIL  restart-with-daemon-file (the helper did not create the 0600 file)"
  sed -n '1,12p' "$WORK/daemon-owned-file.log" | sed 's/^/      | /'
  FAIL=$((FAIL + 1))
fi

# The link fix must leave tailscaled with a real file store, not the silent
# in-memory fallback it uses when it cannot chmod the state directory. The
# state file is 0600 under the daemon uid, inside the real /state/tailscale
# tree (the --state path goes through /state/tailscale-state).
mp=$(podman unshare podman volume inspect "$VOL" --format '{{.Mountpoint}}' 2>/dev/null || true)
state_mode=$(podman unshare stat -c '%a %u' "$mp/tailscale/tailscaled.state" 2>/dev/null || true)
if [ "$state_mode" = "600 65531" ]; then
  echo "PASS  state-file-persisted (tailscaled wrote its own 0600 state, not memory)"
  PASS=$((PASS + 1))
else
  echo "FAIL  state-file-persisted (expected '600 65531', got '$state_mode')"
  FAIL=$((FAIL + 1))
fi

# 12. The supervisor-spawned children must not retain the container
#     capabilities. This is the regression test for the vault's capability
#     drop: without it the vault can setuid back to 65532 and read /state.
run security-isolation 0 "isolation probe: ok" -- \
  "${CAPS[@]}" "$IMAGE" --security-probe

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = 0 ]
