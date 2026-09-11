# Rewrite plan — the "from scratch" decisions, applied incrementally

Result of the architecture review (2026-09-11). Five accepted changes, executed
as five independently verifiable phases. The repo stays green after each one.
Decisions locked with the owner:

1. **pidfd supervision** — replace the waitpid(-1)/stolen-exit registry with a
   single-reaper pidfd hub.
2. **S3 client in the supervisor** — rusty-s3 + ureq replaces rclone (owner:
   "fine so long as the result is the same; we didn't do anything complex
   with S3"). No official crate covers sync-S3 without tokio, so two small,
   maintained crates (rusty-s3 0.10.2, BSD-2, maintained Aug 2026; ureq,
   sync, rustls) instead of one big one — matches the "small enough for a
   human to maintain" bar.
3. **Breaking config simplification** — prefix-only keys, one port spelling,
   unknown keys in the .env file refuse boot.
4. **Boot sequence as an explicit phase state machine.**
5. **Checksum pin automation** — script + Renovate postUpgradeTasks + CI
   drift check; no hand-bumped digests.

---

## Phase 1 — pidfd supervision hub (no user-visible change)

**Problem today:** bounded runs (`process/run.rs`) and the watch loop
(`process/watch.rs` → `reap.rs`) race over `waitpid`; the `stolen` registry
(`process/stolen.rs`) exists to close that race, and its failure modes
(invented success vs. lost status) generate the subtlest code and tests in
the crate.

**Design:** one reaper, zero races.

- New `supervisor/src/runtime/process/pidfd.rs`:
  - `PidFd::open(pid)` — `pidfd_open(2)` via `libc::syscall` (libc ships
    `SYS_pidfd_open`; no new dependency).
  - `ready(&self) -> bool` — poll(2) for POLLIN (child exited or is
    waitable).
  - ~50 lines of tightly-scoped unsafe; everything else safe on top.
- New `process/reaper.rs` (replaces `reap.rs` + `stolen.rs`):
  - `spawn()` returns a registered handle: pid + pidfd inserted into a
    shared registry (Mutex) *immediately* after spawn.
  - The main thread is the **only** caller of waitpid in the process. It
    polls the registry's pidfds on a short slice, reaps what reports
    ready, and delivers the `WaitStatus` to the registered waiter
    (Mutex<Option<..>> + Condvar, std-only).
  - `reap_until_gone` becomes: signal group, wait on delivery with
    TERM_GRACE, escalate to KILL.
- `run_bounded_core`: spawn+register → poll abort/deadline on its own
  thread → killpg on timeout/abort → block on delivered status (verdict =
  exit code 0). No try_wait, no ECHILD path, no registry lookups.
- Watch loop: poll the two long-running pidfds; a ready vw = exit path, a
  ready tsd = teardown, everything else = stray, logged (same semantics as
  today).
- Boot guard: if `pidfd_open` fails with ENOSYS, exit 1 with a clear
  message (fail-closed; RHEL 9 baseline kernel 5.14 ≥ 5.3, so this is
  theoretical).
- Delete: `process/stolen.rs`, the stolen branches in `run.rs`, their
  tests; adapt timeout/capture/descendant tests to the hub; add
  hub-delivery tests (single reaper makes "reaped out from under" tests
  unnecessary by construction).

**Verify:** cargo test/fmt/clippy; the existing behavioral tests
(`capture_timeout_survives_a_stdout_holding_descendant`,
oversized-output, env-allowlist) must pass unchanged.

## Phase 2 — rusty-s3 + ureq, rclone removed

**Scope is exactly the four rclone verbs in use:** put (state sync push,
backup push), get (state sync pull), list (backup lineage), batch delete
(prune/KEEP). No multipart, no sync engine, no bucket ops.

- New top-level `supervisor/src/s3/`:
  - `mod.rs` — small public surface: `Client::new(SyncConfig)`, `put`,
    `get`, `list(prefix)`, `delete(keys)`.
  - `sign.rs` — rusty-s3 `Credentials`/`Url`/`Actions`; path-style URLs
    (R2-compatible); SigV4 queries generated per request.
  - `http.rs` — one `ureq::Agent` (rustls): hard timeouts
    (SYNC_TIMEOUT/BACKUP semantics), redirect policy off, `SSL_CERT_FILE`
    plumbed into the root store explicitly (replaces what the Go binaries
    picked up from the env allowlist — `BASELINE_ENV` keeps the key only
    if we still consume it).
- Behavior parity checklist (all current guarantees kept):
  - secrets never on argv (they ride the signed request headers; nothing
    else sees them — actually *stronger* than rclone-env),
  - every request bounded; abort flag checked between list pages and
    before each op,
  - list output capped (the 16 MiB CAPTURE_MAX intent, now enforced
    structurally on pagination),
  - `--no-check-dest` semantics: PUT to unique timestamped keys,
    unconditional overwrite never used in place,
  - state-sync include set (`tailscaled.state`, `rsa_key*`, `certs/**`)
    becomes an explicit client-side file enumeration,
  - unchanged-skip stays local (`unchanged.rs` compares staged dump to the
    retained copy; no HEAD/ETag needed),
  - prune: DeleteObjects in ≤1000-key batches.
- Removals: `runtime/backup/tools.rs` (rclone wrapper), `RCLONE*` consts,
  Containerfile RCLONE ARGs + fetch + COPY, renovate.json rclone manager.
  Image shrinks by the ~50 MB rclone binary; supervisor grows ~2–3 MB
  (ureq+rustls).
- Keep all `SUPERVISOR_S3_*` knobs byte-identical (user-visible API).
- Live check (needs owner): one run against a real R2 bucket — put, list,
  get, delete, and a wrong-credential failure that fails closed.

**Verify:** cargo suite + `podman build --format docker` + the live R2
run above.

## Phase 3 — breaking config simplification

- Port: `VAULTWARDEN_PORT` only. `VAULTWARDEN_ROCKET_PORT` and bare
  `ROCKET_PORT` (env or file) refuse boot with a message naming the one
  valid spelling.
- .env file: keys must be `TAILSCALE_*`, `SUPERVISOR_*`, or
  `VAULTWARDEN_*` (optional `export ` prefix). Anything else → boot
  refuses, listing offending key *names* only (values may be secrets).
- Container env stays lenient (platforms inject junk): unknown keys are
  dropped with a warning, as today — the file is the explicit grant
  surface and is strict, ambient env is default-deny and cannot be made
  strict.
- `vaultwarden_key` stripping stays; the file's bare-name pass-through
  (`file_key`'s `map_or_else`) is deleted, collapsing `FileConfig`'s
  knobs/child split into one routed map.
- Keep: empty = unset, env > file > default, hard pins, supervisor-consumed
  filtering after stripping.
- Docs: .env.example rewrite (migration note: `DATABASE_URL` →
  `VAULTWARDEN_DATABASE_URL`, `ROCKET_PORT` → `VAULTWARDEN_PORT`), README
  config section, CONTRIBUTING notes.

**Verify:** cargo suite with the port-resolution and dotenv tests rewritten
for strictness; every test that relied on a legacy spelling inverts into a
refusal test.

## Phase 4 — boot state machine

- `main.rs` becomes a thin fold over an explicit phase list:

  ```
  RestoreDb → AdoptLineage → RestoreState → Tailscaled → TailscaleUp
            → Serve → Vault(watch loop)
  ```

  each `Phase::run(&Ctx) -> Outcome { Next, Exit(code) }`, with the
  stop-flag and failure policy of every phase documented in one table in
  the module header (today that policy is spread across main.rs, watch.rs,
  and the services modules).
- No behavior change intended; the diff should be mechanical except for
  the phase table.

**Verify:** cargo suite; smoke-run the image with a bad authkey (exit 1 at
TailscaleUp), with serve disabled, and the healthcheck one-shot mode.

## Phase 5 — checksum pin automation

- `scripts/update-pins.sh`: for each version ARG, download the artifact
  for both arches, sha256 it, rewrite the matching `*_SHA256*` ARG line.
  (rclone's ARGs disappear in Phase 2, shrinking the set to VW, web-vault,
  Tailscale×2.)
- Renovate `postUpgradeTasks` runs the script on its version-bump PRs, so
  digests always ride along with versions.
- CI job (in `supervisor.yml` or a new `pins.yml`): on any PR touching the
  Containerfile, recompute checksums from the ARG'd versions and fail on
  mismatch — the Containerfile itself is the committed lockfile; drift is
  red CI, and a scheduled run catches hand-edited versions.
- CONTRIBUTING.md: delete the "bump VW_SHA256 by hand" rule, document the
  script.

**Verify:** run the script against the current pins — output must be
byte-identical to what's committed (negative test: bump a version, CI
red).

---

## Progress log

- 2026-09-11 — plan written; phases pending. Baseline: `main` @ 2f8e173,
  clean tree.
- 2026-09-11 — **Phase 1 complete** (commit e888022):
  `process/pidfd.rs` (new, ~120 lines incl. tests), `process/reaper.rs`
  (new, hub + Handle), `child.rs` spawn → `Option<Handle>` with registry
  lock held across spawn+insert, `reap.rs` slimmed to status decoding +
  escalation wait (Gone::Vanished removed — impossible under single
  ownership), `run.rs` verdicts from delivered slots, `watch.rs` loop
  reads slots, `stolen.rs` deleted. Design note: the race-killer is the
  single waitpid owner + delivery, with the registry lock held across
  spawn+registration; pidfds are the prompt-detection path and the
  sweep is the correctness backstop. All waitpid call sites are
  WNOHANG. Verified: 106 tests × 8 runs, fmt, clippy -D warnings,
  `cargo check --release`.
- 2026-09-11 — **Phase 2 complete** (uncommitted): rclone removed; new
  `src/s3.rs` (rusty-s3 0.10 signing + ureq 3 sync HTTP/rustls, put/get/
  list/delete; presigned URLs, Content-Length PUTs, 0 redirects, 10k-key
  and 16 MiB listing caps, errors never contain the signed URL).
  SyncConfig parsed into bucket+prefix (validation in `sync::spec`);
  state sync enumerates the identity set (`tailscaled.state`,
  `rsa_key*`, `certs/**`) locally and enforces it on pulls too (traversal
  guard); pushes list once and upload only size-changed files. Backup
  `tools.rs` fronts the client; dump/prune/restore rewired; prune keeps
  single-object deletes (parity). Containerfile: rclone fetch/unzip/COPY
  and its ARGs/checksums gone (`unzip` dropped from fetch). renovate.json:
  rclone manager removed. Verified: 111 tests ×3, fmt, clippy -D
  warnings, check --release, full image build, real-binary smoke test
  (dead-endpoint S3 → non-fatal; fail-closed Tailscale refusal; clean
  hub-driven teardown). Image: 321 MB (rclone ~55 MB layer gone;
  supervisor grew by ureq/rustls).

- 2026-09-11 — **Phase 3 complete** (uncommitted): breaking config
  simplification. The dotenv file is strict — only TAILSCALE_*/
  SUPERVISOR_*/VAULTWARDEN_* keys are accepted; anything else (bare
  upstream names, a VAULTWARDEN_ key stripping into the supervisor
  namespace) refuses the boot naming the offending keys, values never
  logged. The port has ONE spelling (VAULTWARDEN_PORT); the legacy
  VAULTWARDEN_ROCKET_PORT alias and bare ROCKET_PORT refuse the boot
  with a message naming the valid spelling (ambient bare ROCKET_PORT
  was never consumed, so ambient handling is unchanged). FileConfig
  gained `invalid`; vaultwarden.rs `file_key` deleted (the file map
  arrives pre-routed); db_url empty-file-value now means unset.
  Docs rewritten: README config section, .env.example header with
  migration note, compose.yaml header. Verified: 114 tests ×3, fmt,
  clippy -D warnings, check --release, image build, and real-binary
  smoke tests: bare-key file refuses naming DATABASE_URL; alias file
  and alias env refuse with the specific message; strict prefix-only
  file proceeds past config to the Tailscale gate.

- 2026-09-11 — **Phase 4 complete** (uncommitted): boot is an explicit
  phase machine (`src/boot.rs`; main.rs slims to arg dispatch + module
  declarations). The seven phases — RestoreDb, AdoptLineage,
  RestoreState, Tailscaled, DaemonWait, TailscaleUp, Serve — run as a
  fold over a const table; `Vault` (the watch loop) is the fold's tail
  and never returns. The per-phase stop/failure policy lives in one
  table in the module header. No behavior change: log messages,
  exit codes, teardown shapes (shutdown(tsd, None, code, None) for
  boot-phase exits, no final state push before the vault runs), and
  stop-consumption points are byte-for-byte the old main.rs semantics.
  Verified: 114 tests ×3, fmt, clippy -D warnings, check --release,
  image build, and real-binary smoke runs: healthcheck one-shot exit 1
  (config refusal), healthcheck with config but no gate exit 1,
  invalid-authkey boot fails at TailscaleUp with the refusal and exit 1.

## Status

- Phases 1–3: **done** (committed: e888022, 03b06dd, 7d76d25).
  Phase 4: done, uncommitted.
- Phase 5 pending: checksum pin automation (update script + Renovate
  postUpgradeTasks + CI drift check). UNKNOWN until a live run: real R2
  round-trip (put/list/get/delete + wrong-credentials fail-closed).
