# Audit and redesign: vaultwarden-hummingbird

- **Revision audited:** `aa2ac6a` ("chore: bump supervisor to 1.0.3"), working tree clean
- **Date:** 2026-09-27
- **Scope:** `supervisor/` (all 53 source files, ~7,100 lines), `Containerfile`, compose, `.env.example`,
  CI workflows, scripts, README/CONTRIBUTING. End-to-end design review plus a from-scratch blueprint.
- **Method:** full read of every source file; independent verification of every High/Medium finding
  at the cited lines; the project's own gates run first-hand (`fmt`, `clippy -D warnings`, `test --locked`);
  git-history and secret-hygiene analysis; upstream Vaultwarden 1.37.2 source consulted for one claim.

**Bottom line:** the architecture is right and unusually disciplined, and nothing here justifies a rewrite.
The problems are concentrated in three foundational mechanisms that were built incrementally and now contradict
each other: **durability state** (ad-hoc sidecar/last/mtime heuristics with no recovery path),
**maintenance scheduling** (detached threads plus a consumed stop flag), and **configuration layering**
(one logical rule implemented in three places). Fix those three foundations and the rest of the system is
in good shape.

---

## 1. Executive summary

### 1.1 Strengths (verified, worth preserving)

- Sound security architecture: Tailscale is the only ingress, the vault binds loopback, the public port answers
  two canned responses and can never forward (`gate/server.rs:96-136`), and a tailscaled death tears the vault
  down (`process/watch.rs:112-119`).
- Fail-closed policy is real, not aspirational: missing auth key refuses boot (`config/env/merge.rs:149-156`),
  failed restore refuses boot (`boot.rs:83-87`), lost exit status is a failure, ambiguous DB state is never
  overwritten (`backup/sqlite/restore.rs:12-32,42-84`).
- Secrets discipline: auth key staged 0600 with `create_new`, passed as `file:<path>` argv, unlinked on drop
  (`util/staged.rs:22-36,63-67`); child env is `env_clear` + explicit grant (`process/env.rs:43-48`); no secret
  reaches logs, argv, or another child's env. No secret-shaped string exists anywhere in git history.
- Process supervision core: one reaper hub is the sole `waitpid` owner, pidfd-based, status delivered once and
  never consumed (`process/reaper.rs:138-197`). Correct and rare.
- Code quality: 128 tests, 0 failures; `clippy -D warnings` clean; `fmt` clean; exactly one production
  `expect` (`boot.rs:215`); three `unsafe` blocks, all documented, all in `pidfd.rs`; 6 files >250 lines,
  largest 387.
- Documentation is a genuine feature: README is user-facing, CONTRIBUTING contributor-facing, module docs
  explain *why*. The audit's documentation flaws are minor drift, not neglect.
- Supply-chain posture is above average: release artifacts digest-pinned and `sha256sum -c` enforced at build
  (`Containerfile:63-77`), provenance attestation on publish, `--locked` everywhere, SHA-pinned actions.

### 1.2 Risk register (all findings verified at the cited lines unless marked "reported")

| # | Severity | Area | Finding | Evidence |
|---|----------|------|---------|----------|
| F1 | **High** | sync | An interrupted pull leaves a truncated file that the next push uploads over the good remote copy. Can permanently lose `tailscaled.state`, `rsa_key.pem`, attachments. | `s3/client.rs:140-143`, `sync/state.rs:74-77,110-112,135-155` |
| F2 | **High** | config / image | The "attachments off" default is inert: bare `ORG_ATTACHMENT_LIMIT`/`USER_ATTACHMENT_LIMIT` in the image never reach the child, so uploads are actually unlimited. | `Containerfile:152-160`, `services/vaultwarden.rs:47-66,75-85`; upstream `ciphers.rs:1223,1245` |
| F3 | **High** | process | Reaper busy-spins (100% of a core) whenever the registry is empty — notably through the entire shutdown persist phase (up to 60 s). | `process/reaper.rs:199-205`, `process/pidfd.rs:51-53` |
| F4 | **High** | backup | A stale lineage sidecar permanently refuses all future backups; the logged remedy (`RESTORE=true`) cannot work because adoption requires an absent sidecar. | `backup/dump.rs:70-74`, `backup/restore.rs:102-108` |
| F5 | Med-High | process / backup | Stop consumes the one stop flag, so in-flight maintenance threads abort *less* after a stop and can race the final shutdown tick; one race outcome is the final backup being deleted mid-flight. | `process/signals.rs:55-57`, `watch.rs:121,175-180`, `backup/staging.rs:30-44` |
| F6 | Med-High | backup | An existing tableless/truncated DB is "empty" to the gate but `EEXIST` to the import → permanent exit-1 boot loop. | `backup/sqlite/restore.rs:16-32,62-78`, `boot.rs:83-87` |
| F7 | Med-High | config | Ambient empty values bypass the "empty = unset" rule for the child env; supervisor and child can resolve different DB URLs. | `services/vaultwarden.rs:52-54`, `process/env.rs:27-32`, `env/merge.rs:126-130,139-140` |
| F8 | Med-High | gate | Slowloris holds one of 32 slots for hours; 32 trickling connections starve `/alive` → platform restarts. | `gate/server.rs:27,102-117` |
| F9 | Medium | backup | Clock rollback can prune the dump just pushed, then jam the lineage guard permanently. | `backup/dump.rs:118-123`, `prune.rs:18-23`, `lineage.rs:62-70` |
| F10 | Medium | backup | A corrupt/tampered newest object blocks boot forever with no fallback to the next-newest. | `backup/restore.rs:45-59` |
| F11 | Medium | backup | A foreign `db/sqlite-*.sqlite3` object sorts newest, is imported if valid SQLite, and never ages out. | `backup/tools.rs:18-38`, `restore.rs:90-91`, `prune.rs:21-23` |
| F12 | Medium | backup | Downloads have no size cap; a huge object can fill `/data` before any check. | `s3/client.rs:125-144` |
| F13 | Medium | sync | Size-only change detection: a locally corrupted file overwrites the good remote copy; equal-size remote corruption is never healed. | `sync/state.rs:135-155` |
| F14 | Medium | sync | Whole-call 60 s timeout with no resume/multipart: large attachments can never sync, and each failed attempt feeds F1. | `s3/client.rs:88-92`, `consts.rs:14` |
| F15 | Medium | sync / s3 | 3xx responses are treated as success (uploads become silent no-ops; downloads write the redirect body). | `s3/client.rs:90,116-121,133-143,209-213`; ureq `max_redirects(0)` semantics |
| F16 | Medium | s3 | AWS `dualstack`/`fips`/`s3-<region>` endpoint forms derive an invalid signing region; an endpoint with a path segment is silently dropped. | `s3/client.rs:41-49`, `bucket.rs` `join` behavior in rusty-s3 0.10.2 |
| F17 | Medium | config | A UTF-8 BOM silently drops the first key (dotenvy's iterator does not strip it); unreadable/non-UTF-8 file silently degrades to env-only. | `config/dotenv.rs:46-56`; vendored dotenvy `iter.rs:15-25,31-45` |
| F18 | Medium | config | `$VAR` substitution mutates values (including secrets) with no diagnostic; undocumented. | `config/dotenv.rs:56`; vendored dotenvy `parse.rs:125+` |
| F19 | Medium | config | Namespace-internal typos (`SUPERVISOR_DB_BACKUP_RESTOR`) are accepted and silently ignored. | `config/dotenv.rs:59-69`, `env/knobs.rs:10-24` |
| F20 | Medium | process | `pidfd_open` vs the lock-free stray sweep race: a child that exits in the window is misreported as a spawn failure. | `process/child.rs:52-74`, `reaper.rs:164-171` |
| F21 | Medium | CI | No image build/smoke on PRs (regressed from an earlier workflow); artifact pins verify self-consistency only (TOFU). | `supervisor.yml`, `pins.yml:31-35`, `scripts/update-pins.sh:34-40` |
| F22 | Low | process | Second stop signal is inert; Serve-phase stop exits 1; pidfd dropped at reap allows signals to recycled pids; `panic=abort` invalidates `Drop`-based cleanup claims; relative `TAILSCALE_STATE_FILE` yields `--statedir=""`. | `signals.rs:55-57`, `boot.rs:156-175`, `reaper.rs:184-189`, `staged.rs:3-4`, `tailscale.rs:17-22` |
| F23 | Low | config / backup | `sqlite://` yields an empty path and arms a broken backup; dburl normalization (trim/percent-decode) can diverge from the raw URL the child receives; `TAILSCALE_SERVICE=""` shadows a file value. | `config/dburl.rs:14-22`, `services/vaultwarden.rs:54`, `env/merge.rs:167-170` |
| F24 | Low | gate / util / image | Accept errors can busy-spin; `make_private` failures ignored in three backup callers; OCI source label points at upstream Vaultwarden; `update-pins.sh` temp leak and no curl timeout; no SBOM; `:latest` moved on manual dispatch. | `gate/server.rs:69`, `backup/dump.rs:92` etc., `Containerfile:124`, `scripts/update-pins.sh:36-39`, `publish.yml:80-91` |

### 1.3 Documentation drift (each is small; together they erode a core project asset)

1. README:109 "Attachment uploads are off" — false in the default deployment (F2).
2. README:5 "everything … checked against a checksum before it runs" — base images float and `dnf install` is
   unpinned (`Containerfile:28-29,54,101`), though `dnf` does verify Red Hat repo signatures.
3. README:48 "a typo … stops the boot" — true only outside the accepted namespaces (F19).
4. README:73 / `.env.example:86-88` "vaultwarden refuses to boot on a non-persistent /data" — `Containerfile:147-150`
   says the opposite was verified on 1.37.2.
5. `.env.example:19` lists `SUPERVISOR_ENV_FILE` as a file key; it is read only from the process env (`dotenv.rs:33-39`).
6. CONTRIBUTING:38 says to fill in a database URL; the image is SQLite-only with a working default.
7. CONTRIBUTING image-name examples disagree between lines 30 and 110/114/117.
8. CONTRIBUTING:116-117 healthcheck example exits 1 for the wrong reason (missing auth key first).
9. README:93 "does nothing rather than guess" vs. the fatal refusal at `backup/restore.rs:67-73`.

---

## 2. The system as built

```
                    public 0.0.0.0:8080                     tailnet (WireGuard/HTTPS)
                           |                                        |
                     [ gate ]  GET /alive only                      |
                           |  (200 up / 503 down / 403 all else)    |
                           v                                        v
   PID 1 supervisor ── supervises ──> tailscaled (userspace) ──> tailscale CLI up/serve
        |                                   |
        |                                   └── tailscale serve https://<node>.<tailnet>.ts.net
        |                                                                 |
        +── supervises ──> vaultwarden (127.0.0.1:8081, API + web vault)
        |                     |  /data/db.sqlite3 (SQLite, WAL)
        |
        +── boot phases: RestoreDb -> AdoptLineage -> RestoreState -> Tailscaled -> DaemonWait
        |                 -> TailscaleUp [+sync] -> Serve
        |
        +── watch: vault exit | tailscaled death | stop -> ordered shutdown
        |          (TERM groups -> reap -> quiesce -> final DB dump -> final state push)
        |
        +── maintenance threads (detached): periodic DB backup tick, periodic state sync
        |
        +── S3 (SUPERVISOR_S3_*): <prefix>/db/sqlite-*.sqlite3  and  <prefix>/<synced /data files>
```

**Module map** (accurate as built):

- `main.rs` — `--healthcheck` one-shot vs boot.
- `boot.rs` — explicit phase machine with a stop/failure policy table.
- `config/` — `env/` (knobs, merge, `Config`), `dotenv.rs` (strict file), `dburl.rs`, `backup/` and `sync/`
  (spec/resolve), `consts.rs` (timeouts).
- `runtime/process/` — `child` (spawn + pgid), `pidfd`, `reaper` (single waitpid owner), `reap`, `run`
  (bounded CLI runs with output caps), `signals` (flag), `watch` (vault loop + shutdown + periodic threads),
  `env` (EnvGrant).
- `runtime/services/` — tailscaled + tailscale CLI, vaultwarden child and its env grant.
- `runtime/gate/` — loopback probe, TTL liveness cache, limiter, canned-response server.
- `runtime/backup/` — dump/restore/lineage/prune/staging/unchanged/timestamp + `sqlite/` (in-process
  rusqlite VACUUM INTO and no-replace import).
- `runtime/sync/` — synced-file allowlist/enumeration (`synced.rs`), pull/push (`state.rs`).
- `s3/` — minimal presigned S3 client (rusty-s3 + ureq/rustls), listing with pagination and caps.
- `util/` — log, bounded poll, Unix-socket wait, atomic-ish staged files, chmod.

History context that matters for the redesign: the project already pivoted twice — rclone → in-process S3
(03b06dd), multi-DB → SQLite-only (0e86df7) — and reorganized modules three times. The design below assumes
those decisions are settled.

---

## 3. Measured health

| Metric | Value | How |
|---|---|---|
| Rust source | 7,096 lines / 53 files | `find … \| xargs wc -l` |
| Tests | 128 passing, 0 failed, 5.0 s | `cargo test --locked` (twice, independently) |
| Lint / format | clean | `cargo clippy --all-targets --locked -- -D warnings`; `cargo fmt --check` |
| Production panics | 1 `expect` (documented invariant) | `grep -n 'unwrap\|expect\|panic!'` |
| `unsafe` | 3 blocks, all in `pidfd.rs`, all with SAFETY comments | manual read |
| Direct deps / transitive | 10 / 163 | `cargo tree` |
| Release binary | 4.9 MB, stripped, panic=abort, LTO; links only libc/libm/libgcc | `ls`, `ldd` |
| Commits / window | 154 / 21 days, single author; 43 `fix` vs 25 `feat` | `git log` |
| Secret hygiene | `.env` ignored and never committed; no secret-shaped string in any revision | `git check-ignore`, `git rev-list \| git grep` |
| Backup/sync test split | backup 36, gate 18, config 38 (of 128) | subagent enumeration, verified totals |

The fix/feat ratio and the error-message quality suggest a codebase that has been hardened rather than merely
grown. The findings below are the *remaining* structural debt, not evidence of a fragile system.

---

## 4. Findings in detail

### 4.1 State sync can destroy the offsite copy (F1, F13, F14)

`Client::get` truncates the target (`File::create`) and `io::copy` propagates an error *after* bytes have been
written (`s3/client.rs:140-143`). `restore_state` logs the failure and continues (`sync/state.rs:93-96`);
`should_pull` only checks existence (`state.rs:110-112`); the next push compares sizes and uploads the
truncated local file over the good object (`state.rs:135-155`). One interrupted boot (kill, network drop,
60 s whole-call timeout on a large attachment) can permanently lose `tailscaled.state`, `rsa_key.pem`, certs,
attachments, and Sends. This is the single most dangerous path in the repository, because the feature exists
precisely to prevent data loss on ephemeral hosts.

Related: change detection is size-only, so a locally corrupted file with a different size overwrites the
remote, and an equal-size corrupt remote object is never repaired; per-object transfer is bounded by a 60 s
transition budget that makes large attachments unsyncable.

**Fix direction:** download to a temp path, verify length (and ideally checksum) and only then atomically
rename; delete temps on failure; do not treat an unverified file as present; hash-based comparison with a
local journal; per-object size/time budgets or multipart.

### 4.2 The image default for attachments is dead code (F2)

`Containerfile:152-160` sets `ORG_ATTACHMENT_LIMIT=0` and `USER_ATTACHMENT_LIMIT=0` as **bare** names. The
supervisor clears the child environment and forwards only ambient `VAULTWARDEN_*` keys
(`process/env.rs:43-48`, `services/vaultwarden.rs:75-85`), so both are dropped. In Vaultwarden 1.37.2 an unset
limit means no limit (`Some(0)` is the "disabled" spelling — verified in upstream `src/api/core/ciphers.rs:1223,1245`).
Result: README:109 promises uploads are off; the default deployment allows unlimited uploads. The supervisor
already pins `DATA_FOLDER`, `ROCKET_ADDRESS`, `WEB_VAULT_FOLDER`, and re-derives `WEB_VAULT_ENABLED`; these two
belong in the same pin set (or the Containerfile ENV names must be prefixed; see the design — this is exactly
the class of bug a declarative config schema removes).

### 4.3 The reaper spins when idle (F3)

`reaper::run` loops with no wait (`process/reaper.rs:199-205`). With at least one registered child, `poll`
blocks for `POLL` (100 ms). With an empty registry, `ready_indices` returns before polling
(`process/pidfd.rs:51-53`) and the `WNOHANG` sweep returns immediately — a hot loop. This happens in every
graceful shutdown after both long-running children are reaped, i.e. while the final DB dump and state push run
(up to ~60 s), and briefly in smaller windows. On a CPU-limited container this can extend shutdown past the
orchestrator's grace period and cause a SIGKILL that defeats the final persist.

**Fix direction:** block on a condition variable when the registry is empty (pidfd/eventfd would be ideal);
never rely on a spin to provide latency.

### 4.4 Shutdown is a race between three writers (F5)

`take_stop()` *consumes* the single global flag (`process/signals.rs:55-57`). The watch loop consumes it at
`watch.rs:121`; from that moment every detached maintenance thread's abort closure (`stopping`) returns false,
so an in-flight periodic tick no longer aborts and can overlap the shutdown tick (`watch.rs:175-180`). The two
share `/data/db-backups.state`, `/data/db-backups.last`, staging, and the S3 keyspace with no lock
(`staging.rs:30-44` deletes every staging entry unconditionally). Outcomes include the final dump's staged file
being deleted before upload (final persist silently lost) and lineage-sidecar regressions that escalate into F4.

**Fix direction:** a monotonic shutdown state (`Running → Draining → Stopped`) that is never cleared, plus one
scheduler that owns every periodic task and runs the final flush itself. A second signal should shorten
budgets, not vanish.

### 4.5 The backup lineage guard can jam forever (F4, F6, F9, F10, F11)

The guard is the right idea — refuse to shadow a newer bucket generation — but its *only* source of truth is
`/data/db-backups.state`, a bare object name written after the PUT (`backup/dump.rs:109-118`). Three failure
modes are built in:

- **Stale sidecar** (kill between PUT and sidecar write, or a failed sidecar write): verdict refuses forever
  (`lineage.rs:66-68`). The log tells the operator to boot with `RESTORE=true` (`dump.rs:70-74`), but
  `adopt_lineage` returns early when a sidecar exists (`restore.rs:103`) — the documented remedy cannot work.
  The actual remedy (delete `db-backups.state`) is undocumented.
- **Clock rollback:** the newly pushed dump's name sorts older, prune (`prune.rs:21-23`) deletes the
  strictly-oldest name — the object just uploaded — and the sidecar then points below the bucket newest, so
  every later tick refuses.
- **Tableless existing DB:** `is_empty` returns true for a tableless SQLite file
  (`sqlite/restore.rs:16-32`), but `import` publishes with `hard_link`, which cannot replace an existing path
  (`restore.rs:62-78`) → restore "fails" → exit 1 forever (`boot.rs:83-87`). The module's own doc says that
  state is supported.

Additionally the "newest" is derived by lexicographic sort of keys matching `sqlite-*.sqlite3`
(`backup/tools.rs:18-38`): a foreign object without a timestamp can sort last, become "newest", be imported if
it parses as SQLite, and never be pruned. And a single corrupt newest object blocks boot with no attempt at the
next one (`restore.rs:45-59`).

**Fix direction:** replace name-sorting plus sidecar with a **manifest object** in the bucket
(`db/manifest.json`) carrying a monotonic generation, the current object key, size, and checksum, plus a
bounded history for pruning. Restore reads the manifest, tries the newest verifiable entry; push allocates the
next generation; the local journal records what this volume last pushed/imported, and an explicit operator
command (`SUPERVISOR_DB_BACKUP_ADOPT=true`) can re-establish lineage without heuristics. Clock skew disappears
because ordering is by generation, not time.

### 4.6 Configuration has three implementations of one rule (F7, F17, F18, F19, F23)

"env > file > default; empty = unset" is implemented in `env/merge.rs` for supervisor knobs
(`merge.rs:126-130`), again for `TAILSCALE_SERVICE` (`merge.rs:167-170` — an empty ambient value shadows the
file), and again for the child env (`services/vaultwarden.rs:52-54` + `process/env.rs:27-32` — ambient empty
values are forwarded with no filter). The child case has a concrete consequence: with an empty ambient
`VAULTWARDEN_DATABASE_URL` and a file value, the supervisor's backup resolves the file DB while the child
receives `DATABASE_URL=""` — the exact desync the code comments promise can never happen.

The dotenv layer adds pitfalls: `dotenvy::from_read_iter` does not strip a UTF-8 BOM (verified in vendored
dotenvy 0.15.7: `Iter::load` calls `remove_bom`, the bare iterator constructor does not), so a Windows-edited
file loses its first key; unreadable or non-UTF-8 files are silently discarded (`dotenv.rs:46-54`); `$VAR`
substitution rewrites unquoted values — a secret containing `$` is silently truncated; unknown keys *inside*
an accepted namespace are accepted and ignored. The logged "byte N" for a parse error is a value offset, not a
file offset.

**Fix direction:** one declarative knob table (name, scope, default, parser, secret flag); one resolver; one
place that defines empty-value handling; derive file validation, ambient routing, and child grants from the
table. Add a test that cross-checks `.env.example` against the table so documentation cannot drift.

### 4.7 The gate is correct but not adversarial (F8)

The safety property is excellent: there is no forwarding path at all, so no parser weakness reaches the vault.
But `READ_TIMEOUT` is per read (`gate/server.rs:27,102-117`), so a client dribbling one byte every 4 s holds
one of 32 slots for up to ~2.8 hours; 32 such connections starve `/alive`, the platform healthcheck sees 503,
and the orchestrator restart-loops. This is a public port by design. Also `Err(_) => continue`
(`server.rs:69`) can spin under EMFILE, and the listener has no shutdown (acceptable: `exit()` owns the
process).

**Fix direction:** one absolute deadline per connection (read timeout = remaining budget), accept-error
backoff, keep the two-response invariant enforced by a single response function.

### 4.8 The S3 client is close, with sharp edges (F12, F15, F16)

Good: presigned URLs never logged, explicit Content-Length, listing paginated and capped, abort hooks
everywhere. Sharp edges: downloads have no size cap (disk fill), 3xx is treated as success (ureq with
`max_redirects(0)` returns the response; put/delete never inspect status), `dualstack`/`fips` host forms
derive invalid regions (`client.rs:41-49`), endpoints with a path segment are silently dropped by rusty-s3's
URL join, TLS trusts public roots only (fine for R2/B2/AWS, blocks private-CA MinIO), and one whole-call
timeout conflates connect/read/write budgets.

**Fix direction:** check every status; stream downloads with a cap and verify expected size/checksum;
separate connect/read/write timeouts with bounded idempotent retries; validate the endpoint up front
(reject path segments or normalize); add an explicit region override.

### 4.9 Process supervision minutiae (F20, F22)

The core is right; the edges are worth cleaning: the stray sweep reaps without the registry lock, so a child
exiting between `spawn` and `pidfd_open` is misreported as a spawn failure (`child.rs:52-74` vs
`reaper.rs:164-171`) — have the sweep take the registry lock, since spawn holds it across registration. The
pidfd is dropped at reap, so post-reap `killpg` can hit a recycled pgid. A stop during the Serve phase exits 1
while DaemonWait/Up exit 0. `panic=abort` means `Drop`-based cleanup (staged authkey) does not run on panic —
acceptable for a dying container, but the comments claiming otherwise should be corrected. `--statedir` derives
from `Path::parent` and can be `""` for a relative state path.

### 4.10 Container, CI, supply chain (F21, F24)

Publish has provenance and digest-pinned release artifacts; PR CI has no image build at all (an earlier
workflow did this and was dropped), so a Containerfile regression surfaces at tag time. `pins.yml` re-downloads
from the same origin the Containerfile uses: it proves stability, not authenticity. Base images float while
README claims everything is checksum-checked. No SBOM. Minor: wrong OCI source label, `:latest` moved on
manual dispatch, `update-pins.sh` `mktemp` leak and no `curl --max-time`.

If the project wants the README claim to be literally true, pin base images by digest and let Renovate bump
digests on a schedule (freshness preserved, reproducibility gained), and generate an SBOM as a build step.

### 4.11 Test coverage gaps

Coverage is good at the unit level and absent where the bugs are:

- No fake-S3 server harness; the only HTTP mock is ad hoc in `backup/restore.rs` tests. Success-path PUT/GET,
  pagination, 3xx, truncation, and size caps are untested.
- No tests for the concurrency interactions: periodic tick vs shutdown tick, staging sweep, lineage writes.
- No tests for clock rollback, stale-sidecar recovery, corrupt-newest fallback, foreign objects, or restore
  into an existing tableless DB (F6 is a code/test contradiction).
- Gate: no HTTP/1.0, pipelining, >2048-byte line, slowloris-trickle, zero-limit, or accept-error tests.
- Config: BOM, non-UTF-8 file, `$` in secrets, empty ambient shadowing, `sqlite://`.
- No property tests for key/path parsing or timestamp ordering.

---

## 5. If I were writing it from scratch

The architecture stays: a small Rust PID 1 that supervises tailscaled and a loopback vault behind a
canned-response gate, with optional S3 persistence. What changes is that the three accidental foundations —
configuration layering, maintenance scheduling, and durability state — become three intentional kernels.
Everything else is polish.

### 5.1 Requirements and invariants (the spec I would write first)

Hard invariants, each with a test that fails when violated:

1. The vault runs only while tailscaled is healthy; no Tailscale, no vault.
2. The public port never forwards; its entire response set is three canned lines.
3. A restore never overwrites a database unless it is *provably* absent or empty; "ambiguous" means refuse.
4. No push ever shadows a newer bucket generation; ordering is by generation, never by wall clock.
5. A file is authoritative only after a complete, verified transfer; partial data is deleted, never published.
6. No secret in argv, logs, or any environment but the one child that needs it.
7. Every external call has a deadline and every read a size bound.
8. Shutdown: children reaped before the final persist; the final persist fits inside an explicit budget.
9. Exactly one writer per shared resource, enforced by ownership, not by convention.
10. Every failure has a name, a consequence, and a documented recovery.

Non-goals: multi-DB support, HA/multi-writer buckets, general-purpose HTTP ingress, plugin configuration,
making every upstream Vaultwarden knob first-class.

### 5.2 Three foundational choices

**(1) One config schema, no hand-written layer rules.** A static table is the single source of truth for the
whole config surface:

```rust
struct Knob {
    name: &'static str,          // "SUPERVISOR_DB_BACKUP"
    scope: Scope,                // Supervisor | Child | Both
    default: Default,            // static default or "required"
    parse: Parser,               // Bool | Count | Port | Path | Url | Free
    secret: bool,
}
static KNOBS: &[Knob] = &[ ... ];
```

From this table come: resolution (env → file → default, with empty always = unset, uniformly), dotenv
validation (unknown supervisor keys refuse, naming all of them at once), the ambient allowlist, the child env
grant (Child-scope keys stripped), secret typing (`SecretString`, no `Debug`), and a documentation test that
parses `.env.example` and fails if it and the table disagree. Adding a knob is one table row plus a doc line,
and the three-layer divergence class becomes unrepresentable.

**(2) One maintenance reactor, no detached threads.** All periodic work — DB backup, state sync, nothing
else — runs as tasks in a single scheduler thread:

```rust
enum Lifecycle { Running, Draining { deadline: Instant }, Stopped }  // monotonic; never reset

struct Reactor { tasks: Vec<Task>, cancel: CancelToken, store: Arc<Store> }
struct Task { name: &'static str, next: Instant, cadence: Duration,
              run: fn(&TaskCtx) -> Result<(), TaskError> }
```

- Exactly one thread touches `/data` durability artifacts and bucket objects after boot; the boot phase
  machine runs before the reactor starts, so writers never overlap.
- Stop requests set a monotonic `Draining` state. Tasks see it and stop cleanly; the reactor then runs the
  final flush itself, ordered (DB dump, then state push) and budgeted from the remaining grace.
- A second signal shortens the drain budget; it never disappears.
- `TaskCtx` carries a per-task deadline, the remaining budget, and the redacting logger.

This removes F3, F5, and the whole race class without changing what the tasks do.

**(3) Durable state is explicit, versioned, and recoverable.** Two manifests and one local journal:

```
Bucket:  <prefix>/db/manifest.json        <prefix>/state/manifest.json
         <prefix>/db/objects/<sha256>     <prefix>/state/objects/<sha256>
Local:   /data/.supervisor/journal.json   (schema-versioned; temp+fsync+rename)
```

- Backup manifest: `{ schema, generation, entries: [{ generation, key, sha256, size, created }] }`, history
  bounded (KEEP + slack). Push allocates `generation = max(known)+1`, uploads the object with a checksum,
  then rewrites the manifest in one PUT; prune deletes only the evicted generations *after* the manifest
  write. Restore reads the manifest and tries entries newest-first until one verifies.
- Lineage: the journal stores the generation this volume last pushed or imported. `known >= manifest.generation`
  → proceed. A stale or missing journal cannot jam the system silently forever: recovery is an explicit
  `SUPERVISOR_DB_BACKUP_ADOPT=true` (logged, deliberate) that stamps the journal with the manifest generation.
  No heuristic adoption, no time ordering.
- Sync manifest: `{ schema, generation, files: { path: { sha256, size, mtime } } }`; objects are
  content-addressed and immutable. Pull: read manifest, fetch missing files into `/data/.supervisor/tmp`,
  verify size+sha256, then atomic rename; failure deletes the temp. Push: compare `(size, mtime)` against the
  journal cache, hash only changed files, upload if the object is absent, then update the manifest. Local files
  are authoritative (as today), but the system can no longer *manufacture* a truncated authoritative file.
  Deletes are tombstones only if explicitly enabled; default retains remote history.
- Journal corruption/missing: rebuild from the manifests; only if that fails, refuse loudly with the manual
  recovery spelled out.

All object writes go through one `Store` API that enforces: status checking, size caps, checksums, retries
with jitter on idempotent operations, and separate connect/read/write budgets. The reactor is its only caller.

### 5.3 Module layout

```
src/
  main.rs                  arg dispatch (--healthcheck | boot)
  boot.rs                  phase machine (unchanged shape, stop-aware exit codes)
  config/
    schema.rs              KNOBS table + types (incl. SecretString)
    dotenv.rs              source: strict parsing, BOM/UTF-8 handled, one error list
    resolve.rs             one resolver over sources; produces Config + errors
  supervise/
    child.rs               spawn (registry lock across spawn+pidfd), Handle with live pidfd
    reaper.rs              single waitpid owner; idle waits on a condvar, never spins
    run.rs                 bounded CLI runs
    services/{tailscale,vaultwarden}.rs   # grants derived from the schema table
    watch.rs               vault loop; owns the stop lifecycle; hands drain to reactor
  reactor/
    mod.rs                 Lifecycle, Reactor, TaskCtx, budget arithmetic
    backup.rs              cycle, generation allocation, manifest, prune, restore
    sync.rs                cycle, manifest, journal
  store/
    s3.rs                  Store impl: status, caps, checksums, retries, budgets
    journal.rs             versioned local state, atomic writes
  gate.rs                  canned-response server with absolute per-connection deadline
  util/                    log (redaction), clock (injectable), fs (atomic), time checks
```

Notable differences from today: no logic in `mod.rs` files (already true), `Store` is a trait so the fake-S3
harness is trivial, `Clock` is injectable for rollback tests, and config grants are derived, not hand-written.

### 5.4 Testing strategy

- **Fake S3 in-process** (std `TcpListener`) with programmed responses: normal, paginated, 3xx, 5xx+retry,
  truncated body, slow body, token loop, wrong checksum. Both backup and sync suites run against it.
- **Scenario tests** (the bugs this audit found, as regressions): interrupted pull then next push; crash
  between object PUT and manifest write; stale journal adoption; clock rollback; corrupt newest entry with
  fallback; tableless DB restore; two schedules that would overlap under the old design; stop during each boot
  phase; second signal during drain.
- **Fault-injection seams:** `Clock`, `Store`, and randomness injected as values, not globals.
- **Property tests:** synced-path allowlist over arbitrary `OsStr` (traversal, symlinks, FIFOs, absolute
  paths), timestamp/generation ordering, config resolution tables.
- **Docs contract test:** parse `.env.example`; keys and comments must match the schema table.
- **CI:** `fmt` → `clippy -D warnings` → `test --locked` → build the image and smoke the entrypoint on PRs →
  SBOM + provenance on publish. Keep every current gate.

### 5.5 Process supervision design

Keep the single-reaper pidfd hub — it is the best-engineered part of the current system. Changes:

- Registry lock held across spawn + `pidfd_open` + insert (already true) **and** taken by the sweep before
  `waitpid(-1, WNOHANG)`, closing the misreport race (F20).
- The reaper blocks on a condition variable when the registry is empty (F3). Latency never depends on a spin.
- `Handle` keeps the pidfd until drop; `signal_group` becomes "signal only if not yet reaped" so a recycled
  pgid can never be hit; escalation stays TERM → KILL with the same constant names.
- Stop lifecycle is monotonic (`Running → Draining → Stopped`); the reactor's final flush runs inside
  `Draining` with the remaining budget; a second signal shrinks it; every boot phase checks the same state and
  exits 0 for "stopped during boot" (including Serve), 1 for genuine failure.
- `--healthcheck` stays a pure, side-effect-free probe.

### 5.6 Gate design

Same invariant (three canned responses, GET /alive only, never forward), plus:

- absolute per-connection deadline (initial read included), so a trickle cannot hold a slot;
- accept-error backoff; a small admission cap (32 is fine) with immediate 503;
- `Liveness` with a TTL cache as today; the probe is the only thing that ever talks to the vault;
- a single `respond(code, text)` function so "no other bytes can be written" is auditable at one line.

### 5.7 Config design

- One schema table, one resolver, one error report (all violations at once: unknown keys, invalid values,
  missing required knobs — each named).
- Dotenv: read bytes, strip BOM, decode UTF-8 strictly (a non-UTF-8 file is an error, not a silent
  downgrade), parse with `dotenvy` but with substitution disabled or explicitly documented and tested; log
  parse errors with file line numbers (compute from the iterator's logical-line index, not a value offset).
- Grants: `Child`-scope values resolve exactly like supervisor values (env → file → default, empty = unset
  everywhere), then pins are applied last. A unit test asserts supervisor and child resolve the same
  `DATABASE_URL` for every source combination (the F7 regression test).
- Secrets are typed `SecretString` from the schema; `log::sanitize` remains for free-form fields.
- The `.env.example` contract test keeps the user docs honest.

### 5.8 Build, CI, supply chain

- Pin base images by digest; Renovate updates digests on a schedule (keep the "CVE freshness" intent, gain
  reproducibility). Keep `--format docker` and both healthcheck declarations.
- Keep `sha256sum -c` for release artifacts; resolve source artifacts by commit SHA (`VW_COMMIT=…`) where
  upstream publishes only moving tags, and document the residual TOFU at first pin.
- Publish: verify `VW_VERSION` matches the image label/tag, run the container once with a fake vault before
  pushing, produce an SBOM, keep provenance; do not move `:latest` from a manual dispatch unless explicitly
  intended, and clean per-arch tags.
- PR CI: restore a real image build + `--healthcheck` smoke run.

### 5.9 What I would keep exactly as it is

- Boot as an explicit phase machine with a policy table.
- The `--healthcheck` one-shot mode and the exec-form HEALTHCHECK.
- `process/reaper.rs`'s single-owner design; `run.rs`'s bounded captures with caps; `EnvGrant`'s
  clear-then-grant model.
- Authkey staging (0600, `create_new`, path-only argv, unlink on drop).
- `VACUUM INTO` on a read-only handle and no-replace hard-link publication with `integrity_check`.
- The strict three-namespace config surface and the default-deny child environment.
- `panic=abort`, LTO/fat release profile, and the tiny dependency set.
- README/CONTRIBUTING split and tone, with the drift fixed.

### 5.10 Migration path (incremental, no rewrite)

Each step is independently shippable and test-backed:

1. **Correctness patches (days).** Pin the attachment limits in `granted_env`; absolute gate deadline;
   reaper idle wait; sweep takes the registry lock; guard `signal_group` on status; fix the Serve-phase exit
   code; docs drift. Add regression tests for each.
2. **Single reactor (a focused change).** Move the two periodic threads into one scheduler with a monotonic
   lifecycle; run the final flush from it. This is the highest-leverage structural change; it retires the
   stop-flag and staging races together.
3. **Sync transfer hardening.** Temp download + verify + rename; 0600; status checks; size caps; per-object
   budgets; then the manifest + journal (the object layout can stay compatible: keep old keys readable,
   write new content-addressed objects behind the manifest).
4. **Backup generation manifest.** Read old layout if the manifest is absent (migration), write the manifest
   from the next push, switch restore/prune/lineage to it; explicit adopt command; corrupt-newest fallback.
5. **Config schema.** Introduce the table, keep the current behavior in a compatibility test, then derive
   routes/grants from it and add the docs contract test.
6. **Supply chain.** Digest-pinned bases + Renovate digests; PR image build; SBOM.

The current test suite (128 tests) is a genuine asset here: every step above can land with its regression test,
and the phase machine, reaper, and import mechanisms do not need to be touched at all.

---

## 6. Phase status (2026-09-27)

### Phase 1 — correctness patches

The correctness patches from the migration plan's step 1 are implemented:

| Finding | Change | Regression test |
|---|---|---|
| F2 | `IMAGE_DEFAULTS` in `runtime/services/vaultwarden.rs` re-applies the Containerfile's declared defaults (attachment limits, org creation, signups, TZ) as the grant's weakest layer, so they actually reach the default-deny child; the Containerfile comment now names the sync point | `image_defaults_apply_and_user_config_wins` |
| F7 | Empty = unset on every grant layer (file and ambient values filtered); `TAILSCALE_SERVICE` resolves env-first through `non_empty` so an empty env value can no longer shadow the file | `empty_values_never_shadow_a_lower_layer`, `empty_env_service_falls_back_to_the_file`, `empty_env_db_url_falls_back_to_the_file` (the last is a guard: the supervisor side was already correct) |
| F3 | The reaper sleeps one `POLL` slice when the registry is empty instead of spinning through the shutdown persist | none — structural, no deterministic in-process assertion without instrumentation |
| F20 | The stray sweep holds the registry lock across `waitpid`, closing the spawn-vs-sweep window | `instant_exit_burst_is_never_misreported_as_a_spawn_failure` (probabilistic guard) |
| F22 (pgid recycling) | `signal_child` refuses to signal a reaped handle; every call site converted | `signal_child_refuses_reaped_children` |
| F22 (Serve stop) | A stop observed during the Serve phase exits 0, like DaemonWait/Up | none — the phase machine needs real Tailscale I/O |
| F8 | One absolute budget for the whole request head; a timed-out head is answered 403 | `a_trickling_request_cannot_extend_the_head_budget` |
| Docs drift | README lines 5/48/73/93/109, `.env.example` 19/86-88, CONTRIBUTING 38/110-117, Containerfile defaults comment | n/a |

Committed as `2f35690` (supervisor), `b31d009` (docs), `fdb5a11` (this document).

### Phase 2 — single maintenance reactor

- **F5 and the staging race (backup report M1):** `runtime/maintenance.rs` replaces the two detached periodic
  threads with one scheduler thread that owns the DB backup and state-sync tasks *and* the final shutdown flush.
  The stop token is monotonic (never consumed, unlike the process flag), so an in-flight tick aborts at its next
  check; the drain waits for it and then runs the finals in task order (DB dump before state push) on the same
  thread. Exactly one writer per durability resource after boot; interval and shutdown ticks can no longer
  overlap, so one can never sweep away the other's staged dump.
- **Shutdown is bounded:** the final persists get an explicit budget (`PERSIST_BUDGET`, 120 s); a stop request
  observed while draining shortens it to `PERSIST_FORCED_BUDGET` (15 s). The watch loop asks the reactor to stop
  the moment shutdown is decided, not after child teardown.
- Tests: `drain_stops_in_flight_work_and_flushes_once`, `a_cadence_less_task_only_flushes`,
  `final_flush_aborts_at_the_budget`, `a_hurry_up_shortens_the_flush_budget`.
- Verification: `cargo fmt --check` (exit 0), `cargo clippy --all-targets --locked -- -D warnings` (exit 0),
  `cargo test --locked` → **139 passed, 0 failed**, 10 consecutive runs.

Deliberately not yet done: F1/F13/F14/F15 (sync transfer and S3 semantics), F4/F6/F9–F12 (backup generation
manifests), F17/F18/F19 (dotenv hardening), F16/F21/F24 (S3 endpoint/CI/supply chain).

## Appendix A — evidence commands

```sh
# revision
git log -1 --format='%H %s'                 # aa2ac6a chore: bump supervisor to 1.0.3

# gates (all run first-hand)
cd supervisor
cargo fmt --check --all                     # exit 0
cargo clippy --all-targets --locked -- -D warnings   # exit 0
cargo test --locked                         # 128 passed; 0 failed; 5.01s

# health metrics
find src -name '*.rs' -exec wc -l {} + | tail -1     # 7096 total
grep -rn '#\[test\]' src | wc -l                     # 128
grep -rn 'unsafe' src                                # 3 blocks, pidfd.rs only
ls -la target/release/supervisor; ldd target/release/supervisor

# secret hygiene
git check-ignore -v .env
git rev-list --all | while read c; do git grep -nE 'tskey-|AKIA|BEGIN [A-Z ]*PRIVATE KEY' "$c"; done

# upstream attachment semantics (pinned 1.37.2)
curl -fsSL https://raw.githubusercontent.com/dani-garcia/vaultwarden/1.37.2/src/api/core/ciphers.rs | \
  grep -n 'Some(0) => err!("Attachments are disabled")'   # lines 1223, 1245
```

## Appendix B — findings to fix, ordered

1. F2 attachment defaults (security-relevant, one-line fix) — do first.
2. F1 sync partial-download clobbering (data loss) — temp+verify+rename.
3. F4/F5/F9 backup lineage and shutdown races — reactor + manifest.
4. F3 reaper spin, F20 sweep race, F8 slowloris, F7 config empty-value divergence.
5. F6 tableless restore loop, F10 fallback, F11 foreign objects, F12 caps.
6. F13–F19, F21–F24.
