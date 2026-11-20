# Security policy

## Supported versions

Security fixes land on the latest release and on `main`. Older image tags are
not maintained; upgrade to the newest release.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

<https://github.com/edgarcnp/vaultwarden-hummingbird/security/advisories/new>

Do not open a public issue for a vulnerability. If the Security tab does not
offer private reporting, open a minimal issue asking for a private contact and
leave out exploit details.

Include:

- the image tag or commit;
- architecture, platform, and Podman or Docker version;
- reproduction steps and relevant logs, with secrets and bucket names removed;
- the impact you observed and any suggested fix.

Reports are reviewed on a best-effort basis; this is a volunteer project, so
there is no response-time guarantee. Please allow time for a fix before public
disclosure.

## Scope

In scope: the supervisor (`supervisor/`), the image and its build, the
compose/run layout, and the documented defaults.

Out of scope: vulnerabilities in Vaultwarden, Tailscale, the base images, or
your S3 provider; report those upstream. A misconfigured bucket, a leaked auth
key, or a host that already gives an attacker root is not a container escape.

## Trust boundaries

- Tailscale is the only ingress. The vault binds loopback; the public port
  answers only `/alive`.
- The supervisor is PID 1 and keeps `SETUID`, `SETGID`, `KILL`, and
  `DAC_READ_SEARCH`. Children run with no capabilities and `no_new_privs`.
- The S3 bucket holds the node identity, signing keys, and vault files. Treat
  write access to it as equivalent to access to the vault.
- A world-readable `.env` is detected and logged, not refused. Prefer `0600`
  owned by `65532`, or `0640` with group `65532`.

Architecture and failure rules: [docs/architecture.md](docs/architecture.md).
