# Contributing

Thanks for helping out.

- Development setup, build, checks, source map, and house rules:
  [docs/development.md](docs/development.md).
- Release and retention process: [docs/releasing.md](docs/releasing.md).
- User-facing behavior: [README.md](README.md).
- Security reports: [SECURITY.md](SECURITY.md). Never open a public issue for
  a vulnerability.

Before opening a pull request:

1. Run the checks in the development guide (`fmt`, `clippy`, `test`, `doc`,
   `build`).
2. Build and smoke-test the image if you touched the Containerfile or image
   wiring.
3. Keep version `ARG` lines byte-for-byte as Renovate expects them, and run
   `scripts/update-pins.sh` after a version bump.
4. Update the README or `docs/` in the same change when user-visible behavior
   changes.
5. Describe what changed and why in the pull request.
