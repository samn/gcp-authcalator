# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- PAM (Privileged Access Manager) integration for just-in-time prod escalation via `--pam-policy`. When configured, the gate requests a temporary PAM grant before minting prod tokens, allowing the engineer's ADC to be downscoped by default. Includes entitlement allowlist enforcement, confirmation dialogs showing the entitlement name, audit logging of grant details, and best-effort grant revocation on shutdown.
- Custom OAuth scopes via `scopes` config field (TOML array) and `--scopes` CLI flag (comma-separated). Tokens are now minted with the requested scopes instead of always using `cloud-platform`. Useful for tools requiring narrower scopes like `sqlservice.login`.

### Changed

- Release artifacts are now compressed with gzip (`.tar.gz`), significantly reducing download size

### Fixed

- Token `expires_in` could return negative values in gate and metadata-proxy handlers when a cached token was near expiry; now clamped to a minimum of 0
- Release test suite failing in environments with GPG commit signing enabled
- Kube-setup read-only file test failing when running as root

### Changed

- Improved test coverage: overall line coverage from 97.65% to 98.34%, with new tests for TLS certificate validation, audit logging error paths, token expiry edge cases, `validateClientBundle`, and command summarization edge cases

## [0.3.0] - 2026-03-09

### Added

- All config options can now be set via `GCP_AUTHCALATOR_*` environment variables (e.g. `GCP_AUTHCALATOR_PROJECT_ID`, `GCP_AUTHCALATOR_PORT`)
- Startup validation of mTLS certificates: verifies PEM parseability, expiry, CA BasicConstraints, and that server/client certs are signed by the CA — fails with a descriptive error and non-zero exit code if invalid
- Client bundle validation on metadata-proxy and with-prod startup: verifies bundle certs are well-formed, not expired, and properly chain to the bundle CA

### Changed

- Config precedence is now: environment variables > CLI args > TOML file > defaults

## [0.2.0] - 2026-03-09

### Added

- TCP + mutual TLS transport for remote devcontainer support (SSH, Codespaces, Coder)
- `init-tls` command for TLS certificate management
- `--gate-tls-port` flag for gate to enable TCP listener alongside Unix socket
- `--gate-url` and `--tls-bundle` flags for metadata-proxy and with-prod
- `GCP_AUTHCALATOR_GATE_URL` and `GCP_AUTHCALATOR_TLS_BUNDLE_B64` env vars for zero-config remote setup
- Auto-generation and rotation of TLS certificates (ECDSA P-256, 90-day lifetime)

### Changed

- Upgrade Bun from 1.3.9 to 1.3.10

## [0.1.5] - 2026-02-24

### Fixed

- `with-prod`: set `GCE_METADATA_ROOT` alongside `GCE_METADATA_HOST` and `GCE_METADATA_IP` for compatibility with GCP auth libraries that use this variable

### Changed

- Replace ESLint and Prettier with oxlint and oxfmt from the [Oxc](https://oxc.rs/) toolchain

## [0.1.4] - 2026-02-20

- `with-prod`: nested sessions automatically reuse the parent's prod token and metadata proxy, eliminating redundant confirmation dialogs
- `version`: show git commit SHA alongside the version number (e.g. `0.1.3 (abc1234)`)

## [0.1.3] - 2026-02-19

### Fixed

- `metadata-proxy`: accept `/computeMetadata/v1/universe/universe-domain` (hyphenated) as an alias for the underscore variant, since some tooling expects the hyphenated form

## [0.1.2] - 2026-02-18

### Changed

- Renamed runtime directory fallback from `~/.gcp-gate/` to `~/.gcp-authcalator/` for consistency with the project name
- Audit log now respects `$XDG_RUNTIME_DIR` (same as the socket), falling back to `~/.gcp-authcalator/audit.log`

### Fixed

- `metadata-proxy`: use `/computeMetadata/v1/universe/universe_domain` (underscore) to match the real GCE metadata server path
- `with-prod`: set `CLOUDSDK_CORE_ACCOUNT` and `CLOUDSDK_CORE_PROJECT` so `gcloud auth list` shows the engineer's elevated account instead of the dev service account
- `with-prod`: write access token to a file and configure `auth/access_token_file` in gcloud config so commands that don't use the metadata server still authenticate correctly

## [0.1.1] - 2026-02-17

### Fixed

- Expand `~` to the user's home directory in `socket_path` from config files and CLI args

## [0.1.0] - 2026-02-17

- `gate` command: host-side token daemon with desktop confirmation dialogs
- `metadata-proxy` command: GCE metadata server emulator for containers
- `with-prod` command: wrap commands with production credentials
- TOML configuration file support
- PID-based process restriction for metadata proxy
- Audit logging for token requests
- `kube-setup` command: patch kubeconfig to use gcp-authcalator for GKE auth
- `kube-token` command: kubectl exec credential plugin for fetching tokens from the metadata proxy
- `version` subcommand and `--version` flag
- Compiled single-executable binaries for Linux amd64 and macOS arm64
- Automated release process via GitHub Actions
