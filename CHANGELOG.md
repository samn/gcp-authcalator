# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- All config options can now be set via `GCP_AUTHCALATOR_*` environment variables (e.g. `GCP_AUTHCALATOR_PROJECT_ID`, `GCP_AUTHCALATOR_PORT`)

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
