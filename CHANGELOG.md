# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Upgraded Bun from 1.3.11 to 1.3.13.

### Fixed

- Documentation: corrected rate limiting values in README and SPEC (1-second cooldown and 10 attempts/minute, matching implementation)
- Documentation: updated approve/deny command docs to reflect admin socket isolation from v0.7.2 (separate socket, not the main gate socket)
- Documentation: removed stale `GET /pending` endpoint from API tables (removed in v0.7.2)
- Documentation: fixed pending request ID size in SPEC (32-character hex / 128 bits, not 8-character)
- Documentation: added missing `--admin-socket-path` CLI flag and `GCP_AUTHCALATOR_ADMIN_SOCKET_PATH` env var to README
- Documentation: added missing `GCP_AUTHCALATOR_GATE_TLS_PORT` and `GCP_AUTHCALATOR_TLS_DIR` env vars to SPEC remote transport table
- Documentation: added Docker image build step to releasing guide
- Fixed stale comment in rate limiter (said "max 5" but constant is 10)

## [0.7.2] - 2026-04-01

### Changed

- `approve` and `deny` commands now connect to a separate admin socket instead of the main gate socket. The admin socket is not mounted into devcontainers, preventing container processes from self-approving requests.
- `with-prod` now generates and prints a pending approval ID before requesting a prod session, enabling CLI-based approval without a two-phase protocol.
- Pending request IDs increased from 8 hex chars (32 bits) to 32 hex chars (128 bits).
- Removed `GET /pending` listing endpoint. With single-flight ensuring at most one pending request, the ID is printed by `with-prod` directly.

### Security

- **Admin socket isolation**: Approve/deny endpoints moved from the main gate socket (mounted into containers) to a separate admin socket in `/tmp` (not mounted). This prevents a malicious process in the devcontainer from self-approving its own prod token request.
- Client-generated pending IDs (`X-Pending-Id` header) allow `with-prod` to display the approval ID immediately. The gate validates format and rejects duplicates.

## [0.7.1] - 2026-04-01

### Fixed

- Resolve linker error in Docker images

## [0.7.0] - 2026-04-01

### Added

- Multi-arch Docker image (`linux/amd64`, `linux/arm64`) published to `ghcr.io/samn/gcp-authcalator` on every release, using a minimal distroless base image
- `Dockerfile` for packaging the compiled binary
- `gate`: CLI fallback for approving prod escalation requests. When GUI dialogs and terminal prompts are unavailable (headless environments), requests are queued and can be listed/approved/denied via the new `approve` and `deny` subcommands. New gate endpoints: `GET /pending`, `POST /pending/:id/approve`, `POST /pending/:id/deny`.
- New `approve` and `deny` subcommands to list, approve, or deny pending prod access requests on the gate server (`gcp-authcalator approve`, `gcp-authcalator approve <id>`, `gcp-authcalator deny <id>`).

## [0.6.0] - 2026-03-27

### Added

- `with-prod`: auto-refresh of prod credentials via gate sessions. Long-running processes no longer lose access when tokens expire. Individual tokens remain short-lived for security; the session allows transparent re-minting without re-confirmation.
- `gate`: new `POST /session` and `DELETE /session` endpoints for prod session lifecycle, and `GET /token?session=<id>` for session-based token refresh.
- New `--session-ttl-seconds` config option (default: 28800 / 8 hours) to control how long a prod session allows token refreshes before requiring re-confirmation.

## [0.5.0] - 2026-03-26

### Added

- `with-prod`: extra environment variables via `[env]` TOML table or `--env` / `-e` CLI flag, with `${VAR}` / `${VAR:-default}` substitution resolved within the elevated environment. Useful for tools like GDAL that need env vars referencing the metadata proxy address.

## [0.4.3] - 2026-03-19

### Added

- `host.docker.internal` as a SAN on the server TLS certificate, enabling connections from Docker containers via the host networking bridge.

## [0.4.2] - 2026-03-19

### Added

- `--tls-dir` now works as a TLS client bundle source for metadata-proxy when `gate_url` is set. The client bundle is resolved in priority order: `GCP_AUTHCALATOR_TLS_BUNDLE_B64` env var > `--tls-bundle` path > `--tls-dir` directory (looks for `client-bundle.pem`).

## [0.4.1] - 2026-03-19

### Added

- Linux ARM64 release binary (`gcp-authcalator-linux-arm64`)

### Changed

- Upgrade Bun from 1.3.10 to 1.3.11 (4 MB smaller compiled binaries on Linux, HTTP/2 and security fixes)
- Upgrade google-auth-library from 10.5.0 to 10.6.2
- Upgrade oxlint from 1.50.0 to 1.56.0 and oxfmt from 0.35.0 to 0.41.0
- Pin `@types/bun` to `^1.3.11` instead of `latest` for reproducible installs
- Rename `.mise.toml` to `mise.toml` (mise canonical name)

## [0.4.0] - 2026-03-18

### Added

- PAM (Privileged Access Manager) integration for just-in-time prod escalation via `--pam-policy`. When configured, the gate requests a temporary PAM grant before minting prod tokens, allowing the engineer's ADC to be downscoped by default. Includes entitlement allowlist enforcement, confirmation dialogs showing the entitlement name, audit logging of grant details, and best-effort grant revocation on shutdown.
- Custom OAuth scopes via `scopes` config field (TOML array) and `--scopes` CLI flag (comma-separated). Tokens are now minted with the requested scopes instead of always using `cloud-platform`. Useful for tools requiring narrower scopes like `sqlservice.login`.
- Configurable token TTL via `--token-ttl-seconds` CLI flag, `token_ttl_seconds` TOML config key, or `GCP_AUTHCALATOR_TOKEN_TTL_SECONDS` env var (default: 3600s). Controls the lifetime of minted tokens and PAM grants. `with-prod` can override the TTL to a shorter value (validated LTE the gate's configured maximum). Note: for prod ADC tokens, the TTL cap is advisory — the underlying Google-issued token may remain valid beyond the reported expiry, but gcp-authcalator treats the cap as authoritative.

### Changed

- Release artifacts are now compressed with gzip (`.tar.gz`), significantly reducing download size

### Fixed

- Token `expires_in` could return negative values in gate and metadata-proxy handlers when a cached token was near expiry; now clamped to a minimum of 0
- Release test suite failing in environments with GPG commit signing enabled
- Kube-setup read-only file test failing when running as root
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

### Added

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
