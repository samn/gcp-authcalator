# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- **Folder mode.** The gate can be configured with `--folder-id <numeric-id>`
  (or `folder_id` in TOML / `GCP_AUTHCALATOR_FOLDER_ID` env) instead of
  `--project-id`. In folder mode the gate brokers PAM entitlements at the
  folder level (`folders/{id}/locations/{loc}/entitlements/{id}`) and
  accepts a per-request `?project=<id>` query parameter naming a
  descendant project, verified via Cloud Resource Manager v3 (cached:
  10-min positive / 30-sec negative TTL, with a 5-minute stale-OK window
  on transient CRM 5xx). `service_account` is rejected in folder mode
  (no dev tier — engineer's standing ADC is the non-elevated path; PAM
  is the only elevation route). `pam_policy` is required. The
  long-running `metadata-proxy` command is rejected in folder mode —
  folder-mode users go through `with-prod` exclusively.
- `with-prod` gains `--project <id>` (per-invocation target project).
  Resolution ladder in folder mode: `--project` flag →
  `CLOUDSDK_CORE_PROJECT` → `gcloud config get-value project` → error.
  In project mode `--project` is accepted only when it matches the
  configured `--project-id`.
- Confirmation prompts (zenity / osascript / terminal) now display the
  target project on every elevation, so operators see which tenant they
  are authorising.
- Audit log entries carry `project_id` in both modes for cross-mode grep
  symmetry.

### Changed

- `auth.getProjectNumber` now takes a `projectId` argument with a
  per-project in-memory cache (was: single cached value for the
  configured project). Required for folder mode where the gate may
  resolve many descendant projects over its lifetime.
- Session refresh (`GET /token?session=<id>`) rejects `?project=`
  overrides — sessions are bound to the project chosen at creation.
- PAM entitlement resolution now takes a discriminated `Scope` object
  (`{ kind: "project", projectId } | { kind: "folder", folderId }`).
  Cross-scope paths (e.g. a `projects/...` path on a folder-mode gate)
  are rejected.

## [0.10.0] - 2026-05-14

This release corrects issues that prevented PAM grants from getting reliably refreshed, upgrades the runtime, and includes a handful of security fixes.

### Changed

- **Config precedence change (BREAKING for callers that relied on env
  vars overriding `--flag`).** Was `env > CLI > TOML > defaults`;
  is now `CLI > env > TOML > defaults`, matching universal CLI
  convention. Operators who explicitly pass `--gate-url ...` (or any
  other flag) now get the value they typed, regardless of inherited
  env vars.
- **Prod tokens are now clamped to PAM grant expiry minus a 5-minute
  drain margin (was: clamped to grant expiry).** PAM allows only one
  active grant per `(entitlement, requester)`, so grant renewal has
  no overlap window: concurrent clients holding a still-valid token
  at the moment the gate revokes-and-recreates would see opaque
  `PERMISSION_DENIED` errors for the duration of the rotation. The
  drain-margin clamp pushes minted token expiries before the rotation
  window so that by the time the gate revokes the old grant, no token
  minted under it is still valid. Net effect: clients refresh ~5 min
  earlier than before; concurrent clients no longer see auth flake
  during grant rotation. Three handler paths share the same clamp
  (`/token?level=prod`, `/session`, `/token?session=...`).
- Upgraded `bun` 1.3.13 → 1.3.14
- **`with-prod` now resolves its sandbox parent directory separately
  from the gate's runtime dir** (`$XDG_RUNTIME_DIR` →
  `$XDG_CACHE_HOME/gcp-authcalator` → `~/.cache/gcp-authcalator`).
  Previously both the gate's socket/config and `with-prod`'s per-
  invocation gcloud sandbox shared `getDefaultRuntimeDir()`, which
  broke the two-user shared-gate pattern: when the operator's
  `~/.gcp-authcalator/` is reachable to the agent only via a symlink
  to the operator's home, the agent's `with-prod` couldn't pass the
  symlink check (and even if it had, the target was operator-owned
  `0o750` and not writable by the agent). The sandbox now always
  lands inside the caller's own private space, regardless of how
  the gate's socket dir is shared. `with-prod` also no longer
  applies the strict `ensurePrivateDir` mode check to this parent —
  it lives in the caller's own home (where an attacker-pre-create
  threat does not apply), and the actual security boundary is the
  `mkdtempSync` sandbox inside (`0o700` owned by the caller, with
  `0o600` token files). This lets `with-prod` tolerate the parent
  already existing at `0o755` (typical when `umask 002` is set
  system-wide in the container).
- **Main gate socket is now mode `0660` (group-readable) in a `0750`
  directory, instead of `0600` in a `0700` directory.** A different-UID
  agent that shares the gate UID's primary group (e.g. a `the-robot`
  user in a dev container, added to the operator's primary group) can
  now connect to the main socket without a post-create `chmod` step.
  On Linux distros with per-user primary groups (UPG; default on
  Debian/Ubuntu/RHEL/Arch/etc.), the gate UID's primary group contains
  only the gate UID itself, so this is _effectively_ `0600` — no
  change in who can connect. The privileged operator socket stays
  `0600` in UID mode (kernel-blocks any non-gate UID, including agents
  in the primary group). The `$XDG_RUNTIME_DIR` directory itself
  (system-managed, shared with other apps) is left at `0700` per the
  XDG spec — group access requires placing `socket_path` in a
  gate-managed directory like `~/.gcp-authcalator/`.

### Fixed

- **PAM `grants.revoke` is now correctly awaited as a long-running
  Operation.** Revoke returns a `google.longrunning.Operation` with
  `done:false` initially; we previously treated it as fire-and-forget,
  so the follow-up `createGrant` would race the revoke and 409 with
  "open Grant" because PAM still considered the old grant alive. The
  gate now polls the returned Operation to `done:true` (best-effort,
  30-s deadline, tolerant of `error` field — e.g. already-terminal
  grants) before retrying create. Verified end-to-end against a real
  entitlement: the Operation typically settles within ~3 seconds, and
  an immediate create succeeds without conflict. This collapses the
  multi-round retry logic that previously papered over the race.
- **PAM grant rotation is now single-flight per entitlement.**
  Concurrent `ensureGrant` callers that miss the cache fast-path
  coalesce onto a single rotation Promise, eliminating redundant
  `createGrant` / revoke API calls when multiple clients request a
  token at the same moment a cached grant enters its drain window.

### Security

- **Default `admin_socket_path` moved to `$XDG_RUNTIME_DIR/gcp-authcalator-admin/admin.sock`.**
  The previous default (`/tmp/gcp-authcalator-admin-<uid>/admin.sock`)
  lived in a world-writable directory: on a multi-user host another
  local user could pre-create the parent directory mode `0o777` before
  the gate started and intercept or DoS the admin socket. The new
  default sits in the user-private runtime dir (already `0o700` owned
  by the user, kernel-enforced). Deployments that pin the admin
  socket explicitly via config or `--admin-socket-path` are
  unaffected.
- Gate, with-prod, audit log, and TLS dirs now reject pre-existing
  directories that are symlinks, owned by another uid, or have
  permission bits looser than the requested mode. The previous code
  silently used such a directory because `mkdirSync({recursive:true})`
  ignores its `mode` argument when the directory already exists, which
  would have allowed an attacker who pre-created an inherited dir
  with weak perms to survive across daemon restarts.
- The gate sets `process.umask(0o077)` at startup so the AF_UNIX
  socket file created by `Bun.serve` is bound at `0o700` instead of
  `0o755`, closing the brief window between bind and `chmodSync(...,
0o600)` during which the socket file mode was looser than intended.
  `with-prod` does the same around the token-bearing files it
  creates and restores the operator's original umask before spawning
  the wrapped command.
- `GCP_AUTHCALATOR_TLS_BUNDLE_B64` is now captured into a
  module-private slot and deleted from `process.env` at CLI module
  load — before `formatVersion()` runs `git rev-parse` — so child
  processes spawned during version reporting do not inherit the
  bundle via `/proc/<pid>/environ`. The bundle is still resolvable
  from the captured slot for the lifetime of the process.
- `GCP_AUTHCALATOR_PROD_SESSION` (the nested-session sentinel
  `with-prod` reads to short-circuit reuse) is now restricted to
  loopback hosts (`127.0.0.1`, `::1`, `localhost`). A same-UID
  attacker who plants a non-loopback value in the env can no longer
  redirect the wrapped command's metadata traffic to a remote
  attacker-controlled server.
- The metadata-proxy PID validator now filters
  `/proc/net/tcp[6]` rows by `ESTABLISHED` state. LISTEN /
  TIME_WAIT / CLOSE_WAIT rows that share a local-address tuple with
  the connection of interest are no longer matched, removing an
  inode-collision class of misattribution.
- In **group mode** (`operator_socket_group` set), the gate refuses to
  start when the resolved `agent_uid` is not present in `/etc/passwd`.
  NSS-managed (LDAP/SSSD) users were silently invisible to the
  "agent UID is not in operator group" guardrail; the new error
  surfaces the misconfiguration instead of letting it slip through.
  UID mode is unaffected: its trust boundary is the kernel-enforced
  `0600` socket owned by the gate UID, which does not need to
  enumerate the agent's group memberships, so containerized agents
  whose UID exists only inside the container continue to work.
- Email and PAM-policy strings displayed in the confirmation dialog
  are now run through the same control-character stripper as command
  summaries before reaching zenity / osascript / the terminal prompt
  / the pending queue. Defense-in-depth against ANSI escape and
  newline injection if either upstream validator is ever
  relaxed.
- `getUniverseDomain` now flows through `withAdcMapping` so an
  expired/revoked refresh token surfaces `CredentialsExpiredError`
  with the actionable reauth instruction (and clears the cached
  source client) instead of returning a generic 500 and leaving the
  daemon in a degraded state.

## [0.9.3] - 2026-05-07

### Fixed

- `with-prod` no longer keeps serving a cached access token after the
  underlying PAM grant has ended. The metadata-proxy's caching token
  provider would refresh ~5 minutes before the token's own expiry, which
  could be up to a full token TTL beyond the grant's actual end. The
  gate now clamps each minted prod token's `expires_in` to the PAM
  grant's expiry, so the proxy refreshes in step with PAM. To avoid the
  9.1 lifetime filter dead-end during boundary refreshes, `ensureGrant`
  also pre-emptively revokes a still-active near-expiry grant before
  requesting its replacement instead of relying on `findActiveGrant`'s
  409/400 fallback, which would otherwise reject the open grant for
  being inside the cache margin.

## [0.9.2] - 2026-05-05

### Added

- `/computeMetadata/v1/instance` endpoint for compatibility with
  `gcp-metadata`'s `isAvailable()` detection probe (used by
  `google-auth-library` and `firebase-admin`). Returns a minimal
  directory listing so client libraries recognise the proxy as a
  GCE-style metadata server.

## [0.9.1] - 2026-05-05

### Fixed

- `with-prod` now reliably acquires a fresh PAM grant after the previous
  one has expired. The PAM module's grant-conflict fallback
  (`findActiveGrant`) previously returned any grant whose `state` was
  reported as `ACTIVE`/`ACTIVATED`, even when its
  `createTime + requestedDuration` had already passed. Because PAM's
  state field can briefly lag actual expiry, this could hand the caller
  a dead entitlement that no longer carried elevated permissions.
  `findActiveGrant` now also requires the computed expiry to exceed the
  cache margin, and `ensureGrant` purges expired cache entries on miss
  so dead grants do not linger in the cache (e.g. for `revokeAll` to
  attempt to revoke after shutdown).

### Changed

- Upgraded dependencies to latest versions: `@peculiar/x509` 1.14.3 → 2.0.0,
  `zod` 4.3.6 → 4.4.3, `oxfmt` 0.41.0 → 0.48.0, `oxlint` 1.62.0 → 1.63.0,
  `typescript` 5.9.3 → 6.0.3, and `prek` 0.3.6 → 0.3.13.
- Added `reflect-metadata` as a direct dependency. `@peculiar/x509` v2.0.0 made
  the reflect polyfill required (it is no longer bundled), so `reflect-metadata`
  is now imported at the top of every TLS module that loads `@peculiar/x509`.

## [0.9.0] - 2026-05-04

### Added

- Operator socket setup simplified for single-operator deployments.
  `operator_socket_group` is now optional; when omitted, the operator socket
  is created with mode `0600` owned by the gate UID, removing the need for a
  dedicated Unix group when the operator and gate share a UID (the typical
  local-devcontainer setup). Multi-operator deployments continue to use
  group-based access by setting `operator_socket_group` (mode `0660`). The
  `agent_uid` config remains required when `operator_socket_path` is set; the
  startup guardrail still refuses to start when `agent_uid == gate_uid` (and,
  in group mode, when the agent UID is a member of the operator group).
- New `credentials_expired` error code on JSON error responses from gate
  endpoints that touch ADC (`/token`, `/token?session=...`, `POST
/session`, `/identity`, `/project-number`). Clients can detect the
  condition programmatically; the human-readable `error` field contains
  the full recovery instruction including the exact `gcloud auth
application-default login` command to run on the gate host.

### Changed

- gcloud reauth / `invalid_grant` errors raised by `google-auth-library`
  are now caught in one place and surface to the engineer with a clear,
  action-oriented message instead of a raw `invalid_grant: ...` string.
  Affects gate startup, `with-prod` startup, `with-prod` mid-session
  token refresh, and any other ADC-backed call. The `with-prod` token
  provider also logs the message to its parent stderr so the
  instruction is visible even when the wrapped command (gcloud,
  terraform, …) reports a generic metadata-server error. The message
  names the gate machine by hostname (from `os.hostname()`) and
  explicitly contrasts it with the devcontainer or remote SSH host
  where the command is running, so engineers in remote dev environments
  know exactly which physical machine to run `gcloud auth
application-default login` on.
- After an `invalid_grant` failure, the gate clears its cached source
  and impersonated clients so the next request re-reads
  `application_default_credentials.json`. Engineers no longer need to
  restart the gate after running `gcloud auth application-default login`
  — the next request picks up the refreshed credentials automatically.
  This makes gcp-authcalator integrate cleanly with shorter org-level
  reauth windows.

### Fixed

- `gcloud auth application-default revoke` is now recognised as a
  credentials-expired condition. The gate's cached ADC client can still
  hand out a locally-cached access token after a revoke, so the failure
  surfaces only when Google rejects the token at `tokeninfo` with
  `400 invalid_token`. The gate now forwards the OAuth `error` field
  in the thrown message and matches `invalid_token` as a reauth signal,
  so `with-prod` shows the clear `gcloud auth application-default login`
  instruction instead of a cryptic `tokeninfo returned 400`.
- google-auth-library's `Could not load the default credentials` error
  (raised when `application_default_credentials.json` is missing — the
  state `gcloud auth application-default revoke` and `... logout` leave
  the host in) is now also matched as a reauth signal. After cache
  invalidation triggered by an earlier reauth failure, the next request
  reaches `GoogleAuth.getClient()` and surfaces this message; without
  the matcher it leaked through as a cryptic 500.

## [0.8.2] - 2026-04-28

### Fixed

- Gate listeners now set `idleTimeout: 255s` (Bun's max) on the main, TLS, and
  operator sockets. Bun's 10-second default closed long-running prod requests
  mid-flight — a `POST /session` can legitimately wait up to ~240s (pending
  approval queue + PAM grant polling), causing `with-prod` to fail with
  `socket connection was closed unexpectedly` and leaving stale pending entries
  that produced spurious `429: A prod confirmation dialog is already pending`
  on retry.
- Reuse-existing-PAM-grant path (409 Conflict / 400 FAILED_PRECONDITION) now
  works against the live PAM API. Two latent bugs:
  - The list-grants call passed `?filter=state="ACTIVATED"`, which PAM rejects
    as `400 INVALID_ARGUMENT: invalid list filter` for every filter syntax
    tested (verified empirically). The gate now lists unfiltered with an
    explicit `pageSize=100` and selects the active grant client-side.
  - The state-comparison checks expected `"ACTIVATED"`, but PAM's
    `grants.list` returns `"ACTIVE"`. The gate now treats both spellings as
    activated (in `findActiveGrant`, `pollGrant`, and the create-response
    short-circuit) so it stays robust to PAM API drift.

## [0.8.1] - 2026-04-28

### Added

- Audit log now records the wrapped `command` summary on every prod-path
  request (`/token?level=prod`, `POST /session`, `/token?session=...`). PAM
  grant justifications are immutable and a single grant can be reused across
  many `with-prod` invocations, so the gate's local audit log is the only
  per-invocation record of which command was actually run under elevated
  access. Dev-path entries are unchanged.
- Startup log line that emits the version and short commit SHA to stderr
  for every subcommand (e.g. `gcp-authcalator v0.8.0 (abc1234) (gate)`).
  Skipped for `--version`, `--help`, and the `version` subcommand. Helps
  verify the running build matches what was deployed.

### Fixed

- Reuse existing PAM grant when GCP returns `400 FAILED_PRECONDITION` ("You
  have an open Grant ... that gives the same privileged access"), matching
  prior behavior for `409 Conflict`. Previously `with-prod` failed with
  `failed to acquire prod token` whenever a prior grant was still active.
- Linux: suppress GTK height-mismatch warnings from zenity confirmation
  dialogs by setting an explicit `--width=500`.

### Changed

- PAM grants minted on session token refresh now carry the wrapped command's
  summary as their `unstructuredJustification`, matching the behavior of the
  initial grant. Previously, renewed grants used the generic fallback
  justification.

## [0.8.0] - 2026-04-27

### Added

- **Operator socket** for allowlisted auto-approve. A new third Unix socket
  (`--operator-socket-path`) auto-approves prod requests whose PAM policy is
  in `--auto-approve-pam-policies`, removing the confirmation prompt on the
  human operator's path. Trust attaches to the _socket_ (via filesystem group
  permissions, mode `0660`) rather than to a per-request UID, so the agent
  UID can never reach this code path. Designed for two-UID devcontainer
  setups: the operator runs as one UID with the operator socket bind-mounted
  into their environment, the agent runs as a different UID with only the
  main socket mounted.
- New CLI flags: `--operator-socket-path`, `--operator-socket-group`,
  `--auto-approve-pam-policies`, `--agent-uid`. Same names as snake-case TOML
  keys and `GCP_AUTHCALATOR_*` env vars.
- New audit-log fields: `socket` (`"main" | "operator" | "tcp" | "admin"`)
  on every entry, and `auto_approved: true` on operator-socket grants.

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
