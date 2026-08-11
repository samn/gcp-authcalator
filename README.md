# gcp-authcalator

A GCP auth escalator for containerized development environments.
Keeps GCP credentials out of devcontainers and AI coding agents by proxying token requests through a host-side daemon with confirmation dialogs for production access.

## Why

Modern IDEs encourage running AI coding agents in the same devcontainer the engineer works in. This is convenient — but it means every process inside the container, including unattended agents, has the same GCP credentials as the engineer. A single compromised dependency, a prompt-injection attack, or a malicious tool can silently use those credentials to write to production databases, decrypt secrets, or exfiltrate data.

The core problem is that `google.auth.default()` returns the engineer's full-privilege credentials to **any** process. There is no privilege boundary between the engineer's interactive session and automated tooling.

### Why not just keep credentials on the host behind a simple proxy?

A natural first thought is to run a proxy outside the container that injects auth tokens into requests, so credentials never enter the container directly. This helps, but it is not sufficient:

- **Client libraries cache tokens aggressively.** Google Cloud SDKs and `gcloud` cache access tokens in memory and on disk (`~/.config/gcloud/`, `~/.kube/gke_gcloud_auth_plugin_cache`). Once a token passes through the proxy into the container, the proxy no longer controls who uses it or for how long.
- **Cached tokens cause privilege escalation.** If you temporarily serve a higher-privilege token for a production operation and then switch back, processes inside the container keep using the cached prod token until it expires (~1 hour). A coding agent or compromised dependency can silently reuse it long after the elevated session was supposed to end.
- **No per-request privilege boundary.** A static proxy hands the same token to every caller. There is no mechanism to require human approval for sensitive operations or to give different processes different privilege levels.

### Why not just use GCP PAM (Privileged Access Manager)?

GCP [PAM](https://cloud.google.com/iam/docs/pam-overview) provides just-in-time privilege escalation with time-bound grants and approval workflows. It's a strong control for managing _who_ gets elevated access and _when_ — but it doesn't address _which process_ uses the resulting credentials, which is the critical gap in untrusted environments.

- **PAM grants elevate the entire session.** Once a PAM grant is approved, the engineer's ADC carries the elevated roles. Every process running as that user — including coding agents, build scripts, and compromised dependencies — inherits the escalation for the grant's full duration (typically 1–4 hours). PAM cannot distinguish between the engineer running a migration and an agent exfiltrating data.
- **Credentials are still inside the container.** PAM controls _which roles_ ADC carries but not _where_ ADC lives. If ADC is mounted or forwarded into a devcontainer, any process can read the credentials directly and use them outside PAM's visibility.
- **No per-request confirmation.** PAM is approve-once for the grant duration. There is no mechanism to prompt the engineer each time a process actually uses the elevated credentials. A single approval covers unlimited requests until the grant expires.
- **Revocation is coarse-grained.** Revoking a PAM grant removes the IAM binding, but cached tokens remain valid until they expire. Processes that already obtained a token keep their access.

gcp-authcalator is complementary to PAM — in fact, it [integrates with PAM directly](#gate--host-side-token-daemon) for just-in-time escalation. The difference is what happens _after_ the grant:

|                            | PAM alone                   | gcp-authcalator + PAM                                  |
| -------------------------- | --------------------------- | ------------------------------------------------------ |
| Credentials location       | Inside the container (ADC)  | Host only; container gets short-lived tokens           |
| Who can use elevated creds | Any same-user process       | Only the approved process tree (`with-prod`)           |
| Per-request confirmation   | No — approve once, use many | Yes — host-side dialog per escalation                  |
| Token scope after approval | Full ADC with granted roles | Single downscoped token, isolated metadata proxy       |
| Agent/automation access    | Same as engineer            | Dev service account only; prod requires human approval |

In short: PAM answers "should this person have access right now?" while gcp-authcalator answers "should this specific process have access right now?" Both questions matter in environments with untrusted automation.

---

gcp-authcalator solves this by keeping credentials on the host and making the container ask for them:

1. A **token daemon** (`gate`) runs on the host and holds the engineer's Application Default Credentials. It mints short-lived, downscoped tokens via service account impersonation — never handing out the root credentials.
2. A **metadata server emulator** (`metadata-proxy`) runs inside the container, serving those downscoped tokens transparently to all Google Cloud client libraries. No application code changes needed.
3. **Production-level access requires explicit human confirmation** — a desktop dialog or terminal prompt on the host — so no automated process can silently escalate privileges.

Credentials never enter Docker. The Unix socket (local) or TCP+mTLS connection (remote) is the only channel, and the host daemon controls what tokens are issued.

## Architecture

### Local devcontainer (Unix socket)

```
┌─────────────────────────────────────────────┐
│ Host Machine                                │
│                                             │
│  ~/.config/gcloud/  ──▶  gcp-gate daemon    │
│  (engineer creds)        (Unix socket)      │
│                          ├─ confirmation UI │
│                          └─ audit log       │
└──────────────────┬──────────────────────────┘
                   │ $XDG_RUNTIME_DIR/gcp-authcalator.sock
┌──────────────────┴──────────────────────────┐
│ devcontainer                                │
│                                             │
│  gcp-metadata-proxy (127.0.0.1:8173)        │
│       ▲                                     │
│       │ GCE_METADATA_HOST                   │
│  app / agent / tests                        │
│                                             │
│  with-prod ──▶ temp proxy (random port)     │
│                    ▲                        │
│                    │ GCE_METADATA_HOST      │
│               elevated process              │
└─────────────────────────────────────────────┘
```

### Remote devcontainer (TCP + mTLS)

For remote environments (SSH devcontainers, GitHub Codespaces, Coder), the gate daemon also listens on a TCP port secured with mutual TLS. Credentials still never leave the developer's machine.

```
Developer's Laptop                          Remote Host / Codespace / Coder
┌─────────────────────┐                     ┌──────────────────────────────┐
│  ADC credentials    │                     │  Devcontainer                │
│  gcp-gate daemon    │◄── mTLS over ───────│  gcp-metadata-proxy          │
│    TCP :8174        │    forwarded port   │    (127.0.0.1:8173)          │
│  Confirmation UI    │                     │  with-prod                   │
│  CA + server cert   │                     │  CA cert + client cert/key   │
└─────────────────────┘                     └──────────────────────────────┘
```

## Prerequisites

Before using gcp-authcalator, set up GCP IAM:

1. **Create a service account** with limited permissions for development (e.g., `dev-runner@<project>.iam.gserviceaccount.com`)
2. **Grant developers** the `roles/iam.serviceAccountTokenCreator` role on that service account
3. **Authenticate on the host** with `gcloud auth application-default login` so that Application Default Credentials (ADC) are available

The host-side `gate` daemon uses ADC to impersonate the service account via [`generateAccessToken`](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken), producing short-lived tokens (1-hour TTL).

### gcloud reauthentication

gcp-authcalator integrates with org-level [Google session length
controls](https://support.google.com/a/answer/9368756) and gcloud's
`gcloud auth application-default login` flow. When the engineer's ADC
refresh token expires (the org's session length elapses, the refresh
token is revoked, or RAPT/2SV reauth is required), the gate detects the
`invalid_grant` / reauth response from `google-auth-library` and surfaces
a single clear instruction to the engineer:

> gcloud Application Default Credentials need re-authentication on host
> "\<gate-hostname\>" (where the gcp-authcalator gate daemon is running):
> \<detail\>. Run `gcloud auth application-default login` on that host —
> typically your local laptop, NOT the devcontainer or remote SSH host
> where this command is running. The gate picks up refreshed credentials
> automatically; no restart needed.

The gate's hostname (from `os.hostname()` on the gate process) is named
explicitly so engineers in remote dev environments — devcontainers, SSH
sessions, Codespaces, Coder — know which physical machine to switch to.
The hostname matches the laptop where you originally ran `gcloud auth
application-default login` to set up ADC.

This message appears:

- On `with-prod` startup (the CLI prints it to stderr and exits 1).
- On mid-session token refresh (the with-prod parent process logs it to
  stderr; the wrapped command may also see the gate's response forwarded
  through the metadata proxy).
- In the gate's JSON error responses with `code: "credentials_expired"`,
  for any client that wants to handle the condition programmatically.

After running `gcloud auth application-default login`, the next request
to the gate succeeds — the cached source client is reset on the failed
request so the daemon re-reads
`~/.config/gcloud/application_default_credentials.json` automatically.
This means tightening your org's reauth window does not require any
operational changes to gcp-authcalator: shorter sessions just produce
more frequent reauth prompts, each with the same one-step recovery.

## Installation

### From releases

Download a prebuilt binary from the [GitHub Releases](https://github.com/samn/gcp-authcalator/releases) page:

| Platform     | Binary                         |
| ------------ | ------------------------------ |
| Linux x86_64 | `gcp-authcalator-linux-amd64`  |
| Linux ARM64  | `gcp-authcalator-linux-arm64`  |
| macOS ARM64  | `gcp-authcalator-darwin-arm64` |

Each release includes SHA256 checksums for verification.

### From source

```bash
mise install
bun install
bun run build
```

This produces a single compiled `gcp-authcalator` binary.

## Configuration

Settings can be provided via CLI flags, a TOML config file, environment variables, or a combination.
Precedence: CLI flags > environment variables > TOML file > defaults.

### CLI flags

```
--project-id <id>          GCP project ID (default project for with-prod)
--project <id>             with-prod only: per-invocation target project (overrides --project-id)
--service-account <email>  Service account email to impersonate
--socket-path <path>       Absolute Unix socket path (default: $XDG_RUNTIME_DIR/gcp-authcalator.sock)
--admin-socket-path <path> Absolute admin socket path for approve/deny (default: $XDG_RUNTIME_DIR/gcp-authcalator-admin/admin.sock)
-p, --port <port>          Metadata proxy port (default: 8173)
--gate-tls-port <port>          Gate TCP+mTLS listener port (enables remote devcontainer support)
--tls-dir <path>           TLS certificate directory (default: ~/.gcp-authcalator/tls/)
--gate-url <url>           Gate HTTPS origin for remote connections (no path, query, fragment, or credentials)
--tls-bundle <path>        Path to TLS client bundle file (PEM or base64-encoded)
--scopes <scopes>          Comma-separated OAuth scopes (default: cloud-platform)
--pam-policy <id|path>     PAM entitlement for just-in-time prod escalation
--pam-allowed-policies <ids>  Additional PAM entitlements callers may request (comma-separated)
--pam-location <loc>       PAM entitlement location (default: global)
--token-ttl-seconds <secs> Token lifetime in seconds (60–43200, default: 3600)
--pam-grant-ttl-seconds <secs> PAM grant lifetime in seconds (301–43200 — must exceed the 5-min drain margin; default: token-ttl-seconds). Set longer than the token TTL to amortise PAM/IAM propagation latency across multiple refreshes — one grant serves many tokens before the gate rotates it
--session-ttl-seconds <secs> Prod session lifetime in seconds (300–86400, default: 28800 / 8h)
--quota-project <id>       with-prod: GOOGLE_CLOUD_QUOTA_PROJECT for the wrapped command (default: the target project)
--no-quota-project         with-prod: don't manage GOOGLE_CLOUD_QUOTA_PROJECT (leave the inherited value untouched)
-e, --env <KEY=VALUE>      Extra env var for with-prod subprocess (repeatable, supports ${VAR} substitution)
-c, --config <path>        Path to TOML config file
```

### Environment variables

Most config options can be set via `GCP_AUTHCALATOR_*` environment variables (uppercased key name with `GCP_AUTHCALATOR_` prefix). Options that take arrays or maps (`scopes`, `pam_allowed_policies`, `auto_approve_pam_policies`, `env`) are only available via CLI flags or TOML config.

| Variable                                | Description                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------ |
| `GCP_AUTHCALATOR_PROJECT_ID`            | GCP project ID (same as `--project-id`)                                              |
| `GCP_AUTHCALATOR_SERVICE_ACCOUNT`       | Service account email (same as `--service-account`)                                  |
| `GCP_AUTHCALATOR_SOCKET_PATH`           | Unix socket path (same as `--socket-path`)                                           |
| `GCP_AUTHCALATOR_ADMIN_SOCKET_PATH`     | Admin socket path for approve/deny (same as `--admin-socket-path`)                   |
| `GCP_AUTHCALATOR_PORT`                  | Metadata proxy port (same as `--port`)                                               |
| `GCP_AUTHCALATOR_GATE_TLS_PORT`         | Gate TCP+mTLS listener port (same as `--gate-tls-port`)                              |
| `GCP_AUTHCALATOR_TLS_DIR`               | TLS certificate directory (same as `--tls-dir`)                                      |
| `GCP_AUTHCALATOR_GATE_URL`              | Gate URL for remote connections (same as `--gate-url`)                               |
| `GCP_AUTHCALATOR_TLS_BUNDLE`            | Path to TLS client bundle file (same as `--tls-bundle`)                              |
| `GCP_AUTHCALATOR_TLS_BUNDLE_B64`        | Base64-encoded TLS client bundle (preferred for secrets)                             |
| `GCP_AUTHCALATOR_PAM_POLICY`            | PAM entitlement ID or path (same as `--pam-policy`)                                  |
| `GCP_AUTHCALATOR_PAM_LOCATION`          | PAM entitlement location (same as `--pam-location`)                                  |
| `GCP_AUTHCALATOR_TOKEN_TTL_SECONDS`     | Token lifetime in seconds (same as `--token-ttl-seconds`)                            |
| `GCP_AUTHCALATOR_PAM_GRANT_TTL_SECONDS` | PAM grant lifetime in seconds (same as `--pam-grant-ttl-seconds`)                    |
| `GCP_AUTHCALATOR_SESSION_TTL_SECONDS`   | Prod session lifetime in seconds (same as `--session-ttl-seconds`)                   |
| `GCP_AUTHCALATOR_OPERATOR_SOCKET_PATH`  | Operator socket path (same as `--operator-socket-path`)                              |
| `GCP_AUTHCALATOR_OPERATOR_SOCKET_GROUP` | Operator socket Unix group (same as `--operator-socket-group`)                       |
| `GCP_AUTHCALATOR_AGENT_UID`             | Agent UID or username (same as `--agent-uid`)                                        |
| `GCP_AUTHCALATOR_QUOTA_PROJECT`         | with-prod quota/billing project (same as `--quota-project`)                          |
| `GCP_AUTHCALATOR_NO_QUOTA_PROJECT`      | `true`/`false`: opt out of managing the quota project (same as `--no-quota-project`) |

### TOML config file

```toml
project_id = "my-gcp-project"
service_account = "dev-runner@my-gcp-project.iam.gserviceaccount.com"
# socket_path defaults to $XDG_RUNTIME_DIR/gcp-authcalator.sock
# (or ~/.gcp-authcalator/gcp-authcalator.sock if XDG_RUNTIME_DIR is unset)
# admin_socket_path defaults to $XDG_RUNTIME_DIR/gcp-authcalator-admin/admin.sock
# (used by approve/deny commands — not mounted into containers)
port = 8173

# Remote devcontainer support (optional):
# gate_tls_port = 8174       # Enable TCP+mTLS listener on gate
# gate_url = "https://localhost:8174"  # Point metadata-proxy at remote gate
# scopes = ["https://www.googleapis.com/auth/cloud-platform"]

# Token lifetime (optional, default: 3600):
# token_ttl_seconds = 3600

# PAM grant lifetime in seconds (optional, default: token_ttl_seconds).
# Setting this longer than the token TTL amortises PAM/IAM propagation
# latency across multiple token refreshes — one cached grant serves many
# minted tokens before the gate rotates it. Minted tokens are still clamped
# to the grant's expiry minus the 5-minute drain margin, so this only changes
# how often the gate calls PAM, not how long any individual token is valid.
# Range: 301–43200 (must exceed the 5-minute drain margin). 12 h max.
# pam_grant_ttl_seconds = 14400  # 4 h

# Prod session lifetime — how long with-prod can refresh tokens without
# re-confirmation (optional, default: 28800 / 8 hours):
# session_ttl_seconds = 28800

# PAM integration for just-in-time prod escalation (optional).
# Short-form entitlement IDs expand against project_id + pam_location:
# pam_policy = "prod-db-admin"
# pam_allowed_policies = ["prod-readonly", "prod-migration"]
# pam_location = "global"
#
# Multi-project setups: a folder- or organization-scoped entitlement covers
# every project beneath it, so one PAM policy backs every with-prod --project
# target. Folder/org-scoped paths must be provided in full form (project_id
# is ignored):
# pam_policy = "folders/123456789/locations/global/entitlements/prod-db-admin"
# pam_policy = "organizations/987654321/locations/global/entitlements/prod-db-admin"

# Extra environment variables for with-prod subprocess (optional).
# Values support ${VAR} and ${VAR:-default} substitution resolved within
# the elevated environment (after GCE_METADATA_HOST etc. are set).
# [env]
# CPL_MACHINE_IS_GCE = "YES"
# CPL_GCE_CREDENTIALS_URL = "http://${GCE_METADATA_HOST}/computeMetadata/v1/instance/service-accounts/default/token"
```

Pass the file with `--config`:

```bash
gcp-authcalator gate --config config.toml
```

TOML files are parsed strictly: unknown keys are errors. Socket paths must be
absolute and pairwise distinct, `scopes` must contain at least one entry, and
`gate_url` must be a pure HTTPS origin. One trailing slash on `gate_url` is
accepted and normalized.

## Commands

### `gate` — Host-side token daemon

Runs on the **host machine**. Listens on a Unix domain socket and mints GCP access tokens. Optionally also listens on a TCP port with mutual TLS for remote devcontainer support.

```bash
# Local only (Unix socket):
gcp-authcalator gate \
  --project-id my-project \
  --service-account dev-runner@my-project.iam.gserviceaccount.com

# Local + remote (Unix socket + TCP+mTLS):
gcp-authcalator gate \
  --project-id my-project \
  --service-account dev-runner@my-project.iam.gserviceaccount.com \
  --gate-tls-port 8174
```

**Required options:** `--project-id`, and at least one of `--service-account` or `--pam-policy`:

- `--service-account` alone: dev tokens via impersonation, prod tokens via ADC
- `--pam-policy` alone: prod tokens only (dev tokens disabled), with just-in-time PAM escalation
- Both: dev tokens via impersonation, prod tokens with PAM escalation

**Optional:** `--gate-tls-port` enables a TCP listener with mutual TLS, allowing remote devcontainers to connect. TLS certificates must be generated first with `gcp-authcalator init-tls` and are stored in `~/.gcp-authcalator/tls/`.

**PAM (Privileged Access Manager) integration:** When `--pam-policy` is configured, prod token requests trigger a temporary [PAM grant](https://cloud.google.com/iam/docs/pam-overview) before minting the token. This allows the engineer's ADC to be downscoped by default, with just-in-time escalation for production access. The `--pam-allowed-policies` flag defines additional entitlements that callers may request via `?pam_policy=<id>` query parameter. Grants are withdrawn (`grants:withdraw`, the requester's own operation) on a best-effort basis when they are rotated and when the gate shuts down — the engineer only needs PAM requester access on the entitlement, not the admin-level `grants.revoke` permission.

Cached grants rotate with 5 minutes remaining, at the same boundary used to clamp minted token expiry. This guarantees that rotation does not withdraw IAM access while a token minted under the old grant can still be valid. The adaptive client refresh margin keeps short remaining token lifetimes useful without moving that safety boundary earlier. Grant expiry is calculated from PAM's `auditTrail.accessGrantTime` (or activated timeline event) plus the requested duration, rather than assuming access began at request creation. `createTime`, then a request-start estimate for an incomplete fresh response, are conservative fallbacks. Existing grants with no bounded expiry or marked `externallyModified` are not reused. Concurrent rotations coalesce, and a timed-out rotation is generation-fenced so it cannot later overwrite or withdraw state adopted by its replacement. Create retries reuse PAM's `requestId` idempotency key, preventing an ambiguous timeout from creating duplicate grants. Shutdown rejects new rotations, aborts admitted work, and spends at most 10 seconds dispatching withdrawals for grants it can prove it owns. The configured grant lifetime must therefore be at least 301 seconds; a longer grant amortises PAM/IAM propagation latency across multiple token refreshes without extending any individual token past the 5-minute drain boundary.

**API endpoints** (over Unix socket or TCP+mTLS):

| Endpoint                  | Behavior                                                               |
| ------------------------- | ---------------------------------------------------------------------- |
| `GET /token`              | Returns a dev-scoped access token (impersonated service account)       |
| `GET /token?level=prod`   | Prompts, then returns the engineer's token and email                   |
| `GET /token?session=<id>` | Refreshes a token within a pre-approved prod session                   |
| `POST /session`           | Creates a prod session (with confirmation), returns session ID + token |
| `DELETE /session?id=<id>` | Revokes a prod session                                                 |
| `GET /identity`           | Returns the authenticated user's email                                 |
| `GET /project-number`     | Returns the numeric GCP project ID                                     |
| `GET /universe-domain`    | Returns the GCP universe domain                                        |
| `GET /health`             | Returns `{ "status": "ok", "uptime_seconds": N }`                      |

**Admin socket endpoints** (separate socket, not mounted into containers — see `approve` / `deny` commands):

| Endpoint                    | Behavior                         |
| --------------------------- | -------------------------------- |
| `POST /pending/:id/approve` | Approves a pending request by ID |
| `POST /pending/:id/deny`    | Denies a pending request by ID   |
| `GET /health`               | Health check                     |

Both `/token` and `/token?level=prod` accept an optional `scopes` query parameter (comma-separated) to request tokens with specific OAuth scopes. For example: `/token?scopes=https://www.googleapis.com/auth/sqlservice.login`. When omitted, tokens are minted with the default `cloud-platform` scope.

**Dev tokens** are minted by impersonating the configured service account. The refresh margin adapts to the observed token lifetime: 10% for short-lived tokens, capped at 5 minutes for ordinary hour-long tokens. This avoids treating every token with a lifetime of 5 minutes or less as immediately stale.

**Prod tokens** use the engineer's own ADC credentials. Before issuing a prod token, the daemon:

1. Shows a desktop confirmation dialog (`osascript` on macOS, `zenity` on Linux)
2. Falls back to a terminal prompt if no GUI is available
3. Falls back to a pending approval queue for CLI-based approval (see `pending` / `approve`)
4. Denies access if no interactive method is available and the request times out (120 seconds)

Prod token requests are rate-limited: one confirmation dialog at a time, a 1-second cooldown after denial, and a maximum of 20 attempts per minute. The single-flight slot is released as soon as the operator decides; slow PAM propagation and token minting happen afterward and cannot block the next confirmation dialog. After approval, PAM acquisition and OAuth token minting run concurrently, and the response is returned only when both succeed.

**The dialog shows the reported command in full.** When `with-prod` reports the
command it is wrapping (via `X-Wrapped-Command`), every argument is listed on
its own numbered line in a scrollable view — nothing is hidden behind an
ellipsis, because an argument you cannot read is one you cannot meaningfully
approve. On Linux this is a `zenity --text-info` dialog with an "I have read the
full command" checkbox that must be ticked before **Allow** is enabled; on macOS
it is an AppleScript list where **Allow** stays disabled until you select a
line. Both dialogs receive the command over stdin rather than on the command
line, so it is not visible in the host process table. The terminal prompt
prints every argument and requires you to type `yes` in full (it re-prompts
once if you answer something else). Arguments that look like secrets are still redacted to `***` first, including secrets supplied as a separate flag value and JWT-shaped arguments. Terminal controls and Unicode bidirectional formatting controls are replaced before display so they cannot redraw or visually reorder the command. A
handful of size caps apply (512 arguments, 2000 characters per argument, 32 KiB
total) — when one fires, the dialog says so and how much it withheld.

**Audit logging:** All token requests are logged as JSON lines to the runtime directory's `audit.log` (`$XDG_RUNTIME_DIR/audit.log` or `~/.gcp-authcalator/audit.log`). Prod entries carry both `command` (an 80-character summary) and `command_argv` (the complete redacted argument list), so an approval can be reconstructed after the fact.

### `metadata-proxy` — Container-side metadata emulator

Runs **inside the devcontainer**. Emulates the [GCE metadata server](https://cloud.google.com/compute/docs/metadata/overview) so that all Google Cloud client libraries transparently fetch tokens from the proxy.

```bash
gcp-authcalator metadata-proxy --project-id my-project
```

**Required options:** `--project-id`

Set `GCE_METADATA_HOST=127.0.0.1:8173 GCE_METADATA_IP=127.0.0.1:8173 GCE_METADATA_ROOT=127.0.0.1:8173` in the container environment so client libraries discover the proxy automatically.

**Endpoints:**

| Path                                                               | Response                               | `Metadata-Flavor: Google` required? |
| ------------------------------------------------------------------ | -------------------------------------- | ----------------------------------- |
| `GET /`                                                            | `200 ok` (detection ping)              | No                                  |
| `GET /identity`                                                    | Authenticated user email JSON          | Yes                                 |
| `GET /computeMetadata/v1/instance`                                 | Directory listing for GCE detection    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default/token`  | Token JSON                             | Yes                                 |
| `GET /computeMetadata/v1/project/project-id`                       | Plain text project ID                  | Yes                                 |
| `GET /computeMetadata/v1/project/numeric-project-id`               | Plain text numeric project ID          | Yes                                 |
| `GET /computeMetadata/v1/universe/universe_domain`                 | Plain text universe domain             | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default/email`  | Plain text SA email                    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default/scopes` | Newline-delimited OAuth scopes         | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default`        | SA info (JSON or directory listing)    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts`                | SA listing (JSON or directory listing) | Yes                                 |

Endpoints returning "JSON or directory listing" respond with JSON when `?recursive=true` is passed, and a text directory listing otherwise. This matches real GCE metadata server behavior.

Service account paths that use an email identifier (e.g., `.../service-accounts/sa@project.iam.gserviceaccount.com/token`) are automatically aliased to `default`, since the proxy serves a single set of credentials. Only the exact `default` segment and email-shaped identifiers are accepted as aliases; lookalikes such as `default-prod` remain unknown paths. This ensures compatibility with `gcloud` and other client libraries that resolve accounts by email without accidentally routing arbitrary identifiers to the credential endpoint.

`GET /identity` proxies the gate's [`/identity`](#gate--host-side-token-daemon) route, returning the authenticated engineer's email as JSON (`{ "email": "..." }`). This lets container-side tooling — for example telemetry that must attribute activity to a real person — discover the human behind the downscoped service account. It is intentionally **not** the GCE `.../service-accounts/default/identity` path (which is reserved for OIDC identity tokens and is not supported); it lives at the top level, mirroring the gate. Because it returns the engineer's real email (PII), it requires the `Metadata-Flavor: Google` header like the other data-returning endpoints — the header blocks header-less "simple" requests (a browser or an SSRF-prone local service) from reading it. When the proxy is backed by a custom token provider rather than a gate client, the endpoint returns `404`.

The proxy fetches tokens from the `gate` daemon via a Unix socket (local) or TCP+mTLS (remote) and caches them locally. Its refresh margin is 10% of the observed token lifetime, capped at 5 minutes, so both short-lived and ordinary hour-long tokens retain a useful cache window. The transport is determined automatically based on whether `--gate-url` or `GCP_AUTHCALATOR_GATE_URL` is configured.

### `with-prod` — Elevation wrapper

Wraps a shell command with production-level GCP credentials. Runs **inside the devcontainer**.

```bash
gcp-authcalator with-prod -- python some/script.py
gcp-authcalator with-prod -- gcloud sql instances list
gcp-authcalator with-prod -- alembic upgrade head
gcp-authcalator with-prod --scopes="https://www.googleapis.com/auth/sqlservice.login" -- cloud-sql-proxy my-project:us-central1:my-instance

# Target a specific project (overrides the configured default for this invocation):
gcp-authcalator with-prod --project alt-project -- gcloud sql instances list

# Pin the quota/billing project, or opt out of setting it:
gcp-authcalator with-prod --quota-project my-billing-project -- gcloud ...
gcp-authcalator with-prod --no-quota-project -- gcloud ...

# Pass extra env vars (e.g. for GDAL/OGR):
gcp-authcalator with-prod \
  --env CPL_MACHINE_IS_GCE=YES \
  --env 'CPL_GCE_CREDENTIALS_URL=http://${GCE_METADATA_HOST}/computeMetadata/v1/instance/service-accounts/default/token' \
  -- ogr2ogr ...
```

**Required options:** `--project-id` (or `--project` for the target this invocation acts against)

**Multi-project setups.** `--project` lets one gate serve many GCP projects without re-running for each. Common pattern: organise projects under a GCP folder (or attach an org-wide entitlement); configure `pam_policy` as a folder- or organization-scoped entitlement (`folders/{id}/locations/{loc}/entitlements/{name}` or `organizations/{id}/locations/{loc}/entitlements/{name}`) so a single PAM grant covers every project beneath; grant the impersonation service account the IAM it needs across that scope. The gate does not enforce a project allowlist — the security boundary is folder/org/PAM scope + IAM bindings on the service account. The effective project flows through to the metadata proxy (`/computeMetadata/v1/project/project-id`), the wrapped child's `CLOUDSDK_CORE_PROJECT`, and the gate's audit log via the `X-Target-Project` header / `target_project` audit field.

**Quota project.** `with-prod` sets `GOOGLE_CLOUD_QUOTA_PROJECT` on the wrapped command so end-user-credential (prod) API calls have a quota/billing project — without one, Google APIs emit "authenticated using end user credentials" warnings or fail with quota errors. By default it follows the selected target project (`--project` / `project_id`), so the project you act against bills its own quota; this requires the active credential to hold `serviceusage.services.use` on that project. Pin a separate billing project with `--quota-project <id>` (or `quota_project` in config), or opt out with `--no-quota-project` (`no_quota_project = true`) — opt-out leaves any inherited `GOOGLE_CLOUD_QUOTA_PROJECT` untouched and takes precedence over `quota_project`. An explicit `--env GOOGLE_CLOUD_QUOTA_PROJECT=...` overrides all of the above.

This command:

1. Gives the gate transport a 3-second health preflight, then creates a **prod session** at `gate` (triggers a host-side confirmation dialog). The session allows transparent token refresh without re-confirmation for a bounded lifetime (default 8 hours, configurable via `--session-ttl-seconds`).
2. Starts a temporary metadata proxy on a random port that **auto-refreshes tokens** from the gate near expiry (at 10% of the observed lifetime, capped at 5 minutes). This means long-running processes never lose access — individual tokens remain short-lived while the session stays active.
3. Creates an isolated `CLOUDSDK_CONFIG` directory so `gcloud` doesn't reuse cached credentials. The access token file is atomically updated through an exclusive, randomly named staging file on each refresh; a refresh-side write failure is not committed to the in-memory cache.
4. Strips credential-related environment variables (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_AUTH_ACCESS_TOKEN`, etc.) to force the child through the proxy
5. Spawns the wrapped command with `GCE_METADATA_HOST`, `GCE_METADATA_IP`, and `GCE_METADATA_ROOT` pointing at the temporary proxy
6. Applies any extra environment variables from `[env]` config or `--env` CLI flags, with `${VAR}` / `${VAR:-default}` substitution resolved against the elevated environment
7. Cancels acquisition immediately if `SIGINT` or `SIGTERM` arrives before the child starts. Once running, it forwards the first signal to the child, gives it 5 seconds to exit cleanly, then sends `SIGKILL`; a second signal skips the remaining grace period. The wrapper propagates the child's exit code.
8. Revokes the session on exit (best-effort cleanup)

The temporary proxy uses PID-based process restriction — only the wrapped command and its descendants can request tokens from it. The session ID (which authorizes token refresh) stays in the `with-prod` process and never reaches the subprocess — an attacker inside the subprocess cannot refresh tokens independently.

Before opening an approval request, `with-prod` gives the gate transport a
3-second health preflight, so a missing daemon, stale socket, broken tunnel, or
bad remote address fails promptly instead of consuming the full acquisition
deadline. Every longer gate request is separately bounded and includes the
complete response body, not only receipt of HTTP headers. Nested `with-prod`
detection checks the parent proxy's stable email and project metadata; it does
not probe the token endpoint, because doing so could start an unnecessary PAM
rotation merely to decide whether the parent is healthy. Once a session has
been acquired, setup and teardown form one cleanup transaction: an error still
restores the umask, stops any temporary proxy, removes token-bearing files, and
awaits best-effort session revocation.

### `pending` / `approve` / `deny` — CLI approval of pending requests

Inspects, approves, or denies pending prod access requests on the gate server. This is the CLI fallback for environments where GUI dialogs and terminal prompts are unavailable (headless servers, containers without a display, CI).

```bash
# List queued requests, each with its command in full:
gcp-authcalator pending

# Show one request (ID printed by with-prod when waiting for approval):
gcp-authcalator pending <id>

# Approve a request by ID — prints the full command, then asks for confirmation:
gcp-authcalator approve <id>

# Approve without the interactive prompt (required when not on a TTY):
gcp-authcalator approve <id> --yes

# Deny a request by ID:
gcp-authcalator deny <id>
```

`approve` always prints the request's complete argument list before it resolves anything, then asks you to type `yes`. On a non-TTY it refuses outright unless `--yes` is passed, so nothing is ever approved without the command having been shown. `deny` skips the confirmation — the failure mode worth guarding against is a blind yes.

When the gate's confirmation module cannot show a GUI dialog or terminal prompt, it queues the request and prints the request ID to stderr with instructions. If no approval has arrived within 10 seconds, the `with-prod` command also prints the pending ID with the `gcp-authcalator pending <id>` hint, so you can review and approve it manually. Requests auto-deny after 120 seconds if not resolved.

All three commands connect to the gate's **admin socket** (separate from the main socket, not mounted into devcontainers) — which is also why the process that requested prod access cannot read back the command the operator is being shown. They do not require `--project-id` — only `--admin-socket-path` is needed (defaults to `$XDG_RUNTIME_DIR/gcp-authcalator-admin/admin.sock`).

### `init-tls` — TLS certificate management

Generates TLS certificates for remote devcontainer support. Run this on the **developer's laptop**.

```bash
# Generate all TLS certificates:
gcp-authcalator init-tls

# Print the base64-encoded client bundle (for setting as a secret):
gcp-authcalator init-tls --bundle-b64

# Print just the TLS directory path:
gcp-authcalator init-tls --show-path
```

The client bundle (CA cert + client cert + client key) is a single base64-encoded string that you distribute to remote environments via secrets or environment variables. It is **not** a GCP credential — it only authorizes communication with the gate daemon.

Certificates are generated with ECDSA P-256 with a 90-day lifetime for all certificates (CA, server, and client). All certs are treated as ephemeral and regenerated together. `init-tls` honors `tls_dir` from CLI, environment, or TOML configuration. Gate refuses to start if the TLS directory or key material is symlinked, has unsafe ownership or permissions, is not yet valid or is expired, has the wrong CA/key-usage/extended-key-usage constraints, has an unexpected subject or server SAN, or contains a key that does not match its certificate. A missing derived `client-bundle.pem` is rebuilt from a valid existing chain without rotating that chain; authoritative material is regenerated together when invalid.

### `kube-setup` — Patch kubeconfig for GKE

One-time setup command that patches your kubeconfig to use gcp-authcalator instead of `gke-gcloud-auth-plugin` for GKE cluster authentication.

```bash
gcp-authcalator kube-setup
```

This command:

1. Reads the kubeconfig (from `$KUBECONFIG` or `~/.kube/config`)
2. Finds all users with `exec.command: gke-gcloud-auth-plugin` (including full paths)
3. Replaces the exec section to point to `gcp-authcalator kube-token`
4. Creates or replaces a mode-preserving backup at `<kubeconfig>.bak`
5. Atomically writes the patched kubeconfig, preserving its mode and following a kubeconfig symlink to update its target

After patching, kubeconfig user entries will look like:

```yaml
users:
  - name: gke_project_region_cluster
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: /absolute/path/to/gcp-authcalator
        args: ["kube-token"]
        installHint: "Install gcp-authcalator or revert with: gcloud container clusters get-credentials <cluster>"
        provideClusterInfo: true
```

To revert, re-run `gcloud container clusters get-credentials <cluster>`.

### `kube-token` — kubectl credential plugin

kubectl [exec credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins) that fetches a token from the active metadata proxy and outputs an `ExecCredential` JSON for kubectl. You don't call this directly — kubectl invokes it automatically after running `kube-setup`.

```bash
gcp-authcalator kube-token
```

The plugin reads `GCE_METADATA_HOST` from the environment (falls back to `127.0.0.1:8173`) and requests a token from that metadata proxy. It mirrors the supported `client.authentication.k8s.io/v1` or `v1beta1` requested in `KUBERNETES_EXEC_INFO`, so its response matches the exec-plugin contract used by the invoking kubectl. This means it automatically picks up the correct token:

- **Normal usage:** fetches a dev token from the default metadata proxy
- **Under `with-prod`:** `GCE_METADATA_HOST` points to the temporary prod proxy, so kubectl transparently gets the prod token

The `expirationTimestamp` is set to ~1 second from now, which effectively disables kubectl's exec credential cache. This ensures concurrent kubectl processes (some normal, some under `with-prod`) always get the correct token. The metadata proxy already caches tokens, so the overhead is one fast localhost HTTP round-trip per kubectl API call.

**Why not `gke-gcloud-auth-plugin`?** The GKE plugin caches tokens at `~/.kube/gke_gcloud_auth_plugin_cache` and ignores `CLOUDSDK_CONFIG`, so it keeps serving stale dev tokens even under `with-prod`.

### `version` — Show version

Prints the current version and exits.

```bash
gcp-authcalator version
gcp-authcalator --version
```

## Devcontainer setup

To use gcp-authcalator in a devcontainer:

1. **Host:** Start the `gate` daemon (e.g., in a devcontainer lifecycle script that runs on the host):

   ```bash
   gcp-authcalator gate --config /path/to/config.toml
   ```

2. **Mount the socket** into the container by adding to `devcontainer.json`.
   The socket lives in a user-private directory — use `$XDG_RUNTIME_DIR` (typically `/run/user/$UID`) or `~/.gcp-authcalator/` if that's unset:

   ```json
   "mounts": [
     "source=${localEnv:XDG_RUNTIME_DIR}/gcp-authcalator.sock,target=${localEnv:XDG_RUNTIME_DIR}/gcp-authcalator.sock,type=bind"
   ]
   ```

   Make sure the container uses the same `--socket-path` as the host.

3. **Container:** Start the metadata proxy (e.g., in a post-start script):

   ```bash
   gcp-authcalator metadata-proxy --project-id my-project &
   ```

4. **Container:** Set the environment variables so client libraries discover the proxy:

   ```json
   "remoteEnv": {
     "GCE_METADATA_HOST": "127.0.0.1:8173",
     "GCE_METADATA_IP": "127.0.0.1:8173",
     "GCE_METADATA_ROOT": "127.0.0.1:8173"
   }
   ```

5. **Container (optional):** If you use `kubectl` with GKE, patch the kubeconfig so kubectl fetches tokens through gcp-authcalator instead of `gke-gcloud-auth-plugin`:

   ```bash
   gcloud container clusters get-credentials <cluster> --region <region> --project <project>
   gcp-authcalator kube-setup
   ```

   This ensures `kubectl` works correctly under both normal and `with-prod` usage.

## Remote devcontainer setup

For remote environments where the devcontainer runs on a different machine (SSH remote, GitHub Codespaces, Coder), use TCP+mTLS instead of a Unix socket.

### SSH remote devcontainer

```bash
# 1. On laptop — generate TLS certificates (one-time):
gcp-authcalator init-tls

# 2. On laptop — start gate with TCP:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --gate-tls-port 8174

# 3. On laptop — get the client bundle:
gcp-authcalator init-tls --bundle-b64
# Copy the output

# 4. SSH with port forwarding:
ssh -R 8174:localhost:8174 remote-host

# 5. On remote host — set env vars (e.g., in .bashrc or devcontainer.json):
export GCP_AUTHCALATOR_TLS_BUNDLE_B64="<paste>"
export GCP_AUTHCALATOR_GATE_URL="https://localhost:8174"

# 6. In devcontainer — metadata-proxy auto-detects env vars:
gcp-authcalator metadata-proxy --project-id my-project
```

### GitHub Codespaces

```bash
# 1. On laptop — generate TLS certificates (one-time):
gcp-authcalator init-tls

# 2. On laptop — start gate with TCP:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --gate-tls-port 8174

# 3. Set Codespace secrets (one-time):
gcp-authcalator init-tls --bundle-b64 | gh secret set GCP_AUTHCALATOR_TLS_BUNDLE_B64
gh secret set GCP_AUTHCALATOR_GATE_URL --body "https://localhost:8174"

# 4. Forward port to Codespace:
gh cs ports forward 8174:8174

# 5. In Codespace — metadata-proxy auto-detects env vars:
gcp-authcalator metadata-proxy --project-id my-project
```

### Coder

```bash
# 1. On laptop — generate TLS certificates (one-time):
gcp-authcalator init-tls

# 2. On laptop — start gate with TCP:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --gate-tls-port 8174

# 3. Set workspace env vars (via Coder UI or template):
#    GCP_AUTHCALATOR_TLS_BUNDLE_B64=<from init-tls --bundle-b64>
#    GCP_AUTHCALATOR_GATE_URL=https://localhost:8174

# 4. Forward port to workspace:
coder port-forward my-workspace --tcp 8174:8174

# 5. In workspace — metadata-proxy auto-detects env vars:
gcp-authcalator metadata-proxy --project-id my-project
```

### Port forwarding resilience

When port forwarding drops (SSH disconnect, Codespace timeout):

- **Dev tokens**: metadata-proxy continues serving cached tokens for up to 55 minutes. New token requests fail with a clear connection error.
- **Prod tokens**: `with-prod` continues serving the cached token until it expires. Token refresh attempts fail with a descriptive error; access resumes automatically when the connection is restored (if the session hasn't expired).
- **Reconnection**: Automatic when port forwarding resumes — no restart of metadata-proxy required.

## Security model

### Threat model

gcp-authcalator is designed for environments where a coding agent (or other untrusted automation) runs in the same devcontainer as the engineer. The goal is to ensure that **all privilege escalation requires human approval** and that **credentials are never directly accessible inside the container**.

**Hard security boundaries:**

- **Credentials never enter the container.** The host daemon holds ADC; the container only receives short-lived, downscoped tokens. Even if the container is fully compromised, the attacker gets only a dev service account token — not the engineer's identity.
- **Cross-user isolation.** The main Unix socket is set to `0660` (group-readable by the gate UID's primary group) in a `0750` directory; the privileged operator socket is `0600` (owner-only) in the same directory. On modern Linux distros (UPG), the gate UID's primary group contains only the gate UID itself, so this is _effectively_ `0600` end-to-end. To grant a different-UID agent access to the main socket (e.g. a `the-robot` user in a dev container), add that user to the gate UID's primary group; the kernel still blocks access to the operator socket because its file mode is `0600`. The `$XDG_RUNTIME_DIR` directory itself is left at the system-managed `0700` per the XDG spec — group access requires placing `socket_path` in a gate-managed directory like `~/.gcp-authcalator/`. All configured socket paths must be absolute and pairwise distinct; startup also resolves their existing parent directories and rejects paths that alias through symlinks. `with-prod`'s per-invocation sandbox dir (where ephemeral gcloud config and token files live, `0600` owned by the calling UID) is resolved separately from the gate's runtime dir (`$XDG_RUNTIME_DIR` → `$XDG_CACHE_HOME/gcp-authcalator` → `~/.cache/gcp-authcalator`), so the agent's sandbox stays in its own private, owned space even when the gate's `~/.gcp-authcalator/` is shared via symlink. **For strongest isolation, run coding agents as a separate OS user _not_ in the gate's primary group** — they will be unable to access the main socket at all.
- **Mutual TLS for remote transport.** When using TCP for remote devcontainers, both gate and the client verify each other's identity via self-signed certificates. The gate only listens on localhost (port forwarding is required for remote access). `gate_url` must be a pure HTTPS origin, with no credentials, query, fragment, or non-root path. A single trailing slash is accepted and normalized before endpoint paths are appended; plaintext `http://` and ambiguous URLs are rejected at config parse time.
- **Human-in-the-loop for production access.** Prod tokens require explicit confirmation via a desktop dialog (`osascript` on macOS, `zenity` on Linux), terminal prompt, or CLI approval (`gcp-authcalator approve`) on the host. If no method resolves within 120 seconds, access is denied.
- **Informed consent.** Every approval surface shows the reported command in full, one argument per line. Nothing is elided silently: the size caps that bound dialog growth each state what they withheld. The reported command is still caller-supplied and advisory — a compromised container can lie about what it intends to run — so this protects the honest-client case, where the risk is an operator approving a payload they were structurally unable to see.
- **Rate limiting** prevents automated brute-forcing of the confirmation flow: one dialog at a time, a 1-second cooldown after denial, and a maximum of 20 attempts per minute.

**Best-effort protections** (defense in depth against same-user attacks):

- **PID-based process restriction** on `with-prod` temporary proxies ensures only the intended process tree can request elevated tokens. This uses `/proc` introspection and is effective against casual abuse, but a sufficiently privileged same-user process could circumvent it.
- **Environment isolation** in `with-prod` strips credential-related env vars (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_AUTH_ACCESS_TOKEN`, etc.) and uses a temporary `CLOUDSDK_CONFIG` in the user-private runtime directory to prevent credential leakage around the proxy.
- **Token files** are written with `0600` permissions in user-private directories, not passed via environment variables (which are readable via `/proc/*/environ`). Atomic refreshes use unpredictable, exclusively created staging names so a planted fixed-name symlink cannot redirect the write.
- **Audit logging** records all token requests as JSON lines to the runtime directory, providing a trail for forensic review.
- **Stale socket recovery** verifies socket ownership and refuses to follow symlinks, preventing TOCTOU races. Listener startup is transactional: if a later TLS, admin-socket, or operator-socket step fails, listeners and socket files created by that attempt are rolled back before startup returns the error.

**Limitations:**

- A malicious process running as the **same user** with sufficient sophistication (e.g., `ptrace`, reading `/proc/*/mem`) can potentially extract tokens from a running process. Full same-user isolation requires OS-level sandboxing beyond what gcp-authcalator provides.
- Once the engineer approves a prod session, elevated tokens are available to the approved process tree for the session lifetime (default 8 hours). Individual tokens are short-lived (default 1 hour) and auto-refresh, but access persists until the session expires or `with-prod` exits. A compromised process within the subprocess tree can continue receiving fresh tokens via the metadata proxy for the session's duration.
- **Stolen client bundle** (remote mode): An attacker with the client cert can authenticate to gate over a forwarded port. Mitigation: client bundle has 90-day expiry; bundle files are `0600`; gate only listens on localhost; prod tokens still require confirmation dialog.
- **Bundle in env var**: `GCP_AUTHCALATOR_TLS_BUNDLE_B64` is cleared from `process.env` immediately after reading to prevent inheritance by child processes. The bundle only authorizes gate communication, not GCP access directly.

### Operator socket — auto-approve for human-initiated escalation

The operator socket is an **opt-in** third Unix socket that auto-approves prod requests whose resolved PAM policy is in an explicit allowlist. It is designed for setups where the operator and the coding agent run as **different Unix UIDs in the same devcontainer**:

- Only the operator can connect to the operator socket; the agent runs as a different UID and is excluded by filesystem permissions.
- The agent continues to use the existing main socket and goes through the standard confirmation flow.

**Why it exists.** Confirmation dialogs every few minutes train operators to dismiss prompts without reading them — a worse failure mode than no prompt at all. Auto-approving an _allowlisted_ set of policies for the human path lets the prompt remain meaningful for everything else.

#### Single-operator (paved path)

The simple setup: the operator and the gate share a UID (typical when the gate runs on the host as your user, and the operator's devcontainer UID matches the host UID for bind-mount compatibility). The operator socket is created mode `0600` owned by that UID — the kernel excludes the agent UID directly, no group setup required.

**Enable it (gate config):**

```toml
operator_socket_path = "/run/user/1000/gcp-authcalator-operator.sock"
agent_uid            = "claude"                 # numeric UID or username
auto_approve_pam_policies = ["prod-readonly"]   # subset of pam_allowed_policies
```

Or via CLI flags / `GCP_AUTHCALATOR_*` env vars of the same names.

**Operator points their client at the operator socket:**

```bash
export GCP_AUTHCALATOR_SOCKET_PATH=/run/user/1000/gcp-authcalator-operator.sock
with-prod gcloud projects list   # no prompt; audit log shows auto_approved=true
```

`with-prod` automatically falls back to per-request token mode on the operator socket — sessions are explicitly disabled there (see below).

**Setup requirements (you are responsible for these):**

1. Run the gate as the same UID as the operator (the typical case for a host-side gate). Run the agent (e.g. Claude Code) as a different UID — for example, a separate user account inside the devcontainer.
2. Set `agent_uid`. The gate's startup misconfiguration check requires it and will refuse to start if the agent UID equals the gate UID.
3. **Keep `auto_approve_pam_policies` minimal.** Treat additions with the same review rigor as IAM policy changes — anything in this list is granted by _any_ code that runs as the operator UID, including malicious code planted via the operator's tooling (npm postinstall, agent-suggested shell command, tampered Makefile, etc.). The allowlist caps blast radius; it does not eliminate confused-deputy attacks.
4. Pipe `~/.gcp-authcalator/audit.log` to your SIEM. Auto-approvals are tagged `auto_approved: true, socket: "operator"`. The gate makes no attempt at log-tamper protection; observability is your job.
5. Do not run the devcontainer with userns-remapping that rewrites file ownership (it can silently break the trust boundary).
6. Operator socket is **Unix-only**. Remote (TCP+mTLS) operators do not get auto-approve.

#### Multi-operator (advanced)

If multiple humans share one gate (e.g. a shared workstation), set `operator_socket_group` to a dedicated Unix group whose members are the operators. The socket is then created mode `0660` group-owned, and any group member can connect.

```toml
operator_socket_path  = "/run/user/1000/gcp-authcalator-operator.sock"
operator_socket_group = "gcp-operators"          # dedicated group; do NOT reuse wheel/staff
agent_uid             = "claude"
auto_approve_pam_policies = ["prod-readonly"]
```

Additional setup requirements for group mode:

1. Create a dedicated Unix group (e.g. `gcp-operators`). Do **not** reuse `wheel`, `staff`, or anyone's primary group.
2. Add **only** the operator UIDs to this group. Never the agent UID. Never `root`.
3. The gate refuses to start if the agent UID is a member of `operator_socket_group` or if the configured group is missing from `/etc/group`.

All other setup requirements from the single-operator section still apply.

**What auto-approve does NOT do:**

- It does **not** issue sessions. `POST /session` and `GET /token?session=…` return 403 on the operator socket. There is no 8-hour bearer-token refresh credential to steal.
- It does **not** affect the main socket. Agent flows are unchanged: dev tokens are served immediately as before; prod requests still trigger the standard confirmation dialog.
- It does **not** loosen the existing PAM allowlist. `auto_approve_pam_policies` is required to be a subset of `pam_allowed_policies`. Out-of-allowlist requests on the operator socket return a clean 403 — they do not fall through to a prompt.
- It does **not** carve out a separate rate-limit budget. The operator socket shares the existing 20/minute prod limiter with the main socket, so a flooding agent surfaces as a real rate-limit signal.

**Audit a window of auto-approvals:**

```bash
jq 'select(.auto_approved == true and .socket == "operator")' ~/.gcp-authcalator/audit.log
```

## Development

### Setup

```bash
mise install
bun install
prek install
```

### Pre-commit checks

```bash
bun run format    # auto-fix formatting
bun run lint      # run oxlint
bun run typecheck # check types
bun test          # run tests
```

### Building

```bash
bun run build                # build for current platform
bun run build:linux-amd64    # cross-compile for Linux x86_64
bun run build:linux-arm64    # cross-compile for Linux ARM64
bun run build:darwin-arm64   # cross-compile for macOS ARM64
```

See [docs/releasing.md](docs/releasing.md) for the release process.
