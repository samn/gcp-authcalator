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
Precedence: environment variables > CLI flags > TOML file > defaults.

### CLI flags

```
--project-id <id>          GCP project ID
--service-account <email>  Service account email to impersonate
--socket-path <path>       Unix socket path (default: $XDG_RUNTIME_DIR/gcp-authcalator.sock)
-p, --port <port>          Metadata proxy port (default: 8173)
--gate-tls-port <port>          Gate TCP+mTLS listener port (enables remote devcontainer support)
--tls-dir <path>           TLS certificate directory (default: ~/.gcp-authcalator/tls/)
--gate-url <url>           Gate URL for remote connections (must use https://)
--tls-bundle <path>        Path to TLS client bundle file (PEM or base64-encoded)
--scopes <scopes>          Comma-separated OAuth scopes (default: cloud-platform)
--pam-policy <id|path>     PAM entitlement for just-in-time prod escalation
--pam-allowed-policies <ids>  Additional PAM entitlements callers may request (comma-separated)
--pam-location <loc>       PAM entitlement location (default: global)
--token-ttl-seconds <secs> Token lifetime in seconds (60–43200, default: 3600)
-c, --config <path>        Path to TOML config file
```

### Environment variables

All config options can be set via `GCP_AUTHCALATOR_*` environment variables (uppercased key name with `GCP_AUTHCALATOR_` prefix):

| Variable                            | Description                                               |
| ----------------------------------- | --------------------------------------------------------- |
| `GCP_AUTHCALATOR_PROJECT_ID`        | GCP project ID (same as `--project-id`)                   |
| `GCP_AUTHCALATOR_SERVICE_ACCOUNT`   | Service account email (same as `--service-account`)       |
| `GCP_AUTHCALATOR_SOCKET_PATH`       | Unix socket path (same as `--socket-path`)                |
| `GCP_AUTHCALATOR_PORT`              | Metadata proxy port (same as `--port`)                    |
| `GCP_AUTHCALATOR_GATE_TLS_PORT`     | Gate TCP+mTLS listener port (same as `--gate-tls-port`)   |
| `GCP_AUTHCALATOR_TLS_DIR`           | TLS certificate directory (same as `--tls-dir`)           |
| `GCP_AUTHCALATOR_GATE_URL`          | Gate URL for remote connections (same as `--gate-url`)    |
| `GCP_AUTHCALATOR_TLS_BUNDLE`        | Path to TLS client bundle file (same as `--tls-bundle`)   |
| `GCP_AUTHCALATOR_TLS_BUNDLE_B64`    | Base64-encoded TLS client bundle (preferred for secrets)  |
| `GCP_AUTHCALATOR_PAM_POLICY`        | PAM entitlement ID or path (same as `--pam-policy`)       |
| `GCP_AUTHCALATOR_PAM_LOCATION`      | PAM entitlement location (same as `--pam-location`)       |
| `GCP_AUTHCALATOR_TOKEN_TTL_SECONDS` | Token lifetime in seconds (same as `--token-ttl-seconds`) |

### TOML config file

```toml
project_id = "my-gcp-project"
service_account = "dev-runner@my-gcp-project.iam.gserviceaccount.com"
# socket_path defaults to $XDG_RUNTIME_DIR/gcp-authcalator.sock
# (or ~/.gcp-authcalator/gcp-authcalator.sock if XDG_RUNTIME_DIR is unset)
port = 8173

# Remote devcontainer support (optional):
# gate_tls_port = 8174       # Enable TCP+mTLS listener on gate
# gate_url = "https://localhost:8174"  # Point metadata-proxy at remote gate
# scopes = ["https://www.googleapis.com/auth/cloud-platform"]

# Token lifetime (optional, default: 3600):
# token_ttl_seconds = 3600

# PAM integration for just-in-time prod escalation (optional):
# pam_policy = "prod-db-admin"
# pam_allowed_policies = ["prod-readonly", "prod-migration"]
# pam_location = "global"
```

Pass the file with `--config`:

```bash
gcp-authcalator gate --config config.toml
```

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

**PAM (Privileged Access Manager) integration:** When `--pam-policy` is configured, prod token requests trigger a temporary [PAM grant](https://cloud.google.com/iam/docs/pam-overview) before minting the token. This allows the engineer's ADC to be downscoped by default, with just-in-time escalation for production access. The `--pam-allowed-policies` flag defines additional entitlements that callers may request via `?pam_policy=<id>` query parameter. Grants are revoked on a best-effort basis when the gate shuts down.

**API endpoints** (over Unix socket or TCP+mTLS):

| Endpoint                | Behavior                                                         |
| ----------------------- | ---------------------------------------------------------------- |
| `GET /token`            | Returns a dev-scoped access token (impersonated service account) |
| `GET /token?level=prod` | Prompts for confirmation, then returns the engineer's own token  |
| `GET /identity`         | Returns the authenticated user's email                           |
| `GET /project-number`   | Returns the numeric GCP project ID                               |
| `GET /universe-domain`  | Returns the GCP universe domain                                  |
| `GET /health`           | Returns `{ "status": "ok", "uptime_seconds": N }`                |

Both `/token` and `/token?level=prod` accept an optional `scopes` query parameter (comma-separated) to request tokens with specific OAuth scopes. For example: `/token?scopes=https://www.googleapis.com/auth/sqlservice.login`. When omitted, tokens are minted with the default `cloud-platform` scope.

**Dev tokens** are minted by impersonating the configured service account. They are cached and re-minted when less than 5 minutes of lifetime remain.

**Prod tokens** use the engineer's own ADC credentials. Before issuing a prod token, the daemon:

1. Shows a desktop confirmation dialog (`osascript` on macOS, `zenity` on Linux)
2. Falls back to a terminal prompt if no GUI is available
3. Denies access if no interactive method is available

Prod token requests are rate-limited: one confirmation dialog at a time, a 5-second cooldown after denial, and a maximum of 5 attempts per minute.

**Audit logging:** All token requests are logged as JSON lines to the runtime directory's `audit.log` (`$XDG_RUNTIME_DIR/audit.log` or `~/.gcp-authcalator/audit.log`).

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
| `GET /computeMetadata/v1/instance/service-accounts/default/token`  | Token JSON                             | Yes                                 |
| `GET /computeMetadata/v1/project/project-id`                       | Plain text project ID                  | Yes                                 |
| `GET /computeMetadata/v1/project/numeric-project-id`               | Plain text numeric project ID          | Yes                                 |
| `GET /computeMetadata/v1/universe/universe_domain`                 | Plain text universe domain             | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default/email`  | Plain text SA email                    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default/scopes` | Newline-delimited OAuth scopes         | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default`        | SA info (JSON or directory listing)    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts`                | SA listing (JSON or directory listing) | Yes                                 |

Endpoints returning "JSON or directory listing" respond with JSON when `?recursive=true` is passed, and a text directory listing otherwise. This matches real GCE metadata server behavior.

Service account paths that use an email identifier (e.g., `.../service-accounts/sa@project.iam.gserviceaccount.com/token`) are automatically aliased to `default`, since the proxy serves a single set of credentials. This ensures compatibility with `gcloud` and other client libraries that resolve accounts by email.

The proxy fetches tokens from the `gate` daemon via a Unix socket (local) or TCP+mTLS (remote) and caches them locally, re-fetching when less than 5 minutes of lifetime remain. The transport is determined automatically based on whether `--gate-url` or `GCP_AUTHCALATOR_GATE_URL` is configured.

### `with-prod` — Elevation wrapper

Wraps a shell command with production-level GCP credentials. Runs **inside the devcontainer**.

```bash
gcp-authcalator with-prod -- python some/script.py
gcp-authcalator with-prod -- gcloud sql instances list
gcp-authcalator with-prod -- alembic upgrade head
gcp-authcalator with-prod --scopes="https://www.googleapis.com/auth/sqlservice.login" -- cloud-sql-proxy my-project:us-central1:my-instance
```

**Required options:** `--project-id`

This command:

1. Requests a prod token from `gate` (triggers a host-side confirmation dialog)
2. Starts a temporary metadata proxy on a random port serving that token
3. Creates an isolated `CLOUDSDK_CONFIG` directory so `gcloud` doesn't reuse cached credentials
4. Strips credential-related environment variables (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_AUTH_ACCESS_TOKEN`, etc.) to force the child through the proxy
5. Spawns the wrapped command with `GCE_METADATA_HOST`, `GCE_METADATA_IP`, and `GCE_METADATA_ROOT` pointing at the temporary proxy
6. Forwards signals to the child process and propagates its exit code

The temporary proxy uses PID-based process restriction — only the wrapped command and its descendants can request tokens from it.

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

Certificates are generated with ECDSA P-256 with a 90-day lifetime for all certificates (CA, server, and client). All certs are treated as ephemeral and regenerated together. Gate requires certs to exist and be valid — it will refuse to start with `--gate-tls-port` if certs are missing or expired, directing you to run `init-tls`.

### `kube-setup` — Patch kubeconfig for GKE

One-time setup command that patches your kubeconfig to use gcp-authcalator instead of `gke-gcloud-auth-plugin` for GKE cluster authentication.

```bash
gcp-authcalator kube-setup
```

This command:

1. Reads the kubeconfig (from `$KUBECONFIG` or `~/.kube/config`)
2. Finds all users with `exec.command: gke-gcloud-auth-plugin` (including full paths)
3. Replaces the exec section to point to `gcp-authcalator kube-token`
4. Creates a backup at `<kubeconfig>.bak`
5. Writes the patched kubeconfig back

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

The plugin reads `GCE_METADATA_HOST` from the environment (falls back to `127.0.0.1:8173`) and requests a token from that metadata proxy. This means it automatically picks up the correct token:

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
- **Prod tokens**: `with-prod` requests fail immediately with a descriptive error.
- **Reconnection**: Automatic when port forwarding resumes — no restart of metadata-proxy required.

## Security model

### Threat model

gcp-authcalator is designed for environments where a coding agent (or other untrusted automation) runs in the same devcontainer as the engineer. The goal is to ensure that **all privilege escalation requires human approval** and that **credentials are never directly accessible inside the container**.

**Hard security boundaries:**

- **Credentials never enter the container.** The host daemon holds ADC; the container only receives short-lived, downscoped tokens. Even if the container is fully compromised, the attacker gets only a dev service account token — not the engineer's identity.
- **Cross-user isolation.** The Unix socket is set to `0600` (owner-only) and lives in a `0700` directory (`$XDG_RUNTIME_DIR` or `~/.gcp-authcalator/`). Processes running as other OS users cannot connect. **For strongest isolation, run coding agents as a separate OS user** — they will be unable to access the socket at all.
- **Mutual TLS for remote transport.** When using TCP for remote devcontainers, both gate and the client verify each other's identity via self-signed certificates. The gate only listens on localhost (port forwarding is required for remote access). The `gate_url` config option enforces `https://` — plaintext `http://` connections are rejected at config parse time.
- **Human-in-the-loop for production access.** Prod tokens require explicit confirmation via a desktop dialog (`osascript` on macOS, `zenity` on Linux) or terminal prompt on the host. If no interactive method is available, access is denied.
- **Rate limiting** prevents automated brute-forcing of the confirmation flow: one dialog at a time, a 5-second cooldown after denial, and a maximum of 5 attempts per minute.

**Best-effort protections** (defense in depth against same-user attacks):

- **PID-based process restriction** on `with-prod` temporary proxies ensures only the intended process tree can request elevated tokens. This uses `/proc` introspection and is effective against casual abuse, but a sufficiently privileged same-user process could circumvent it.
- **Environment isolation** in `with-prod` strips credential-related env vars (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_AUTH_ACCESS_TOKEN`, etc.) and uses a temporary `CLOUDSDK_CONFIG` in the user-private runtime directory to prevent credential leakage around the proxy.
- **Token files** are written with `0600` permissions in user-private directories, not passed via environment variables (which are readable via `/proc/*/environ`).
- **Audit logging** records all token requests as JSON lines to the runtime directory, providing a trail for forensic review.
- **Stale socket recovery** verifies socket ownership and refuses to follow symlinks, preventing TOCTOU races.

**Limitations:**

- A malicious process running as the **same user** with sufficient sophistication (e.g., `ptrace`, reading `/proc/*/mem`) can potentially extract tokens from a running process. Full same-user isolation requires OS-level sandboxing beyond what gcp-authcalator provides.
- Once the engineer approves a prod token request, the elevated token is available to the approved process tree for its lifetime (~1 hour). gcp-authcalator cannot revoke it early.
- **Stolen client bundle** (remote mode): An attacker with the client cert can authenticate to gate over a forwarded port. Mitigation: client bundle has 90-day expiry; bundle files are `0600`; gate only listens on localhost; prod tokens still require confirmation dialog.
- **Bundle in env var**: `GCP_AUTHCALATOR_TLS_BUNDLE_B64` is cleared from `process.env` immediately after reading to prevent inheritance by child processes. The bundle only authorizes gate communication, not GCP access directly.

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
bun run lint      # run ESLint
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
