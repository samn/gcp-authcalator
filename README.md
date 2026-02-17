# gcp-authcalator

A GCP auth escalator for containerized development environments.
Keeps GCP credentials out of devcontainers and AI coding agents by proxying token requests through a host-side daemon with confirmation dialogs for production access.

## Problem

GCP credentials inside a devcontainer are global — `google.auth.default()` returns the engineer's full-privilege credentials to any process.
An unattended coding agent has the same access as the engineer, including production database writes and secret decryption.

gcp-authcalator solves this by:

1. Running a **token daemon** (`gate`) on the host that mints short-lived, downscoped tokens
2. Running a **metadata server emulator** (`metadata-proxy`) inside the container that serves those tokens transparently to all Google Cloud client libraries
3. Requiring **explicit confirmation** before issuing production-level tokens

Credentials never enter Docker.
The Unix socket is the only channel, and the host daemon controls what tokens are issued.

## Architecture

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

Settings can be provided via CLI flags, a TOML config file, or both.
CLI flags take precedence over the config file, which takes precedence over defaults.

### CLI flags

```
--project-id <id>          GCP project ID
--service-account <email>  Service account email to impersonate
--socket-path <path>       Unix socket path (default: $XDG_RUNTIME_DIR/gcp-authcalator.sock)
-p, --port <port>          Metadata proxy port (default: 8173)
-c, --config <path>        Path to TOML config file
```

### TOML config file

```toml
project_id = "my-gcp-project"
service_account = "dev-runner@my-gcp-project.iam.gserviceaccount.com"
# socket_path defaults to $XDG_RUNTIME_DIR/gcp-authcalator.sock
# (or ~/.gcp-gate/gcp-authcalator.sock if XDG_RUNTIME_DIR is unset)
port = 8173
```

Pass the file with `--config`:

```bash
gcp-authcalator gate --config config.toml
```

## Commands

### `gate` — Host-side token daemon

Runs on the **host machine**. Listens on a Unix domain socket and mints GCP access tokens.

```bash
gcp-authcalator gate \
  --project-id my-project \
  --service-account dev-runner@my-project.iam.gserviceaccount.com
```

**Required options:** `--project-id`, `--service-account`

**API endpoints** (over Unix socket):

| Endpoint                | Behavior                                                         |
| ----------------------- | ---------------------------------------------------------------- |
| `GET /token`            | Returns a dev-scoped access token (impersonated service account) |
| `GET /token?level=prod` | Prompts for confirmation, then returns the engineer's own token  |
| `GET /identity`         | Returns the authenticated user's email                           |
| `GET /project-number`   | Returns the numeric GCP project ID                               |
| `GET /universe-domain`  | Returns the GCP universe domain                                  |
| `GET /health`           | Returns `{ "status": "ok", "uptime_seconds": N }`                |

**Dev tokens** are minted by impersonating the configured service account. They are cached and re-minted when less than 5 minutes of lifetime remain.

**Prod tokens** use the engineer's own ADC credentials. Before issuing a prod token, the daemon:

1. Shows a desktop confirmation dialog (`osascript` on macOS, `zenity` on Linux)
2. Falls back to a terminal prompt if no GUI is available
3. Denies access if no interactive method is available

Prod token requests are rate-limited: one confirmation dialog at a time, a 5-second cooldown after denial, and a maximum of 5 attempts per minute.

**Audit logging:** All token requests are logged as JSON lines to `~/.gcp-gate/audit.log`.

### `metadata-proxy` — Container-side metadata emulator

Runs **inside the devcontainer**. Emulates the [GCE metadata server](https://cloud.google.com/compute/docs/metadata/overview) so that all Google Cloud client libraries transparently fetch tokens from the proxy.

```bash
gcp-authcalator metadata-proxy --project-id my-project
```

**Required options:** `--project-id`

Set `GCE_METADATA_HOST=127.0.0.1:8173 GCE_METADATA_IP=127.0.0.1:8173` in the container environment so client libraries discover the proxy automatically.

**Endpoints:**

| Path                                                              | Response                               | `Metadata-Flavor: Google` required? |
| ----------------------------------------------------------------- | -------------------------------------- | ----------------------------------- |
| `GET /`                                                           | `200 ok` (detection ping)              | No                                  |
| `GET /computeMetadata/v1/instance/service-accounts/default/token` | Token JSON                             | Yes                                 |
| `GET /computeMetadata/v1/project/project-id`                      | Plain text project ID                  | Yes                                 |
| `GET /computeMetadata/v1/project/numeric-project-id`              | Plain text numeric project ID          | Yes                                 |
| `GET /computeMetadata/v1/universe/universe-domain`                | Plain text universe domain             | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default/email` | Plain text SA email                    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts/default`       | SA info (JSON or directory listing)    | Yes                                 |
| `GET /computeMetadata/v1/instance/service-accounts`               | SA listing (JSON or directory listing) | Yes                                 |

Endpoints returning "JSON or directory listing" respond with JSON when `?recursive=true` is passed, and a text directory listing otherwise. This matches real GCE metadata server behavior.

Service account paths that use an email identifier (e.g., `.../service-accounts/sa@project.iam.gserviceaccount.com/token`) are automatically aliased to `default`, since the proxy serves a single set of credentials. This ensures compatibility with `gcloud` and other client libraries that resolve accounts by email.

The proxy fetches tokens from the `gate` daemon via the Unix socket and caches them locally, re-fetching when less than 5 minutes of lifetime remain.

### `with-prod` — Elevation wrapper

Wraps a shell command with production-level GCP credentials. Runs **inside the devcontainer**.

```bash
gcp-authcalator with-prod -- python some/script.py
gcp-authcalator with-prod -- gcloud sql instances list
gcp-authcalator with-prod -- alembic upgrade head
```

**Required options:** `--project-id`

This command:

1. Requests a prod token from `gate` (triggers a host-side confirmation dialog)
2. Starts a temporary metadata proxy on a random port serving that token
3. Creates an isolated `CLOUDSDK_CONFIG` directory so `gcloud` doesn't reuse cached credentials
4. Strips credential-related environment variables (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_AUTH_ACCESS_TOKEN`, etc.) to force the child through the proxy
5. Spawns the wrapped command with `GCE_METADATA_HOST` and `GCE_METADATA_IP` pointing at the temporary proxy
6. Forwards signals to the child process and propagates its exit code

The temporary proxy uses PID-based process restriction — only the wrapped command and its descendants can request tokens from it.

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
   The socket lives in a user-private directory — use `$XDG_RUNTIME_DIR` (typically `/run/user/$UID`) or `~/.gcp-gate/` if that's unset:

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
     "GCE_METADATA_IP": "127.0.0.1:8173"
   }
   ```

5. **Container (optional):** If you use `kubectl` with GKE, patch the kubeconfig so kubectl fetches tokens through gcp-authcalator instead of `gke-gcloud-auth-plugin`:

   ```bash
   gcloud container clusters get-credentials <cluster> --region <region> --project <project>
   gcp-authcalator kube-setup
   ```

   This ensures `kubectl` works correctly under both normal and `with-prod` usage.

## Security model

- **Credentials never enter the container.** The host daemon holds ADC; the container only receives short-lived tokens.
- **User-private runtime directory.** The socket and temporary files are placed in `$XDG_RUNTIME_DIR` (typically `/run/user/$UID`, already `0700`) or `~/.gcp-gate/` (created with `0700`), rather than world-writable `/tmp`. This eliminates TOCTOU symlink races from other local users.
- **Unix socket permissions** are set to `0600` (owner-only) on creation.
- **Prod access requires confirmation** via a GUI dialog or terminal prompt on the host.
- **Rate limiting** prevents automated brute-forcing of the confirmation flow.
- **PID-based restriction** on temporary `with-prod` proxies ensures only the intended process tree can use elevated tokens.
- **Environment isolation** in `with-prod` strips credential-related env vars and uses a temporary `CLOUDSDK_CONFIG` (in the user-private runtime directory) to prevent credential leakage around the proxy.
- **Audit logging** records all token requests to `~/.gcp-gate/audit.log` (directory created with `0700` permissions).
- **Stale socket recovery** verifies socket ownership and checks for running instances before cleanup.

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
bun run build:darwin-arm64   # cross-compile for macOS ARM64
```

See [docs/releasing.md](docs/releasing.md) for the release process.
