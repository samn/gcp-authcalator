# Set up gcp-authcalator in a devcontainer

You are setting up gcp-authcalator in a project's devcontainer. gcp-authcalator
keeps GCP credentials on the host machine and serves downscoped, time-limited
tokens to the container via a metadata server emulator. Production access
requires explicit human confirmation via a desktop dialog on the host.

**Current version: 0.1.5**
**GitHub: samn/gcp-authcalator**

## Step 1: Analyze the existing devcontainer setup

Read the project's devcontainer configuration:

1. Check if `.devcontainer/` directory exists
2. Read `.devcontainer/devcontainer.json` (or `devcontainer.json` at project
   root)
3. Determine if docker-compose is used:
   - Look for `dockerComposeFile` property in devcontainer.json
   - Check for `docker-compose.yml`, `docker-compose.yaml`, or `compose.yml` in
     `.devcontainer/`
4. Detect the container user:
   - Look for `remoteUser` in devcontainer.json
   - If using docker-compose, check the Dockerfile for `USER` directives
   - **If not found, ask the user** what the container username is
5. Check for existing lifecycle scripts or commands (`initializeCommand`,
   `postStartCommand`, `postCreateCommand`)

**If there is no `.devcontainer/` directory**, ask the user if they want to:
- Create a minimal devcontainer setup from scratch
- Point you to where their devcontainer config lives
- Abort and set things up manually

## Step 2: Verify host prerequisites

Tell the user they need these prerequisites on their host machine. Ask them to
confirm each one or address any that are missing:

1. **GCP Application Default Credentials**: Run
   `gcloud auth application-default login` on the host if not already done
2. **Service account**: A GCP service account for dev access (e.g.,
   `dev-runner@<project>.iam.gserviceaccount.com`) with appropriate limited
   permissions
3. **IAM role**: The user's GCP account must have
   `roles/iam.serviceAccountTokenCreator` on that service account

## Step 3: Create or verify the config file

The gate daemon needs a config file at `~/.gcp-authcalator/config.toml`. This
file is shared between host and container via the volume mount.

Check if the user already has this file. If not, ask them for:
- `project_id`: Their GCP project ID
- `service_account`: The service account email to impersonate

Then tell them to create `~/.gcp-authcalator/config.toml` with:

```toml
project_id = "<project-id>"
service_account = "<service-account-email>"
```

## Step 4: Version selection

Use version **0.1.5** by default. Ask the user if they want to use a different
version.

Binary download URLs:
- macOS ARM64: `https://github.com/samn/gcp-authcalator/releases/download/v<VERSION>/gcp-authcalator-darwin-arm64`
- Linux x86_64: `https://github.com/samn/gcp-authcalator/releases/download/v<VERSION>/gcp-authcalator-linux-amd64`

## Step 5: Create the initialize script (runs on host)

Create `.devcontainer/gcp-authcalator-initialize.sh`. This script runs on the
**host machine** before the container is built. It downloads the
host-architecture binary and starts the gate daemon.

Replace `<VERSION>` with the chosen version.

```bash
#!/usr/bin/env bash
set -euo pipefail

AUTHCALATOR_VERSION="<VERSION>"
AUTHCALATOR_DIR="$HOME/.gcp-authcalator"
AUTHCALATOR_BIN="$AUTHCALATOR_DIR/bin/gcp-authcalator"
AUTHCALATOR_CONFIG="$AUTHCALATOR_DIR/config.toml"
SOCKET_PATH="$AUTHCALATOR_DIR/gcp-authcalator.sock"

# Detect host platform
detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$os-$arch" in
    darwin-arm64)  echo "darwin-arm64" ;;
    darwin-x86_64) echo "darwin-arm64" ;; # Rosetta compatible
    linux-x86_64)  echo "linux-amd64" ;;
    linux-aarch64) echo "linux-amd64" ;;
    *) echo "[gcp-authcalator] Unsupported platform: $os-$arch" >&2; exit 1 ;;
  esac
}

# Download binary if missing or wrong version
ensure_binary() {
  mkdir -p "$AUTHCALATOR_DIR/bin"

  if [[ -x "$AUTHCALATOR_BIN" ]]; then
    local current_version
    current_version="$("$AUTHCALATOR_BIN" version 2>/dev/null | awk '{print $1}' || echo "")"
    if [[ "$current_version" == "$AUTHCALATOR_VERSION" ]]; then
      echo "[gcp-authcalator] Binary v$AUTHCALATOR_VERSION already installed"
      return
    fi
    echo "[gcp-authcalator] Upgrading from $current_version to $AUTHCALATOR_VERSION"
  fi

  local platform
  platform="$(detect_platform)"
  local url="https://github.com/samn/gcp-authcalator/releases/download/v${AUTHCALATOR_VERSION}/gcp-authcalator-${platform}"

  echo "[gcp-authcalator] Downloading v$AUTHCALATOR_VERSION for $platform..."
  curl -fsSL "$url" -o "$AUTHCALATOR_BIN"
  chmod +x "$AUTHCALATOR_BIN"
  echo "[gcp-authcalator] Installed to $AUTHCALATOR_BIN"
}

# Check if gate daemon is already running and healthy
is_gate_running() {
  [[ -S "$SOCKET_PATH" ]] && \
    curl -sf --unix-socket "$SOCKET_PATH" http://gate/health >/dev/null 2>&1
}

# Start gate daemon with automatic restart on crash
start_gate() {
  if [[ ! -f "$AUTHCALATOR_CONFIG" ]]; then
    echo "[gcp-authcalator] ERROR: Config not found at $AUTHCALATOR_CONFIG" >&2
    echo "[gcp-authcalator] Create it with project_id and service_account." >&2
    echo "[gcp-authcalator] See: https://github.com/samn/gcp-authcalator#configuration" >&2
    exit 1
  fi

  if is_gate_running; then
    echo "[gcp-authcalator] Gate daemon already running"
    return
  fi

  echo "[gcp-authcalator] Starting gate daemon..."
  (
    while true; do
      "$AUTHCALATOR_BIN" gate \
        --config "$AUTHCALATOR_CONFIG" \
        --socket-path "$SOCKET_PATH" 2>&1 \
        | sed 's/^/[gcp-authcalator gate] /' || true
      echo "[gcp-authcalator] Gate daemon exited, restarting in 2s..." >&2
      sleep 2
    done
  ) &
  disown

  # Wait for gate to become healthy
  local i
  for i in $(seq 1 15); do
    if is_gate_running; then
      echo "[gcp-authcalator] Gate daemon is healthy"
      return
    fi
    sleep 1
  done
  echo "[gcp-authcalator] WARNING: Gate daemon may not have started. Check logs." >&2
}

ensure_binary
start_gate
```

## Step 6: Create the post-start script (runs in container)

Create `.devcontainer/gcp-authcalator-post-start.sh`. This script runs **inside
the container** each time the container starts. It downloads the linux-amd64
binary, ensures socat is installed, and starts the metadata proxy and socat
forwarder.

Replace `<VERSION>` with the chosen version.

```bash
#!/usr/bin/env bash
set -euo pipefail

AUTHCALATOR_VERSION="<VERSION>"
AUTHCALATOR_BIN="/usr/local/bin/gcp-authcalator"
AUTHCALATOR_CONFIG="$HOME/.gcp-authcalator/config.toml"
SOCKET_PATH="$HOME/.gcp-authcalator/gcp-authcalator.sock"

# Download container binary if missing or wrong version
ensure_binary() {
  if [[ -x "$AUTHCALATOR_BIN" ]]; then
    local current_version
    current_version="$("$AUTHCALATOR_BIN" version 2>/dev/null | awk '{print $1}' || echo "")"
    if [[ "$current_version" == "$AUTHCALATOR_VERSION" ]]; then
      echo "[gcp-authcalator] Container binary v$AUTHCALATOR_VERSION already installed"
      return
    fi
    echo "[gcp-authcalator] Upgrading container binary to v$AUTHCALATOR_VERSION"
  fi

  local url="https://github.com/samn/gcp-authcalator/releases/download/v${AUTHCALATOR_VERSION}/gcp-authcalator-linux-amd64"
  echo "[gcp-authcalator] Downloading v$AUTHCALATOR_VERSION for container..."
  sudo curl -fsSL "$url" -o "$AUTHCALATOR_BIN"
  sudo chmod +x "$AUTHCALATOR_BIN"
  echo "[gcp-authcalator] Installed to $AUTHCALATOR_BIN"
}

# Install socat if not present
ensure_socat() {
  if command -v socat &>/dev/null; then
    return
  fi
  echo "[gcp-authcalator] Installing socat..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -yqq socat
  elif command -v apk &>/dev/null; then
    sudo apk add --no-cache socat
  elif command -v yum &>/dev/null; then
    sudo yum install -y socat
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y socat
  else
    echo "[gcp-authcalator] ERROR: Cannot install socat (unknown package manager)" >&2
    echo "[gcp-authcalator] Install socat manually and re-run this script." >&2
    return 1
  fi
}

# Check if metadata proxy is already running
is_proxy_running() {
  curl -sf http://127.0.0.1:8173/ >/dev/null 2>&1
}

# Start metadata proxy with automatic restart on crash
start_metadata_proxy() {
  if is_proxy_running; then
    echo "[gcp-authcalator] Metadata proxy already running"
    return
  fi

  echo "[gcp-authcalator] Starting metadata proxy..."
  (
    while true; do
      "$AUTHCALATOR_BIN" metadata-proxy \
        --config "$AUTHCALATOR_CONFIG" \
        --socket-path "$SOCKET_PATH" 2>&1 \
        | sed 's/^/[gcp-authcalator proxy] /' || true
      echo "[gcp-authcalator] Metadata proxy exited, restarting in 2s..." >&2
      sleep 2
    done
  ) &
  disown
}

# Start socat to forward port 80 -> 8173 (some GCP libraries check port 80)
start_socat() {
  if sudo ss -tlnp 2>/dev/null | grep -q ':80 '; then
    echo "[gcp-authcalator] Port 80 already in use, skipping socat"
    return
  fi

  echo "[gcp-authcalator] Starting socat (127.0.0.1:80 -> 127.0.0.1:8173)..."
  (
    while true; do
      sudo socat TCP-LISTEN:80,fork,reuseaddr,bind=127.0.0.1 TCP:127.0.0.1:8173 || true
      echo "[gcp-authcalator] socat exited, restarting in 2s..." >&2
      sleep 2
    done
  ) &
  disown
}

ensure_binary
ensure_socat
start_metadata_proxy
start_socat

echo "[gcp-authcalator] All container services started"
```

## Step 7: Modify devcontainer.json

Determine whether the project uses docker-compose or a plain devcontainer.json,
then apply the appropriate changes.

### Plain devcontainer.json (no docker-compose)

Add or merge these properties into `.devcontainer/devcontainer.json`. Replace
`<CONTAINER_USER>` with the detected container username.

```jsonc
{
  "mounts": [
    "source=${localEnv:HOME}/.gcp-authcalator,target=/home/<CONTAINER_USER>/.gcp-authcalator,type=bind"
  ],
  "remoteEnv": {
    "GCE_METADATA_HOST": "127.0.0.1:8173",
    "GCE_METADATA_IP": "127.0.0.1:8173",
    "GCE_METADATA_ROOT": "127.0.0.1:8173"
  },
  "initializeCommand": ".devcontainer/gcp-authcalator-initialize.sh",
  "postStartCommand": ".devcontainer/gcp-authcalator-post-start.sh"
}
```

### With docker-compose

When docker-compose is used, volume mounts and environment variables go in the
**compose file**, not devcontainer.json.

In the compose file, under the appropriate service:

```yaml
volumes:
  - ~/.gcp-authcalator:/home/<CONTAINER_USER>/.gcp-authcalator
environment:
  GCE_METADATA_HOST: "127.0.0.1:8173"
  GCE_METADATA_IP: "127.0.0.1:8173"
  GCE_METADATA_ROOT: "127.0.0.1:8173"
```

Lifecycle commands still go in devcontainer.json:

```jsonc
{
  "initializeCommand": ".devcontainer/gcp-authcalator-initialize.sh",
  "postStartCommand": ".devcontainer/gcp-authcalator-post-start.sh"
}
```

### Handling existing lifecycle commands

**CRITICAL: Do not silently overwrite existing lifecycle commands.** If the
devcontainer.json already has `initializeCommand` or `postStartCommand`, ask the
user which approach they prefer:

1. **Wrap in a script** (recommended): Create a wrapper script that calls the
   existing command and then the gcp-authcalator script
2. **Use object form**: devcontainer.json supports an object form where multiple
   named commands run in parallel:
   ```jsonc
   {
     "initializeCommand": {
       "existing": "<existing command>",
       "gcp-authcalator": ".devcontainer/gcp-authcalator-initialize.sh"
     }
   }
   ```
3. **Replace entirely**: Only if the user explicitly confirms

If the existing command is already an object, add the gcp-authcalator entry to
it.

### Handling docker-compose with multiple services

If the compose file has multiple services, ask the user which service is their
devcontainer service. Look for hints:
- The `service` property in devcontainer.json
- A service named `app`, `dev`, `devcontainer`, or similar
- The service with the most configuration

## Step 8: Optional — GKE kubectl integration

Ask the user if they use kubectl with GKE clusters. If yes:

1. Ask for the cluster name, region, and project ID
2. Add the following to the **end** of `gcp-authcalator-post-start.sh`, after
   the metadata proxy is started:

```bash
# --- GKE kubectl integration ---
# Wait for metadata proxy to be ready
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8173/ >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

gcloud container clusters get-credentials <CLUSTER> \
  --region <REGION> --project <PROJECT>
gcp-authcalator kube-setup
echo "[gcp-authcalator] kubectl configured for GKE"
```

## Step 9: Finalize and verify

After making all changes:

1. Make the shell scripts executable: `chmod +x .devcontainer/gcp-authcalator-*.sh`
2. Present the user with a verification summary:

```
gcp-authcalator devcontainer setup complete!

Host side:
  - Binary: ~/.gcp-authcalator/bin/gcp-authcalator (downloaded on first run)
  - Config: ~/.gcp-authcalator/config.toml
  - Gate daemon starts automatically via initializeCommand

Container side:
  - Binary: /usr/local/bin/gcp-authcalator (downloaded on first start)
  - Metadata proxy on 127.0.0.1:8173
  - socat forwarding 127.0.0.1:80 -> 127.0.0.1:8173
  - Both restart automatically on crash

Environment:
  - GCE_METADATA_HOST=127.0.0.1:8173
  - GCE_METADATA_IP=127.0.0.1:8173
  - GCE_METADATA_ROOT=127.0.0.1:8173

Volume mount:
  - ~/.gcp-authcalator -> /home/<user>/.gcp-authcalator

Prerequisites (verify on host):
  - [ ] gcloud auth application-default login
  - [ ] ~/.gcp-authcalator/config.toml exists with project_id and service_account
  - [ ] Service account has appropriate dev permissions
  - [ ] Your GCP user has roles/iam.serviceAccountTokenCreator on the SA
```

## When to ask the user

Always ask the user — do NOT assume — when:

- The container username cannot be determined from devcontainer.json or Dockerfile
- Existing lifecycle commands would be overwritten or modified
- Docker-compose has multiple services and the target is ambiguous
- The project has no devcontainer configuration at all
- Any configuration detail is unclear or could go multiple ways
- The user's setup doesn't match any expected pattern
