# Remote Devcontainer Support

## Goal

Extend gcp-authcalator to work with remote development environments:
- **SSH devcontainer**: VS Code Remote-SSH → remote host → devcontainer
- **GitHub Codespaces**: cloud-hosted devcontainer
- **Coder**: self-hosted or cloud workspace environments

The core security property must be preserved: **credentials never leave the developer's machine**. Gate always runs locally on the developer's laptop.

## Problem

Today, gcp-gate communicates with gcp-metadata-proxy (and with-prod) exclusively over a **Unix domain socket** that is bind-mounted from host into the container. This only works when Docker runs on the same machine as gate.

In remote scenarios, the devcontainer runs on a different machine (remote SSH host, Codespace VM, Coder workspace). Unix sockets cannot cross network boundaries.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Gate location | Always local (developer's laptop) | Credentials never leave the machine you're sitting at |
| Remote transport | TCP + mutual TLS | One mechanism for all remote scenarios (SSH, Codespaces, Coder) |
| Certificate algorithm | Ed25519 | Faster, smaller; compatibility is ensured because certs are internal to this tool |
| X.509 library | `node-forge` | Widely adopted, good compatibility |
| Certificate lifetime | 90-day server/client certs, 1-year CA | Reasonable rotation cadence (~4/year) |
| Auto-regeneration | Yes, on gate startup | Better DX; gate warns when certs are regenerated so user can update remotes |
| Bundle distribution | Base64-encoded env var (`GCP_AUTHCALATOR_TLS_BUNDLE_B64`) | Works with Codespace secrets, Coder secrets, SSH env; one env var to set |
| Rotation | Manual; gate warns on regeneration | Simple, predictable; `init-tls --bundle-b64` makes it easy |
| PID validation | mTLS for gate↔proxy transport; PID checks remain for with-prod temp proxy | mTLS can't replace PID checks (google-auth libs use plain HTTP to metadata proxy) |
| Local devcontainer | Unchanged (Unix socket) | No regression, TCP+mTLS is purely additive |

## Architecture

### Transport: TCP + Mutual TLS

Add a TCP listener mode to gate, secured with **self-signed mutual TLS (mTLS)**:

1. Gate generates a private CA (on first run with `--tcp-port`, or via `gcp-authcalator init-tls`)
2. Gate generates a server certificate signed by the CA
3. Gate generates a client certificate signed by the CA (for metadata-proxy / with-prod)
4. Gate listens on `127.0.0.1:<tcp-port>` with TLS, requiring a valid client certificate
5. Metadata-proxy / with-prod connect using the client certificate, verifying the server against the CA

The CA + client cert + client key form a **"client bundle"** — a single base64-encoded string that is distributed to remote environments via environment variables. This is **not** a GCP credential — it only authorizes communication with gate.

### Why mTLS (not bearer tokens)?

- **Mutual authentication**: both sides verify identity (gate verifies client, client verifies gate)
- **No shared secret in transit**: TLS handshake, not a header token that could be logged
- **Certificate pinning**: the self-signed CA means no trust-store dependency
- **Replay resistance**: TLS session keys are ephemeral

### Connection Flow (Remote)

```
Developer's Laptop                          Remote Host / Codespace / Coder
┌─────────────────────┐                     ┌──────────────────────────────┐
│  ADC credentials    │                     │  Devcontainer                │
│  gcp-gate daemon    │◄── mTLS over ───────│  gcp-metadata-proxy          │
│    TCP :8174        │    forwarded port    │    (127.0.0.1:8173)          │
│  Confirmation UI    │                     │  with-prod                   │
│  CA + server cert   │                     │  CA cert + client cert/key   │
└─────────────────────┘                     └──────────────────────────────┘
         │                                           │
    SSH port forward                          Port forwarding via:
    gh cs ports forward                        - SSH -R
    coder port-forward                         - VS Code
    VS Code port forward                       - gh CLI
                                               - Coder CLI
```

### Client Bundle Distribution

The client bundle (CA cert + client cert + client key) is distributed as a **base64-encoded environment variable**: `GCP_AUTHCALATOR_TLS_BUNDLE_B64`.

```bash
# On laptop — get the bundle value:
$ gcp-authcalator init-tls --bundle-b64
LS0tLS1CRUdJTi...(base64)...

# Set as:
#   - GitHub Codespaces: repository or org secret
#   - Coder: workspace secret
#   - SSH: export in remote shell profile or devcontainer env
```

At startup, metadata-proxy (and with-prod) check for `GCP_AUTHCALATOR_TLS_BUNDLE_B64`:
1. If set: base64-decode → write to `$XDG_RUNTIME_DIR/gcp-authcalator/client-bundle.pem` (0600) → use for mTLS
2. If not set: fall back to `--tls-bundle` file path or Unix socket mode

### Certificate Rotation

- Gate auto-regenerates expired certs on startup, logging a prominent warning:
  ```
  gate: ⚠ TLS certificates regenerated (previous certs expired)
  gate: Remote client bundles need updating!
  gate: Run: gcp-authcalator init-tls --bundle-b64
  ```
- 90-day client/server certs → ~4 rotations per year
- 1-year CA → client bundles survive server cert rotation (only CA rotation requires new bundles)
- Rotation is manual: user copies the new bundle value to their secrets

### Connection Flow (Local — unchanged)

Unix socket mode remains the default for local devcontainers. No changes to the existing local flow.

## Implementation Plan

### Phase 1: TLS Certificate Management

**New module: `src/tls/`**

**Dependency: `node-forge`** — add via `bun add node-forge` + `bun add -d @types/node-forge`

#### 1.1 `src/tls/ca.ts` — Certificate Authority generation

- `generateCA()`: Generate a self-signed CA with Ed25519 keypair
  - Returns: `{ caCert: string, caKey: string }` (PEM format)
  - Subject: `CN=gcp-authcalator CA`
  - Validity: 1 year
  - Uses `node-forge` for X.509 certificate generation

#### 1.2 `src/tls/certs.ts` — Certificate generation

- `generateServerCert(caCert, caKey)`: Generate server cert signed by CA
  - SAN: `localhost`, `127.0.0.1`
  - EKU: serverAuth
  - Validity: 90 days
  - Ed25519 keypair
- `generateClientCert(caCert, caKey)`: Generate client cert signed by CA
  - EKU: clientAuth
  - Validity: 90 days
  - Ed25519 keypair
  - Subject: `CN=gcp-authcalator client`

#### 1.3 `src/tls/store.ts` — Certificate storage and loading

- Default location: `~/.gcp-authcalator/tls/` (persistent across reboots, unlike `$XDG_RUNTIME_DIR`)
- Files (all `0600`):
  - `ca.pem` — CA certificate
  - `ca-key.pem` — CA private key
  - `server.pem` — server certificate
  - `server-key.pem` — server private key
  - `client.pem` — client certificate
  - `client-key.pem` — client private key
  - `client-bundle.pem` — combined: CA cert + client cert + client key (single file)
- Functions:
  - `ensureTlsFiles(tlsDir?)`: Generate all certs if missing or expired; return paths. Logs warning if regenerating expired certs.
  - `loadTlsFiles(tlsDir?)`: Load and return PEM contents for server-side and client-side configs
  - `loadClientBundle(bundlePath)`: Parse a client-bundle.pem into { caCert, clientCert, clientKey }
  - `loadClientBundleFromBase64(b64)`: Decode base64, write to temp file, then loadClientBundle
  - `getClientBundleBase64(tlsDir?)`: Read client-bundle.pem and return base64-encoded string
- Directory created with `0700` permissions
- Check expiry by parsing the cert's `notAfter` field

#### 1.4 `src/tls/bundle.ts` — Bundle resolution

- `resolveClientBundle(config, env)`: Determine client bundle source, in priority order:
  1. `GCP_AUTHCALATOR_TLS_BUNDLE_B64` env var → decode from base64
  2. `--tls-bundle` / `tls_bundle` config → load from file path
  3. `null` (no bundle → use Unix socket mode)
- Returns `{ caCert, clientCert, clientKey }` or `null`

#### 1.5 `src/commands/init-tls.ts` — CLI command

- `gcp-authcalator init-tls`: Force-regenerate all TLS certificates
  - Prints paths to generated files
  - Prints the client bundle base64 to stdout for easy copying
- `gcp-authcalator init-tls --bundle-b64`: Print only the base64-encoded client bundle (for piping into `gh secret set`, `pbcopy`, etc.)
- `gcp-authcalator init-tls --show-path`: Print only the TLS directory path

### Phase 2: Gate TCP Listener

#### 2.1 Modify `src/gate/server.ts`

- Add optional TCP listener alongside the existing Unix socket:
  ```typescript
  // Existing Unix socket server (unchanged)
  const unixServer = Bun.serve({ unix: config.socket_path, fetch(req) { ... } });

  // New optional TCP+mTLS server
  if (config.tcp_port) {
    const tlsFiles = await ensureTlsFiles(config.tls_dir);
    const tcpServer = Bun.serve({
      hostname: "127.0.0.1",
      port: config.tcp_port,
      tls: {
        cert: tlsFiles.serverCert,
        key: tlsFiles.serverKey,
        ca: tlsFiles.caCert,
        requestCert: true,
        rejectUnauthorized: true,
      },
      fetch(req) { return handleRequest(req, deps); },
    });
  }
  ```
- Both listeners share the same `handleRequest` and `GateDeps`
- TCP server only starts if `tcp_port` is configured
- Auto-generate TLS certificates on first TCP listen (call `ensureTlsFiles()`)
- Return both servers from `startGateServer` for cleanup

#### 2.2 Modify `src/config.ts`

- Add to `ConfigSchema`:
  ```typescript
  tcp_port: z.coerce.number().int().min(1).max(65535).optional(),
  tls_dir: z.string().min(1).optional().transform(v => v ? expandTilde(v) : v),
  gate_url: z.string().min(1).optional(),    // for metadata-proxy / with-prod
  tls_bundle: z.string().min(1).optional().transform(v => v ? expandTilde(v) : v),
  ```
- Add CLI arg mappings in `cliToConfigKey`:
  - `"tcp-port"` → `"tcp_port"`
  - `"tls-dir"` → `"tls_dir"`
  - `"gate-url"` → `"gate_url"`
  - `"tls-bundle"` → `"tls_bundle"`
- Add env var merging in `loadConfig` (env vars have lowest precedence: schema defaults < env vars < TOML file < CLI args):
  - `GCP_AUTHCALATOR_GATE_URL` → `gate_url`
  - `GCP_AUTHCALATOR_TLS_BUNDLE` → `tls_bundle` (file path)
  - `GCP_AUTHCALATOR_TLS_BUNDLE_B64` is handled separately in bundle resolution (Phase 1.4), not in config

#### 2.3 Modify `src/commands/gate.ts`

- Wire `tcp_port` and `tls_dir` from config into `startGateServer`
- Print TCP listener info at startup (port, TLS status)
- Print the client bundle base64 on first start for easy reference

### Phase 3: Gate Client TCP Support

#### 3.1 Introduce `GateConnection` type

New shared type (in `src/gate/connection.ts` or `src/config.ts`):
```typescript
export type GateConnection =
  | { mode: "unix"; socketPath: string }
  | { mode: "tcp"; gateUrl: string; caCert: string; clientCert: string; clientKey: string };
```

Helper: `buildGateConnection(config, env)`:
- If `gate_url` is configured (or `GCP_AUTHCALATOR_GATE_URL` env var): resolve client bundle → return `tcp` mode
- Otherwise: return `unix` mode with `socket_path`

#### 3.2 Modify `src/metadata-proxy/gate-client.ts`

- `checkGateConnection(conn: GateConnection)`: replaces `checkGateSocket`
  - `unix` mode: existing socket file check + health request
  - `tcp` mode: HTTPS health check with mTLS client cert
- `createGateClient(conn: GateConnection)`: replaces `createGateClient(socketPath, options)`
  - `unix` mode: existing `fetch("http://localhost/...", { unix: socketPath })`
  - `tcp` mode: `fetch(gateUrl + "/...", { tls: { cert, key, ca } })`
  - Returned `GateClient` interface is identical — callers are transport-agnostic

#### 3.3 Modify `src/metadata-proxy/server.ts`

- Accept `GateConnection` instead of relying solely on `config.socket_path`
- Pass through to `createGateClient`
- The metadata-proxy HTTP server (127.0.0.1:8173) stays plain HTTP — google-auth libraries expect the GCE metadata protocol

#### 3.4 Modify `src/commands/metadata-proxy.ts`

- Build `GateConnection` from config + env vars using `buildGateConnection`
- Pass to `startMetadataProxyServer`
- Add startup log line: "gate connection: Unix socket at /path" or "gate connection: TCP+mTLS to https://localhost:8174"

### Phase 4: with-prod TCP Support

#### 4.1 Modify `src/with-prod/fetch-prod-token.ts`

- Change signature:
  ```typescript
  // Before:
  fetchProdToken(socketPath: string, options?)
  // After:
  fetchProdToken(conn: GateConnection, options?)
  ```
- `unix` mode: existing `fetch("http://localhost/...", { unix: socketPath })`
- `tcp` mode: `fetch(gateUrl + "/...", { tls: { cert, key, ca }, headers: { "X-Wrapped-Command": ... } })`

#### 4.2 Modify `src/commands/with-prod.ts`

- Build `GateConnection` from config + env using `buildGateConnection`
- Pass to `fetchProdToken`
- PID validation on the temp metadata proxy is unchanged (container-local)

### Phase 5: CLI and Config Updates

#### 5.1 Update `src/cli.ts`

- Add `init-tls` subcommand to `SUBCOMMANDS`
- Add new CLI options to `parseArgs`:
  - `"tcp-port"`: `{ type: "string" }`
  - `"tls-dir"`: `{ type: "string" }`
  - `"gate-url"`: `{ type: "string" }`
  - `"tls-bundle"`: `{ type: "string" }`
  - `"bundle-b64"`: `{ type: "boolean" }` (for init-tls)
  - `"show-path"`: `{ type: "boolean" }` (for init-tls)
- Update USAGE text with new commands and options
- Wire `init-tls` to `runInitTls`

#### 5.2 TOML config examples

Gate config (on laptop):
```toml
project_id = "my-project"
service_account = "dev@my-project.iam.gserviceaccount.com"
tcp_port = 8174
```

Metadata-proxy config (in remote container):
```toml
project_id = "my-project"
gate_url = "https://localhost:8174"
# tls_bundle not needed if GCP_AUTHCALATOR_TLS_BUNDLE_B64 env var is set
```

### Phase 6: Documentation

#### 6.1 Update `SPEC.md`

Add a new "Remote Development" section after the current Architecture section:
- Explain the problem (Unix sockets can't cross network boundaries)
- Describe the mTLS transport layer
- Document the client bundle concept and distribution via env var
- Update the architecture diagram to show both Unix socket (local) and TCP+mTLS (remote) paths
- Document the `init-tls` command
- Document new config options: `tcp_port`, `tls_dir`, `gate_url`, `tls_bundle`
- Document new env vars: `GCP_AUTHCALATOR_GATE_URL`, `GCP_AUTHCALATOR_TLS_BUNDLE`, `GCP_AUTHCALATOR_TLS_BUNDLE_B64`
- Add per-scenario setup guides:

##### SSH Remote Devcontainer
```bash
# 1. On laptop — start gate with TCP:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --tcp-port 8174

# 2. On laptop — get the client bundle:
gcp-authcalator init-tls --bundle-b64
# Copy the output

# 3. SSH with port forwarding:
ssh -R 8174:localhost:8174 remote-host

# 4. On remote host — set the env var (e.g., in .bashrc or devcontainer.json):
export GCP_AUTHCALATOR_TLS_BUNDLE_B64="<paste>"
export GCP_AUTHCALATOR_GATE_URL="https://localhost:8174"

# 5. In devcontainer — metadata-proxy auto-detects env vars:
gcp-authcalator metadata-proxy --project-id my-project
```

##### GitHub Codespaces
```bash
# 1. On laptop — start gate with TCP:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --tcp-port 8174

# 2. Set Codespace secrets (one-time, via GitHub UI or CLI):
gcp-authcalator init-tls --bundle-b64 | gh secret set GCP_AUTHCALATOR_TLS_BUNDLE_B64
gh secret set GCP_AUTHCALATOR_GATE_URL --body "https://localhost:8174"

# 3. Forward port to Codespace:
gh cs ports forward 8174:8174

# 4. In Codespace — metadata-proxy auto-detects env vars:
gcp-authcalator metadata-proxy --project-id my-project
```

##### Coder
```bash
# 1. On laptop — start gate with TCP:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --tcp-port 8174

# 2. Set workspace env vars (via Coder UI or template):
#    GCP_AUTHCALATOR_TLS_BUNDLE_B64=<from init-tls --bundle-b64>
#    GCP_AUTHCALATOR_GATE_URL=https://localhost:8174

# 3. Forward port to workspace:
coder port-forward my-workspace --tcp 8174:8174

# 4. In workspace — metadata-proxy auto-detects env vars:
gcp-authcalator metadata-proxy --project-id my-project
```

#### 6.2 Update `CHANGELOG.md`

Under `[Unreleased]`:
```markdown
### Added
- TCP + mutual TLS transport for remote devcontainer support (SSH, Codespaces, Coder)
- `init-tls` command for TLS certificate management
- `--tcp-port` flag for gate to enable TCP listener alongside Unix socket
- `--gate-url` and `--tls-bundle` flags for metadata-proxy and with-prod
- `GCP_AUTHCALATOR_GATE_URL` and `GCP_AUTHCALATOR_TLS_BUNDLE_B64` env vars for zero-config remote setup
- Auto-generation and rotation of TLS certificates (Ed25519, 90-day lifetime)
```

### Phase 7: Tests

#### 7.1 TLS module tests

- `src/tls/__tests__/ca.test.ts`:
  - Generates valid CA cert with correct subject, validity, Ed25519 key
  - CA cert is self-signed
- `src/tls/__tests__/certs.test.ts`:
  - Server cert has correct SAN (localhost, 127.0.0.1) and serverAuth EKU
  - Client cert has clientAuth EKU
  - Both signed by CA (verification passes)
  - Both use Ed25519
  - Validity is 90 days
- `src/tls/__tests__/store.test.ts`:
  - `ensureTlsFiles` creates all files with correct permissions
  - `ensureTlsFiles` regenerates expired certs
  - `ensureTlsFiles` is idempotent (doesn't regenerate valid certs)
  - `loadClientBundle` parses the combined PEM correctly
  - `loadClientBundleFromBase64` round-trips correctly
- `src/tls/__tests__/bundle.test.ts`:
  - `resolveClientBundle` prefers env var over file path
  - `resolveClientBundle` returns null when nothing is configured

#### 7.2 Integration tests

- Gate TCP listener accepts mTLS connections with valid client cert
- Gate TCP listener rejects connections without client cert
- Gate TCP listener rejects connections with wrong CA
- `createGateClient` works in both `unix` and `tcp` modes
- `fetchProdToken` works in both `unix` and `tcp` modes
- End-to-end: gate (TCP) → metadata-proxy (with bundle from env var) → token request succeeds

## Security Analysis

### What changes

| Aspect | Local (Unix socket) | Remote (TCP + mTLS) |
|--------|-------------------|-------------------|
| Transport auth | OS file permissions (0600) | mTLS (client cert required) |
| Encryption | N/A (local IPC) | TLS 1.3 |
| Network exposure | None | localhost only (forwarded via SSH/etc) |
| Credential location | Host only | Host only (certs ≠ credentials) |
| Confirmation dialog | Host desktop (zenity/osascript) | Host desktop (unchanged) |
| PID validation (with-prod) | /proc introspection | /proc introspection (container-local, unchanged) |

### What doesn't change

- Gate always runs on the developer's machine
- ADC credentials never leave the developer's machine
- Confirmation dialog runs on the developer's desktop
- with-prod PID validation works within the container
- The metadata-proxy serves plain HTTP (GCE metadata protocol) — no change for google-auth libraries
- All existing local devcontainer functionality is untouched

### Threat model additions

- **Stolen client bundle**: An attacker with the client cert can authenticate to gate over a forwarded port. Mitigation: client bundle has 90-day expiry; bundle files are `0600`; gate only listens on localhost (requires port forwarding access); prod tokens still require confirmation dialog.
- **Port forwarding hijack**: If an attacker can access the forwarded port on the remote, they can send requests to gate. Mitigation: mTLS requires the client certificate (port access alone is insufficient).
- **Certificate expiry**: Certs auto-regenerate when gate starts and detects expiry. Gate logs a warning so the user knows to update remote bundles.
- **Bundle in env var**: Environment variables are visible to same-user processes on the remote. Mitigation: the bundle only authorizes gate communication (not GCP access directly); prod tokens still require confirmation; bundle rotates every 90 days.

## File Change Summary

| File | Change |
|------|--------|
| `src/tls/ca.ts` | **New** — Ed25519 CA generation using node-forge |
| `src/tls/certs.ts` | **New** — server and client cert generation |
| `src/tls/store.ts` | **New** — cert storage, loading, expiry checking |
| `src/tls/bundle.ts` | **New** — client bundle resolution (env var / file / none) |
| `src/tls/__tests__/*.test.ts` | **New** — unit tests for TLS module |
| `src/gate/connection.ts` | **New** — `GateConnection` type and `buildGateConnection` helper |
| `src/commands/init-tls.ts` | **New** — init-tls CLI command |
| `src/config.ts` | **Modify** — add tcp_port, tls_dir, gate_url, tls_bundle fields |
| `src/cli.ts` | **Modify** — add init-tls subcommand, new CLI args |
| `src/gate/server.ts` | **Modify** — add optional TCP+mTLS listener |
| `src/commands/gate.ts` | **Modify** — wire new config |
| `src/metadata-proxy/gate-client.ts` | **Modify** — accept GateConnection, support TCP+mTLS |
| `src/metadata-proxy/server.ts` | **Modify** — accept GateConnection |
| `src/commands/metadata-proxy.ts` | **Modify** — build GateConnection, wire config |
| `src/with-prod/fetch-prod-token.ts` | **Modify** — accept GateConnection |
| `src/commands/with-prod.ts` | **Modify** — build GateConnection, wire config |
| `SPEC.md` | **Modify** — remote development section + setup guides |
| `CHANGELOG.md` | **Modify** — document new features |
