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

## Design

### Transport: TCP + Mutual TLS

Add a TCP listener mode to gate, secured with **self-signed mutual TLS (mTLS)**:

1. Gate generates a private CA (on first run or via `gcp-authcalator init-tls`)
2. Gate generates a server certificate signed by the CA
3. Gate generates a client certificate signed by the CA (for metadata-proxy / with-prod)
4. Gate listens on `127.0.0.1:<tcp-port>` with TLS, requiring a valid client certificate
5. Metadata-proxy / with-prod connect using the client certificate, verifying the server against the CA

The CA + client cert + client key form a **"connection bundle"** that must be distributed to the remote environment. These are **not** GCP credentials — they only authorize communication with gate.

### Why mTLS (not bearer tokens)?

- **Mutual authentication**: both sides verify identity (gate verifies client, client verifies gate)
- **No shared secret in transit**: TLS handshake, not a header token that could be logged
- **Certificate pinning**: the self-signed CA means no trust-store dependency
- **Replay resistance**: TLS session keys are ephemeral
- **Aligns with industry direction**: public CAs are removing clientAuth EKU by mid-2026; private CAs (exactly what we're doing) are the recommended path for mTLS

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

### Connection Flow (Local — unchanged)

Unix socket mode remains the default for local devcontainers. No changes to the existing local flow.

## Implementation Plan

### Phase 1: TLS Certificate Management

**New module: `src/tls/`**

#### 1.1 `src/tls/ca.ts` — Certificate Authority generation

- `generateCA()`: Generate a self-signed CA keypair (RSA 2048 or Ed25519)
  - Returns: `{ caCert: string, caKey: string }` (PEM format)
  - Subject: `CN=gcp-authcalator CA`
  - Validity: 1 year (auto-regeneration on expiry)
  - Use Bun's native crypto or `@peculiar/x509` library

#### 1.2 `src/tls/certs.ts` — Certificate generation

- `generateServerCert(ca)`: Generate server cert signed by CA
  - SAN: `localhost`, `127.0.0.1`
  - EKU: serverAuth
  - Validity: 90 days
- `generateClientCert(ca)`: Generate client cert signed by CA
  - EKU: clientAuth
  - Validity: 90 days
  - Subject: `CN=gcp-authcalator client`

#### 1.3 `src/tls/store.ts` — Certificate storage

- Default location: `$XDG_RUNTIME_DIR/gcp-authcalator/tls/` or `~/.gcp-authcalator/tls/`
- Files (all `0600`):
  - `ca.pem` — CA certificate
  - `ca-key.pem` — CA private key
  - `server.pem` — server certificate
  - `server-key.pem` — server private key
  - `client.pem` — client certificate
  - `client-key.pem` — client private key
  - `client-bundle.pem` — combined CA cert + client cert + client key (single file for easy distribution)
- `ensureTlsFiles()`: Generate all certs if missing or expired, return paths
- `loadTlsFiles()`: Load and return PEM contents
- Directory created with `0700` permissions

#### 1.4 `src/commands/init-tls.ts` — CLI command

- `gcp-authcalator init-tls`: Force-regenerate all TLS certificates
- Prints the path to the client bundle for easy copying
- `gcp-authcalator init-tls --show-bundle`: Print the client bundle to stdout (for piping over SSH)

### Phase 2: Gate TCP Listener

#### 2.1 Modify `src/gate/server.ts`

- Add optional TCP listener alongside the existing Unix socket:
  ```typescript
  // Existing Unix socket server (unchanged)
  const unixServer = Bun.serve({
    unix: config.socket_path,
    fetch(req) { return handleRequest(req, deps); },
  });

  // New optional TCP+mTLS server
  if (config.tcp_port) {
    const tlsFiles = await loadTlsFiles();
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
- Both listeners share the same `handleRequest` and `GateDeps` — the handler logic is transport-agnostic
- TCP server only starts if `tcp_port` is configured
- Auto-generate TLS certificates on first TCP listen (call `ensureTlsFiles()`)

#### 2.2 Modify `src/config.ts`

- Add to `ConfigSchema`:
  ```typescript
  tcp_port: z.coerce.number().int().min(1).max(65535).optional(),
  tls_dir: z.string().min(1).optional().transform(v => v ? expandTilde(v) : v),
  gate_url: z.string().url().optional(),    // for metadata-proxy / with-prod
  tls_bundle: z.string().min(1).optional(), // path to client bundle
  ```
- Add CLI arg mappings:
  - `--tcp-port` → `tcp_port`
  - `--tls-dir` → `tls_dir`
  - `--gate-url` → `gate_url`
  - `--tls-bundle` → `tls_bundle`
- Add env var support (checked in `loadConfig`):
  - `GCP_AUTHCALATOR_GATE_URL` → `gate_url`
  - `GCP_AUTHCALATOR_TLS_BUNDLE` → `tls_bundle`

#### 2.3 Modify `src/commands/gate.ts`

- Wire `tcp_port` and `tls_dir` from config into `startGateServer`
- Print TCP listener info at startup (port, TLS status)
- Print the client bundle path for easy reference

### Phase 3: Gate Client TCP Support

#### 3.1 Modify `src/metadata-proxy/gate-client.ts`

- `checkGateSocket()` → rename/refactor to `checkGateConnection()`:
  - If `gate_url` is configured: do an HTTPS health check with client cert
  - If `socket_path` is configured (default): existing Unix socket check
- `createGateClient()`:
  - Accept `gate_url` + `tls_bundle` as alternatives to `socket_path`
  - When using TCP: `fetch(gateUrl + "/token", { tls: { cert, key, ca } })`
  - When using Unix socket: existing `fetch("http://localhost/token", { unix: socketPath })`
  - The returned `GateClient` interface is unchanged — callers don't know about the transport

#### 3.2 Modify `src/metadata-proxy/server.ts`

- Pass `gate_url` and `tls_bundle` through to `createGateClient` when configured
- The metadata-proxy server itself (127.0.0.1:8173) stays plain HTTP — google-auth libraries connect to it, and they expect the GCE metadata protocol

#### 3.3 Modify `src/commands/metadata-proxy.ts`

- Wire new config options through to server startup
- Add startup log line showing whether gate connection is via Unix socket or TCP+mTLS

### Phase 4: with-prod TCP Support

#### 4.1 Modify `src/with-prod/fetch-prod-token.ts`

- `fetchProdToken()` currently accepts `socketPath` — add `gateUrl` + `tlsBundle` as alternatives
- When using TCP: fetch with mTLS client cert
- The function signature changes:
  ```typescript
  // Before:
  fetchProdToken(socketPath: string, options?)
  // After:
  fetchProdToken(gateConnection: GateConnection, options?)
  // where GateConnection = { socketPath: string } | { gateUrl: string, tlsBundle: string }
  ```

#### 4.2 Modify `src/commands/with-prod.ts`

- Build `GateConnection` from config (gate_url + tls_bundle or socket_path)
- Pass to `fetchProdToken`
- PID validation on the temp metadata proxy continues to work (it's container-local)

### Phase 5: CLI and Config Updates

#### 5.1 Update `src/cli.ts`

- Add `init-tls` subcommand
- Add new CLI options to `parseArgs`:
  - `--tcp-port`
  - `--tls-dir`
  - `--gate-url`
  - `--tls-bundle`
- Update USAGE text

#### 5.2 TOML config support

Example `config.toml` for gate (on laptop):
```toml
project_id = "my-project"
service_account = "dev@my-project.iam.gserviceaccount.com"
tcp_port = 8174
```

Example `config.toml` for metadata-proxy (in remote container):
```toml
project_id = "my-project"
gate_url = "https://localhost:8174"
tls_bundle = "/run/secrets/gcp-authcalator/client-bundle.pem"
```

### Phase 6: Documentation

#### 6.1 Update `SPEC.md`

- Add "Remote Development" section after the existing Architecture section
- Document the mTLS transport layer
- Document all three remote scenarios with setup instructions:
  - SSH devcontainer
  - GitHub Codespaces
  - Coder
- Update Architecture diagram to show both Unix socket and TCP+mTLS paths
- Document the `init-tls` command
- Document new config options and env vars

#### 6.2 Update `CHANGELOG.md`

- Add entries under `[Unreleased]` for all new features

### Phase 7: Per-Scenario Setup Guides (in SPEC.md)

#### 7.1 SSH Remote Devcontainer

```bash
# On developer's laptop:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --tcp-port 8174

# Copy client bundle to remote host:
scp $(gcp-authcalator init-tls --show-path)/client-bundle.pem remote:~/.gcp-authcalator/tls/

# SSH with port forwarding:
ssh -R 8174:localhost:8174 remote-host

# In devcontainer on remote host (devcontainer.json feature or postStartCommand):
gcp-authcalator metadata-proxy --project-id my-project \
  --gate-url https://localhost:8174 \
  --tls-bundle ~/.gcp-authcalator/tls/client-bundle.pem
```

#### 7.2 GitHub Codespaces

```bash
# On developer's laptop:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --tcp-port 8174

# Forward port to codespace:
gh cs ports forward 8174:8174

# In Codespace (devcontainer.json postStartCommand):
# Client bundle stored as Codespace secret (base64-encoded)
echo "$GCP_AUTHCALATOR_TLS_BUNDLE_B64" | base64 -d > /tmp/client-bundle.pem
gcp-authcalator metadata-proxy --project-id my-project \
  --gate-url https://localhost:8174 \
  --tls-bundle /tmp/client-bundle.pem
```

#### 7.3 Coder

```bash
# On developer's laptop:
gcp-authcalator gate --project-id my-project \
  --service-account dev@my-project.iam.gserviceaccount.com \
  --tcp-port 8174

# Forward port to Coder workspace:
coder port-forward my-workspace --tcp 8174:8174

# In Coder workspace:
gcp-authcalator metadata-proxy --project-id my-project \
  --gate-url https://localhost:8174 \
  --tls-bundle /path/to/client-bundle.pem
```

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
- **Certificate expiry**: Certs auto-regenerate when gate starts and detects expiry. Client bundles need redistribution after regeneration.

## File Change Summary

| File | Change |
|------|--------|
| `src/tls/ca.ts` | **New** — CA generation |
| `src/tls/certs.ts` | **New** — cert generation |
| `src/tls/store.ts` | **New** — cert storage and loading |
| `src/commands/init-tls.ts` | **New** — init-tls CLI command |
| `src/config.ts` | **Modify** — add tcp_port, tls_dir, gate_url, tls_bundle |
| `src/cli.ts` | **Modify** — add init-tls subcommand, new CLI args |
| `src/gate/server.ts` | **Modify** — add optional TCP+mTLS listener |
| `src/commands/gate.ts` | **Modify** — wire new config |
| `src/metadata-proxy/gate-client.ts` | **Modify** — support TCP+mTLS connections |
| `src/metadata-proxy/server.ts` | **Modify** — pass gate_url/tls_bundle config |
| `src/commands/metadata-proxy.ts` | **Modify** — wire new config |
| `src/with-prod/fetch-prod-token.ts` | **Modify** — support TCP+mTLS connections |
| `src/commands/with-prod.ts` | **Modify** — build GateConnection from config |
| `SPEC.md` | **Modify** — remote development section |
| `CHANGELOG.md` | **Modify** — document new features |

## Open Questions

1. **Certificate algorithm**: RSA 2048 vs Ed25519? Ed25519 is faster and smaller but has less library support. RSA 2048 is universally supported. Leaning RSA 2048 for compatibility.
2. **Certificate lifetime**: 90 days for server/client certs, 1 year for CA — reasonable?
3. **Auto-regeneration**: Should gate auto-regenerate expired certs on startup, or require explicit `init-tls`? Leaning auto-regenerate with a warning.
4. **Bun crypto library**: Bun has native crypto but may need `@peculiar/x509` or `node-forge` for X.509 cert generation. Need to evaluate which has best Bun compatibility.
