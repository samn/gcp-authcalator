# Plan: Implement `gcp-gate` -- Host-Side Token Daemon

## Context

The `gcp-gate` component is the host-side HTTP daemon that mints GCP tokens and serves them over a Unix domain socket. It's the security boundary of the system -- credentials never enter Docker, only short-lived tokens flow through the socket. Currently `src/commands/gate.ts` is a stub logging "[STUB] Not yet implemented."

## Dependency

```sh
bun add google-auth-library
```

Single new dependency. The `Impersonated` class from `google-auth-library` internally calls `iamcredentials.googleapis.com/v1/.../generateAccessToken`, so we don't need the heavier `@google-cloud/iam-credentials` package.

## File Structure

```
src/
  gate/
    types.ts          # Shared interfaces (TokenResponse, GateDeps, AuditEntry, etc.)
    auth.ts           # GCP auth: ADC client, Impersonated client, token cache
    confirm.ts        # Prod token confirmation (zenity dialog / terminal prompt)
    audit.ts          # JSON-lines audit logger (~/.gcp-gate/audit.log)
    handlers.ts       # Pure request handlers (token, identity, health)
    server.ts         # Bun.serve() setup, wires modules, shutdown
  commands/
    gate.ts           # MODIFY: replace stub → call startGateServer()
  cli.ts              # MODIFY: make main() async, await runGate()
  __tests__/
    gate/
      handlers.test.ts
      auth.test.ts
      confirm.test.ts
      audit.test.ts
      server.test.ts
    commands/
      gate.test.ts    # MODIFY: rewrite for new behavior
```

## Module Design

### `types.ts` -- Shared Interfaces

Key type: `GateDeps` -- dependency injection interface that makes handlers fully testable without real GCP calls.

```typescript
export interface GateDeps {
  mintDevToken: () => Promise<CachedToken>;
  mintProdToken: () => Promise<CachedToken>;
  getIdentityEmail: () => Promise<string>;
  confirmProdAccess: (email: string) => Promise<boolean>;
  writeAuditLog: (entry: AuditEntry) => void;
  startTime: Date;
}
```

Also defines: `TokenResponse`, `IdentityResponse`, `HealthResponse`, `ErrorResponse`, `AuditEntry`, `CachedToken`.

### `auth.ts` -- GCP Authentication

Factory function `createAuthModule(config)` returns `{ mintDevToken, mintProdToken, getIdentityEmail }`.

- Initializes `GoogleAuth` with ADC (engineer's host credentials)
- Creates an `Impersonated` client targeting the configured service account
- **`mintDevToken()`**: Calls `impersonatedClient.getAccessToken()`. Caches result; re-mints when <5 min remain.
- **`mintProdToken()`**: Calls `sourceClient.getAccessToken()` (engineer's own ADC token). No caching.
- **`getIdentityEmail()`**: Gets ADC access token, calls `https://oauth2.googleapis.com/tokeninfo?access_token=...`, extracts `email`. Cached for daemon lifetime.

For testability, accepts optional pre-built clients via an options parameter.

### `confirm.ts` -- Prod Confirmation Flow

Factory function `createConfirmModule()` returns `{ confirmProdAccess }`.

1. **Primary**: `zenity --question --title="gcp-gate: Prod Access" --text="Grant prod-level GCP access to <email>?" --timeout=60`
   - Exit 0 = approved, exit 1 = denied, exit 5 = timeout (denied)
2. **Fallback** (zenity not found): Terminal prompt reading from stdin
   - If stdin is not a TTY, deny by default

Accepts optional `spawn` function for testing.

### `audit.ts` -- Audit Logger

Factory function `createAuditModule(logDir?)` returns `{ writeAuditLog }`.

- Defaults to `~/.gcp-gate/audit.log`
- Creates directory if needed
- Writes JSON lines (one JSON object per line, synchronous append)
- Failures logged to stderr but don't break token serving

### `handlers.ts` -- Request Handlers

Pure function `handleRequest(req, deps)` → `Response`. Routes:

| Route                   | Handler                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `GET /token`            | Mint dev token via `deps.mintDevToken()`, return `{ access_token, expires_in, token_type }` |
| `GET /token?level=prod` | Get email → confirm → mint prod token or 403                                                |
| `GET /identity`         | Return `{ email }`                                                                          |
| `GET /health`           | Return `{ status: "ok", uptime_seconds }`                                                   |
| Non-GET                 | 405                                                                                         |
| Unknown path            | 404                                                                                         |

All responses are JSON with `Content-Type: application/json`. Audit entries written for all token requests (granted, denied, error).

### `server.ts` -- Server Lifecycle

`startGateServer(config)` → `{ server, stop }`:

1. Create auth/confirm/audit modules, build `GateDeps`
2. Remove stale socket file (crash recovery)
3. `Bun.serve({ unix: config.socket_path, fetch(req) { return handleRequest(req, deps) } })`
4. Register SIGTERM/SIGINT handlers for graceful shutdown (stop server, unlink socket)
5. Log startup info

### `commands/gate.ts` -- Updated Entry Point

```typescript
export async function runGate(config: Config): Promise<void> {
  const gateConfig = GateConfigSchema.parse(config);
  await startGateServer(gateConfig);
}
```

### `cli.ts` -- Async Update

Make `main()` async, `await runGate(config)` in the switch block. The server keeps the process alive until shutdown signal.

## Test Strategy

| File               | Approach                                    | Key coverage                                               |
| ------------------ | ------------------------------------------- | ---------------------------------------------------------- |
| `handlers.test.ts` | Mock `GateDeps`, test pure request→response | All endpoints, error cases, audit log writes               |
| `auth.test.ts`     | Inject mock GCP clients                     | Token minting, caching (5-min margin), email lookup        |
| `confirm.test.ts`  | Inject mock spawner                         | zenity approve/deny/timeout, fallback to terminal          |
| `audit.test.ts`    | Use temp directory                          | File creation, JSON lines format, append behavior          |
| `server.test.ts`   | Start real server on temp socket            | Full request cycle, startup/shutdown, stale socket cleanup |
| `gate.test.ts`     | Mock `startGateServer`                      | Config validation, delegation to server                    |

## Implementation Order

1. `bun add google-auth-library`
2. `src/gate/types.ts` (interfaces only)
3. `src/gate/audit.ts` + tests (simplest module, no GCP deps)
4. `src/gate/confirm.ts` + tests (subprocess management, no GCP deps)
5. `src/gate/auth.ts` + tests (GCP integration with mock clients)
6. `src/gate/handlers.ts` + tests (largest test file, pure functions)
7. `src/gate/server.ts` + tests (integration)
8. Update `src/commands/gate.ts`, `src/cli.ts`
9. Update existing tests
10. Verify: `bun test`, `bun run lint`, `bunx tsc --noEmit`

## Risk Mitigation

**`google-auth-library` + Bun compatibility**: If `Impersonated` class has issues, fallback to direct `fetch()` call to the `generateAccessToken` REST endpoint with a bearer token from ADC.

**Unix socket permissions**: Socket file may need `chmod` after creation for container access. Document this as a deployment note.

## Verification

1. `bunx tsc --noEmit` -- no type errors
2. `bun test` -- all tests pass
3. `bun run lint` -- no lint errors
4. Manual test: `bun run index.ts gate --project-id test --service-account sa@test.iam.gserviceaccount.com --socket-path /tmp/test-gate.sock` starts a server, then `curl --unix-socket /tmp/test-gate.sock http://localhost/health` returns 200
