# Plan: Implement `gcp-metadata-proxy` — Container-Side Metadata Emulator

## Context

Step 3 from GOAL.md. The `gcp-metadata-proxy` is a container-side HTTP server that emulates the GCE metadata server protocol. It sits between Google Cloud client libraries (which query `GCE_METADATA_HOST`) and the host-side `gcp-gate` daemon (which mints tokens). This lets all libraries transparently get credentials without any application code changes — the same mechanism GKE workloads already use.

Currently `src/commands/metadata-proxy.ts` is a stub printing `[STUB] Not yet implemented.`.

## File Structure

```
src/
  metadata-proxy/
    types.ts              # NEW: MetadataProxyDeps, TokenProvider, CachedToken
    gate-client.ts        # NEW: Unix socket client for gcp-gate (fetch + cache tokens)
    handlers.ts           # NEW: Pure request handlers (GCE metadata protocol)
    server.ts             # NEW: Bun.serve() on TCP, wires modules, shutdown
  commands/
    metadata-proxy.ts     # MODIFY: replace stub → call startMetadataProxyServer()
  cli.ts                  # MODIFY: await runMetadataProxy() (make async)
  __tests__/
    metadata-proxy/
      gate-client.test.ts # NEW
      handlers.test.ts    # NEW
      server.test.ts      # NEW
    commands/
      metadata-proxy.test.ts  # MODIFY: rewrite for real behavior
    cli.test.ts               # MODIFY: update metadata-proxy subprocess test
```

## Endpoints

| Path                                                              | Response                                                              | Header required? |
| ----------------------------------------------------------------- | --------------------------------------------------------------------- | ---------------- |
| `GET /`                                                           | `200` with `Metadata-Flavor: Google` response header (detection ping) | No               |
| `GET /computeMetadata/v1/instance/service-accounts/default/token` | `{"access_token":"...","expires_in":3600,"token_type":"Bearer"}`      | Yes              |
| `GET /computeMetadata/v1/project/project-id`                      | Plain text project ID                                                 | Yes              |
| `GET /computeMetadata/v1/instance/service-accounts/default/email` | Plain text SA email (404 if not configured)                           | Yes              |
| Non-GET                                                           | 405                                                                   | —                |
| Unknown path                                                      | 404                                                                   | —                |

All `/computeMetadata/*` endpoints require `Metadata-Flavor: Google` request header → 403 if missing.

## Module Design

### `types.ts` — Shared interfaces

```typescript
export interface CachedToken {
  access_token: string;
  expires_at: Date;
}

export interface TokenProvider {
  getToken: () => Promise<CachedToken>;
}

export interface MetadataProxyDeps {
  getToken: () => Promise<CachedToken>;
  projectId: string;
  serviceAccountEmail: string | undefined; // from config.service_account
  startTime: Date;
}
```

`TokenProvider` is the key extensibility point — in step 4, `with-prod` can swap in a static token provider without changing handlers.

### `gate-client.ts` — Token fetching + caching

Factory: `createGateClient(socketPath, options?) → TokenProvider`

- Fetches `GET /token` from gcp-gate via Unix socket (Bun's `fetch` with `{ unix: socketPath }`)
- Caches token; re-fetches when < 5 min remaining (`CACHE_MARGIN_MS = 5 * 60 * 1000` — same as `gate/auth.ts`)
- Accepts optional `fetchFn` for test injection (pattern from `gate/auth.ts`)
- Throws descriptive errors when gate is unreachable or returns invalid responses

### `handlers.ts` — Pure request handler

Function: `handleRequest(req, deps) → Response`

- Validates `Metadata-Flavor: Google` on `/computeMetadata/*` paths (403 if missing)
- Root `/` always returns 200 (no header check — used for detection)
- Token endpoint: calls `deps.getToken()`, computes `expires_in`, returns JSON
- Project-id: returns `deps.projectId` as plain text
- Email: returns `deps.serviceAccountEmail` as plain text, or 404 if undefined
- All responses include `Metadata-Flavor: Google` response header
- Non-GET → 405, unknown path → 404
- No audit logging (gate daemon handles that)

### `server.ts` — Server lifecycle

Function: `startMetadataProxyServer(config, options?) → { server, stop }`

- Creates gate client, builds `MetadataProxyDeps`
- `Bun.serve({ hostname: "127.0.0.1", port: config.port, fetch: ... })`
- SIGTERM/SIGINT handlers for graceful shutdown
- Logs startup info
- Accepts `gateClientOptions` for test injection

### `commands/metadata-proxy.ts` — Entry point

```typescript
export async function runMetadataProxy(config: Config): Promise<void> {
  const proxyConfig = MetadataProxyConfigSchema.parse(config);
  startMetadataProxyServer(proxyConfig);
}
```

### `cli.ts` — Make metadata-proxy async

Change line 103 from `runMetadataProxy(config)` to `await runMetadataProxy(config)`.

## Config

No schema changes needed. Existing `MetadataProxyConfigSchema` already has everything:

- `project_id` (required)
- `service_account` (optional — serves email endpoint if provided)
- `socket_path` (default `/run/gcp-gate.sock`)
- `port` (default 8173)

## Test Strategy

| File                     | Approach                          | Key coverage                                              |
| ------------------------ | --------------------------------- | --------------------------------------------------------- |
| `gate-client.test.ts`    | Mock `fetchFn`                    | Token fetch, caching, re-fetch on stale, error handling   |
| `handlers.test.ts`       | Mock `MetadataProxyDeps`          | All endpoints, header validation (403), email 404, errors |
| `server.test.ts`         | Real TCP server + mock gate fetch | Full request cycle, startup/shutdown                      |
| `metadata-proxy.test.ts` | Config validation                 | ZodError on missing project_id                            |
| `cli.test.ts`            | Subprocess (kill after startup)   | Startup output, config error handling                     |

## Implementation Order

1. `src/metadata-proxy/types.ts` — interfaces only
2. `src/metadata-proxy/gate-client.ts` + tests — token fetch + cache
3. `src/metadata-proxy/handlers.ts` + tests — pure request handlers
4. `src/metadata-proxy/server.ts` + tests — integration
5. Update `src/commands/metadata-proxy.ts` — replace stub
6. Update `src/cli.ts` — make metadata-proxy case async
7. Update `src/__tests__/commands/metadata-proxy.test.ts` — new behavior
8. Update `src/__tests__/cli.test.ts` — metadata-proxy test to subprocess pattern (like the gate test at lines 86-128)
9. Verify: `bun run format && bun run lint && bunx tsc --noEmit && bun test`

## Key patterns to reuse

- **Dependency injection**: `gate/types.ts:GateDeps` pattern → `MetadataProxyDeps`
- **Token caching**: `gate/auth.ts` `CACHE_MARGIN_MS` + `isCacheValid` pattern
- **Handler structure**: `gate/handlers.ts` `handleRequest()` + `jsonResponse()` pattern
- **Server lifecycle**: `gate/server.ts` `Bun.serve()` + signal handling pattern
- **Test mocking**: `gate/server.test.ts` `mockClient` / `mockFetch` pattern
- **CLI subprocess tests**: `cli.test.ts` lines 86-128 (spawn, wait, kill, check output)

## Verification

1. `bunx tsc --noEmit` — no type errors
2. `bun test` — all tests pass
3. `bun run lint` — no lint errors
4. `bun run format` — formatting clean
5. Manual: `bun run index.ts metadata-proxy --project-id test-proj --port 9090` starts server, then `curl -H "Metadata-Flavor: Google" http://127.0.0.1:9090/computeMetadata/v1/project/project-id` returns `test-proj`
