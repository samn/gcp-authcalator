# Plan: Admin Socket Isolation for Approval Flow

## Problem

The gate daemon serves approve/deny endpoints on the same Unix socket (or TCP+mTLS listener) that is mounted into the devcontainer for the metadata proxy. A malicious process in the container can:

1. `GET /pending` to enumerate pending approval requests
2. `POST /pending/<id>/approve` to self-approve its own prod token request

The approve/deny endpoints have no endpoint-level authentication — security relies entirely on transport-level access (socket permissions / mTLS). Since the main socket _must_ be reachable from the container, any endpoint on it is reachable by a malicious process.

## Design

### 1. Separate admin socket

The gate starts a **second Unix socket** exclusively for admin operations (approve/deny). This socket is NOT mounted into the devcontainer.

**Default path:** `/tmp/gcp-authcalator-admin-<uid>/admin.sock`

- `/tmp` is chosen because host `/tmp` is almost never mounted into containers (containers get their own tmpfs `/tmp`)
- `<uid>` suffix prevents multi-user collisions
- Directory created with `0700`, socket with `0600` (same hardening as main socket)
- Same stale-socket cleanup logic as the main socket (symlink check, ownership check, liveness probe)

**Config:**

- New config field: `admin_socket_path` (optional, with the `/tmp`-based default)
- New CLI flag: `--admin-socket-path`
- Env var: `GCP_AUTHCALATOR_ADMIN_SOCKET_PATH`

### 2. Remove approve/deny from the main socket

The `/pending` routes are removed from the main socket's request handler entirely. A request to `/pending/*` on the main socket returns 404.

The admin socket serves **only**:

- `POST /pending/<id>/approve`
- `POST /pending/<id>/deny`
- `GET /health` (for liveness probes / approve CLI connection check)

No `GET /pending` listing endpoint on either socket. Since single-flight ensures at most one pending request, and `with-prod` prints the ID to the user, there is no need for enumeration. Removing it eliminates the discovery vector entirely.

### 3. Client-generated pending IDs

`with-prod` generates the pending ID locally before sending the session request. This lets it print the approval command immediately without a two-phase protocol.

**Flow:**

1. `with-prod` generates `randomBytes(16).toString("hex")` (32 hex chars, 128 bits)
2. `with-prod` prints: `with-prod: if no GUI/TTY prompt appears, approve with: gcp-authcalator approve <id>`
3. `with-prod` sends `POST /session` with `X-Pending-Id: <id>` header
4. Gate's `confirmProdAccess` receives the pending ID and passes it to `pendingQueue.enqueue()`
5. If the gate uses GUI/TTY confirmation instead, the pending ID is never used (no harm)
6. If the gate falls through to the pending queue, it parks the request under the client-provided ID
7. User runs `gcp-authcalator approve <id>` on the host (hits admin socket)
8. Gate resolves the pending request, the original HTTP response completes
9. `with-prod` proceeds normally

**Gate validation of client-provided IDs:**

- Must be exactly 32 lowercase hex characters (`/^[a-f0-9]{32}$/`)
- Must not collide with an already-pending request (reject with 409 Conflict)
- If the header is missing, the gate generates its own ID as before (backwards compat for direct `curl` usage, but the ID is only discoverable on the gate's stderr)

**Security analysis of client-generated IDs:**

- The ID is a correlation token, not a security credential. The security boundary is the admin socket.
- A malicious process knowing the ID cannot self-approve because it cannot reach the admin socket.
- Collision risk with 128 bits of randomness is negligible. Single-flight further prevents concurrent pending requests.
- Replay risk: once resolved, the ID is deleted from the map. Submitting a stale ID gets a 404. The gate also rejects duplicate IDs for in-flight requests.

### 4. One-shot token requests (`GET /token?level=prod`)

The same `X-Pending-Id` header works for one-shot prod token requests too (not just sessions). The `fetchProdToken` path can also supply a pending ID for the same self-approval protection.

The `acquireProdAccess` shared flow passes the pending ID from the request header through to `confirmProdAccess`, which passes it to `pendingQueue.enqueue()`.

## Files Modified

### `src/gate/pending.ts`

- `enqueue()` accepts an optional `id` parameter: `enqueue(email, command?, pamPolicy?, id?)`
- If `id` is provided, validate format (`/^[a-f0-9]{32}$/`) and uniqueness (throw if duplicate)
- If `id` is omitted, generate one with `randomBytes(16).toString("hex")` (increased from 4 to 16 bytes for consistency)
- Update stderr log to print the (possibly client-provided) ID

### `src/gate/confirm.ts`

- `confirmProdAccess` signature gains an optional `pendingId?: string` parameter
- Pass `pendingId` through to `pendingQueue.enqueue()`

### `src/gate/types.ts`

- `GateDeps.confirmProdAccess` signature updated to include `pendingId?: string`

### `src/gate/handlers.ts`

- `acquireProdAccess()`: extract `X-Pending-Id` header from the request, pass to `confirmProdAccess`
- Remove the `/pending` route block from `handleRequest()` (no pending endpoints on main socket)
- Extract `handleResolvePending` into a shared function used by the admin socket handler

### `src/gate/server.ts`

Major changes:

- Compute `admin_socket_path` from config (default: `/tmp/gcp-authcalator-admin-<uid>/admin.sock`)
- Create the admin socket directory with `0700`, same stale-socket cleanup as main socket
- Start a second `Bun.serve` on the admin socket with a dedicated request handler that only routes:
  - `POST /pending/<id>/approve`
  - `POST /pending/<id>/deny`
  - `GET /health`
- Print admin socket path in startup log
- Clean up admin socket in `stop()` and signal handlers
- `GateServerResult` gains `adminServer` field

### `src/config.ts`

- Add `admin_socket_path` to `ConfigSchema` (optional string, defaults to `/tmp/gcp-authcalator-admin-${process.getuid?.() ?? 0}/admin.sock`)
- Add to `GateConfigSchema` (inherited)
- Add `"admin-socket-path": "admin_socket_path"` to `cliToConfigKey`
- Add `admin_socket_path` to `configKeys` for env var loading

### `src/cli.ts`

- Add `--admin-socket-path` to `parseArgs` string options
- Pass through to config

### `src/commands/approve.ts`

- `runApprove()` connects to the **admin socket** path instead of the main socket
- Build connection using the admin socket path from config (not `buildGateConnection` which targets the main socket)
- Remove `listPending()` — no listing functionality (user already knows the ID from `with-prod` output)
- Running `approve` with no ID prints a help message instead of listing
- Keep the approve/deny resolution flow the same

### `src/commands/with-prod.ts`

- Import `randomBytes` from `node:crypto`
- Before calling `createProdSession()`, generate `pendingId = randomBytes(16).toString("hex")`
- Print: `with-prod: if no prompt appears, approve with: gcp-authcalator approve <pendingId>`
- Pass `pendingId` to `createProdSession()` via options

### `src/with-prod/fetch-prod-token.ts`

- `FetchProdTokenOptions` gains `pendingId?: string`
- `createProdSession()`: if `pendingId` is set, add `X-Pending-Id` header to the request
- `fetchProdToken()`: same treatment for one-shot token requests

## Files Created

### `src/gate/admin-handlers.ts`

Dedicated request handler for the admin socket. Minimal surface:

```typescript
export async function handleAdminRequest(req: Request, deps: GateDeps): Promise<Response> {
  // Only approve/deny and health
}
```

Keeping this in a separate file from `handlers.ts` makes the separation of concerns explicit and makes it harder to accidentally expose admin endpoints on the main socket.

## Tests

### `src/__tests__/gate/pending.test.ts`

- Test `enqueue()` with client-provided ID (valid, invalid format, duplicate)
- Test that omitting ID still generates one automatically
- Update existing tests for the new 32-char ID format

### `src/__tests__/gate/admin-handlers.test.ts` (new)

- Test approve/deny via admin handler
- Test that non-admin routes return 404
- Test health endpoint

### `src/__tests__/gate/handlers.test.ts`

- Test that `/pending/*` routes on the main handler return 404
- Test that `X-Pending-Id` header is passed through to `confirmProdAccess`

### `src/__tests__/gate/server.test.ts` (if exists, or integration tests)

- Test that admin socket is created with correct permissions
- Test that admin socket serves approve/deny
- Test that main socket does NOT serve approve/deny

### `src/__tests__/commands/approve.test.ts`

- Update to use admin socket connection
- Test help message when no ID provided (instead of listing)

### `src/__tests__/commands/with-prod.test.ts`

- Test that `X-Pending-Id` header is sent with session creation
- Test that pending ID is printed before the request

## Key Design Decisions

- **`/tmp` for admin socket**: host `/tmp` is almost never mounted into containers. Containers get their own tmpfs. This is not a cryptographic guarantee — it's a sensible default that avoids accidental exposure.
- **No `GET /pending`**: single-flight means at most one pending request. The user knows the ID from `with-prod` output. Removing listing eliminates the enumeration vector entirely.
- **Client-generated IDs**: avoids a two-phase protocol. The ID is a correlation token, not a secret. Security comes from the admin socket being unreachable from the container. The two factors are: know the ID (container-side) + reach the admin socket (host-side). Neither alone is sufficient.
- **32 hex chars (128 bits)**: increased from 8 hex chars (32 bits) since the client controls generation. Makes brute-force infeasible even in a degraded scenario.
- **Backwards compatible**: if `X-Pending-Id` is missing, the gate generates its own ID. Direct `curl` usage still works, though the ID is only visible on the gate's stderr.
- **Separate handler file**: `admin-handlers.ts` keeps admin routes physically separate from main routes, preventing accidental exposure through the main socket.

## Migration

- The `approve` CLI command switches to the admin socket by default. Users with custom scripts hitting the main socket's `/pending` endpoints will need to update.
- The old `GET /pending` endpoint on the main socket returns 404.
- CHANGELOG entry under `[Unreleased]` in `Changed` and `Security` categories.

## Verification

1. `bun run typecheck` — no type errors
2. `bun test` — all tests pass
3. `bun run lint` — no warnings
4. `bun run format` — formatting correct
5. Manual integration test:
   - Start gate with both sockets
   - Verify main socket returns 404 for `/pending/*`
   - Verify admin socket serves approve/deny
   - Run `with-prod` in headless mode, observe printed pending ID
   - Approve via `gcp-authcalator approve <id>` on host
   - Verify token is returned to `with-prod`
   - Verify a process with access to only the main socket cannot approve
