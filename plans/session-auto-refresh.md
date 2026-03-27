# Plan: Auto-Refresh Prod Credentials via Gate Sessions

## Context

When `with-prod` wraps a long-running process (e.g., local API server), credentials expire after the token TTL (default 1 hour) and the process stops working. Currently `with-prod` fetches a single prod token and serves it statically via `createStaticTokenProvider` — there is no refresh mechanism.

**Goal:** Keep token TTL low (reduces exfiltration risk) while allowing the metadata proxy to refresh tokens from the gate. The refresh capability (session state) stays on the host in the gate daemon — the subprocess only ever sees short-lived access tokens.

## Design

Add a "prod session" concept to the gate. A session is created once (with user confirmation), then allows token refreshes without re-confirmation for a bounded lifetime.

```
with-prod                          gate daemon
   |                                   |
   |-- POST /session ----------------->|  (rate limit + confirm + PAM)
   |<-- { session_id, token, email } --|
   |                                   |
   | [start metadata proxy]            |
   | [spawn child process]             |
   |                                   |
   |    child ----> metadata proxy     |
   |                  | getToken()     |
   |         [cache hit? return it]    |
   |         [near expiry? refresh:]   |
   |-- GET /token?session=<id> ------->|  (validate session, mint token, no confirmation)
   |<-- { access_token, expires_in } --|
   |         [update cache + file]     |
   |                                   |
   | [child exits]                     |
   |-- DELETE /session?id=<id> ------->|  (best-effort cleanup)
```

**Security properties:**

- Session IDs: 32-byte crypto-random (256-bit entropy), transmitted only over Unix socket or mTLS
- Session ID never reaches the subprocess — it lives in the token provider closure inside the with-prod process
- Session lifetime bounded (default 8h, configurable)
- Individual tokens remain short-lived (configured TTL, default 1h)
- Session creation goes through full rate limiting + confirmation + PAM
- Sessions revoked on gate shutdown and with-prod exit
- All session operations audit-logged

## Implementation Steps

### Step 1: Session Manager — `src/gate/session.ts` (new file)

In-memory session store with `SessionManager` interface:

- `create({ email, scopes?, pamPolicy?, ttlSeconds, sessionLifetimeSeconds })` → `ProdSession`
- `validate(id)` → `ProdSession | null` (null if expired or unknown)
- `revoke(id)` → `boolean`
- `revokeAll()` — for gate shutdown
- Session ID via `crypto.randomBytes(32).toString('hex')`
- Injectable `now()` for deterministic testing (same pattern as `rate-limit.ts`)

### Step 2: Config — `src/config.ts`

Add `session_ttl_seconds` field:

- Type: `z.coerce.number().int().min(300).max(86400).optional()`
- Default applied in gate server: 28800 (8 hours)

### Step 3: Gate Types — `src/gate/types.ts`

- Add `session_id?: string` to `AuditEntry`
- Add `SessionResponse` interface
- Add to `GateDeps`: `sessionManager`, `sessionTtlSeconds`

### Step 4: Gate Handlers — `src/gate/handlers.ts`

- Add `POST /session` — same flow as prod token (rate limit → confirm → PAM → mint), plus creates session
- Add `DELETE /session` — revoke by ID
- Modify `GET /token?session=<id>` — validate session, mint fresh prod token, skip confirmation

### Step 5: Wire into Gate Server — `src/gate/server.ts`

### Step 6: Session Token Provider — `src/with-prod/session-token-provider.ts` (new file)

Caching token provider that refreshes via `GET /token?session=<id>`. Same 5-min cache margin pattern as gate-client.ts. Accepts `onRefresh` callback for updating gcloud token file.

### Step 7: Session Lifecycle Functions — `src/with-prod/fetch-prod-token.ts`

- `createProdSession(conn, options)` → `POST /session`
- `revokeProdSession(conn, sessionId)` → `DELETE /session?id=<id>` (best-effort)

### Step 8: Update With-Prod Command — `src/commands/with-prod.ts`

Replace static token flow with session-based flow.

### Step 9: Documentation — CHANGELOG.md, SPEC.md, config.example.toml
