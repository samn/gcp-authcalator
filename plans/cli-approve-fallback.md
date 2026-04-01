# Plan: CLI Fallback for Gate Approval Requests

## Context

When a prod token is requested, the gate server's confirmation module tries GUI dialogs (osascript/zenity), then a terminal TTY prompt, then auto-denies. In headless environments (CI, remote SSH without X forwarding, containers), both GUI and TTY fail and prod access is silently denied. This feature adds a pending approval queue so that when interactive methods are unavailable, requests are parked and a separate CLI command can list and approve/deny them.

## Design

The confirmation flow currently returns `Promise<boolean>` from `confirmProdAccess()`. The pending queue slots in as a third fallback: GUI → TTY → **pending queue** → auto-deny. From `handlers.ts` perspective, `confirmProdAccess` is still just `Promise<boolean>` — the queue is an internal detail of the confirmation module.

When a request is queued, the gate logs to stderr with the request ID and a hint to run `gcp-authcalator approve <id>`. The pending queue auto-denies after 120 seconds (2x the current dialog timeout, since CLI approval requires switching terminals).

## Files Created

### 1. `src/gate/pending.ts` — Pending queue module

Factory: `createPendingQueue(options?) → PendingQueue`

```typescript
interface PendingRequest {
  id: string; // 8-char hex (randomBytes(4))
  email: string;
  command?: string;
  pamPolicy?: string;
  createdAt: Date;
  expiresAt: Date;
}

interface PendingQueue {
  enqueue(email: string, command?: string, pamPolicy?: string): Promise<boolean>;
  list(): PendingRequest[];
  approve(id: string): boolean;
  deny(id: string): boolean;
  denyAll(): void;
}
```

Internal state: `Map<string, { request, resolve, timer }>`. Follows the same factory + options pattern as `session.ts` and `rate-limit.ts` (with `now?` override for deterministic testing).

On enqueue, logs to stderr:

```
gate: pending approval abc12def — user@example.com (gcloud compute instances list) — expires in 120s
gate: run 'gcp-authcalator approve abc12def' to approve, or 'gcp-authcalator approve --deny abc12def' to deny
```

### 2. `src/commands/approve.ts` — CLI command

```typescript
export async function runApprove(
  config: Config,
  positionals: string[],
  flags: { deny?: boolean },
): Promise<void>;
```

- No args → `GET /pending`, print table of pending requests, exit
- `<id>` → `POST /pending/<id>/approve` (or `/deny` with `--deny` flag)
- Connects to gate via `buildGateConnection(config)` + `connectionFetchOpts()`
- Uses `PendingRequestJSON` wire type with string dates (not server-side `Date` type)
- Imports `ErrorResponse` from `types.ts` (not redefined locally)
- Output: human-friendly table for list, one-line confirmation for approve/deny

### 3. `src/__tests__/gate/pending.test.ts` — 16 queue unit tests

### 4. `src/__tests__/commands/approve.test.ts` — 5 integration tests with shared `setup()` helper

## Files Modified

### 5. `src/gate/confirm.ts`

Added `pendingQueue?: PendingQueue` to `ConfirmOptions`. The pending queue fallback lives in `confirmProdAccess` (not inside `tryTerminalPrompt`), keeping `tryTerminalPrompt` focused on its single concern (3 params, not 5):

```typescript
// In confirmProdAccess, after GUI and TTY checks:
if (isTTY) {
  return tryTerminalPrompt(email, command, pamPolicy);
}
if (pendingQueue) {
  console.error("confirm: no interactive method available, queuing for CLI approval");
  return pendingQueue.enqueue(email, command, pamPolicy);
}
console.error("confirm: no interactive method available, denying prod access");
return false;
```

### 6. `src/gate/types.ts`

Added `pendingQueue?: PendingQueue` to `GateDeps`.

### 7. `src/gate/handlers.ts`

Added three endpoints, gated behind `url.pathname.startsWith("/pending")` to avoid regex on non-pending routes:

- `GET /pending` → `handleListPending(deps)` — returns `{ pending: PendingRequest[] }`
- `POST /pending/<id>/approve` → resolves request, returns `{ status: "approved" }`
- `POST /pending/<id>/deny` → resolves request, returns `{ status: "denied" }`

Returns 404 for unknown/expired IDs, 501 if `pendingQueue` not in deps. Audit logs approve/deny actions.

### 8. `src/gate/server.ts`

- Creates `pendingQueue = createPendingQueue()` and passes to `createConfirmModule` and `deps`
- Calls `pendingQueue.denyAll()` in shutdown handler
- New endpoints shown in startup console log

### 9. `src/cli.ts`

- Added `"approve"` to `SUBCOMMANDS`
- Added `--deny` boolean flag to `parseArgs`
- Routes `approve` subcommand with proper ZodError handling (matching other commands)
- Updated USAGE string with examples

### 10. `src/__tests__/gate/confirm.test.ts` — 4 new pending queue fallback tests

### 11. `src/__tests__/gate/handlers.test.ts` — 7 new endpoint tests

### 12. `src/__tests__/cli.test.ts` — Verify `approve` appears in help

### 13. `CHANGELOG.md` — Entry under `[Unreleased]`

### 14. `README.md` — New `approve` command section, updated API table, security model

### 15. `SPEC.md` — New component section, updated API table, confirmation flow

## Key Design Decisions

- **120s timeout** (not 60s): CLI approval requires the user to notice the log, switch terminals, and type a command — 60s is too tight.
- **Short hex IDs** (8 chars): Human-friendly for typing. Collision risk is negligible for the small number of concurrent pending requests.
- **Always-on queue**: No config toggle. If GUI and TTY work, the queue is never used. Zero overhead when not needed.
- **No watch/poll mode**: The CLI can be re-run trivially. Adds complexity for marginal benefit.
- **Rate limiter interaction**: The single-flight lock is held while a request is queued. This correctly prevents queue flooding — only one pending request at a time.
- **Security model unchanged**: New endpoints are behind the same socket permissions (0600) / mTLS as all other endpoints. No new authentication surface.
- **Wire types**: Client-side `PendingRequestJSON` uses `string` for dates (matching JSON serialization), not the server-side `Date` type. Prevents silent type lie across the JSON boundary.

## Verification

1. `bun run typecheck` — no type errors
2. `bun test` — 702 tests pass, 0 fail, `pending.ts` at 100% coverage
3. `bun run lint` — no warnings
4. `bun run format` — formatting correct
5. Manual integration test:
   - Start gate: `bun run index.ts gate --project-id test --service-account sa@test.iam.gserviceaccount.com --socket-path /tmp/test.sock`
   - Request prod token (with no GUI/TTY): `curl --unix-socket /tmp/test.sock http://localhost/token?level=prod`
   - List pending: `bun run index.ts approve --socket-path /tmp/test.sock`
   - Approve: `bun run index.ts approve --socket-path /tmp/test.sock <id>`
   - Verify the original curl request completes with a token
