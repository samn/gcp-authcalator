# Prod Token Rate Limiting

**Issue:** https://github.com/samn/gcp-authcalator/issues/15

## Problem

`GET /token?level=prod` has no rate limiting, cooldown, or anti-replay protection.
An attacker with socket access can:

1. **DoS** — Flood the user with confirmation dialogs
2. **Race** — Time a rapid request to coincide with a legitimate approval
3. **Fatigue** — Exhaust the user's patience until they reflexively approve

## Solution

Create a `ProdRateLimiter` module with three layers of protection:

### 1. Single-flight (mutex)

Only one confirmation dialog at a time. If a prod request arrives while a dialog
is already pending, reject immediately with 429.

### 2. Cooldown after denial

After a prod request is denied (user clicks "no"), impose a 30-second cooldown.
Requests during the cooldown are rejected with 429.

### 3. Sliding window rate limit

Maximum 5 prod confirmation attempts within a 5-minute window. Prevents sustained
low-rate attacks that stay under the cooldown.

## Design

### New module: `src/gate/rate-limit.ts`

```typescript
export interface ProdRateLimiter {
  acquire(): { allowed: true } | { allowed: false; reason: string };
  release(result: "granted" | "denied" | "error"): void;
}
```

- `acquire()` is called before showing the confirmation dialog
- `release()` is called after the dialog completes (or errors)
- The handler gates on `acquire()` before calling `confirmProdAccess()`

### Type changes

- Add `"rate_limited"` to `AuditEntry.result`
- Add `prodRateLimiter: ProdRateLimiter` to `GateDeps`

### Configuration

All limits are constants (not configurable), keeping the attack surface minimal:

| Parameter           | Value |
| ------------------- | ----- |
| Max concurrent      | 1     |
| Denial cooldown     | 30s   |
| Window size         | 5 min |
| Max attempts/window | 5     |

## Files changed

- `src/gate/rate-limit.ts` — new module
- `src/gate/types.ts` — updated types
- `src/gate/handlers.ts` — integrate rate limiter
- `src/gate/server.ts` — wire up rate limiter
- `src/__tests__/gate/rate-limit.test.ts` — new tests
- `src/__tests__/gate/handlers.test.ts` — updated tests
