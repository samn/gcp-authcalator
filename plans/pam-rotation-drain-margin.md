# PAM API alignment: drain-margin token clamping for zero-downtime grant rotation, LRO revoke, search filter, audit comments

## Context

`src/gate/pam.ts` carries a thick layer of workarounds for documented and undocumented PAM behaviors. The user reports the recurring bug is "grants aren't refreshed as expected" and suspects defensive filtering and stale-grant detection are the cause. The deeper problem is different:

**Audit finding (the core insight this plan acts on):**

1. The gate currently clamps minted tokens to the PAM grant's _expiry_. Because PAM only allows one active grant per `(entitlement, requester)` (the "open Grant" rule), grant renewal requires revoking the old grant before creating a new one. There is no overlap window — so any client holding a still-valid token at the moment of rotation sees `403 PERMISSION_DENIED` for the duration of the rotation. This is invisible to clients (their token looks fine) and surfaces as flaky auth in long-running operations.
2. `grants.revoke` is a long-running `Operation` (docs: "If successful, the response body contains an instance of `Operation`"), but `revokeGrantBestEffort` (pam.ts:470–487) treats it as fire-and-forget. The Operation may not be `done` when we POST the follow-up `createGrant`, so PAM still sees the old grant as "open" and 409s. This drove commits 2c3becc, dd4b5fa, da8d167 — most of the multi-round retry logic in `pam.ts` exists to paper over it.

The two issues compound: revoke-races make rotation slow and prone to retry storms, and the no-overlap rotation window makes those retries visible to clients as permission errors.

**The plan, in priority order:**

1. **Drain-margin token clamping** — change `expiresInClampedToGrant` (handlers.ts:302–308) to clamp minted tokens to `grant_expiry - DRAIN_MARGIN_MS`, not `grant_expiry`. Clients then naturally refresh before the grant enters its drain window, and by the time the gate revokes the old grant, no token minted under it is still valid. This is the user-facing fix for the concurrent-client failure mode.
2. **Single-flight grant rotation** — add a per-entitlement in-flight `Promise` map so concurrent `ensureGrant` calls coalesce. The first call rotates; the rest await its result.
3. **LRO-aware revoke** — poll the Operation returned by `grants.revoke` until `done:true` before the recovery path retries `createGrant`. Eliminates the race that drove the multi-round recovery.
4. **`grants.search` with documented filter** — `grants.search` (v1) explicitly documents a `filter` query parameter, while `grants.list`'s filter syntax is undocumented and pam.ts:269 confirms every list-filter we've tried fails. If the search-filter works in practice, delete the `LIST_GRANTS_MAX_PAGES` pagination loop.
5. **Add missing terminal states** — `pollGrant` (pam.ts:357–390) only treats DENIED/REVOKED/ENDED as terminal. Per the v1beta State enum, EXPIRED, ACTIVATION_FAILED, EXTERNALLY_MODIFIED, WITHDRAWN are also terminal. Falling through silently retries until the 120-s polling timeout.
6. **Audit header comment** — codify, at the top of pam.ts, which behaviors are spec-compliant, defensive-against-ambiguity, or workarounds for undocumented quirks. This is institutional knowledge that has had to be re-derived from commit messages on every regression.

## Audit summary: spec vs. implementation

| Behavior                                                                            | Spec source                                                                                                                                | Verdict                                                           |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `https://privilegedaccessmanager.googleapis.com/v1` base                            | v1 GA reference                                                                                                                            | ✅ correct                                                        |
| Compute expiry as `createTime + requestedDuration` (pam.ts:392–405)                 | Grant schema has no `expireTime` field — only `createTime`, `updateTime`, `requestedDuration`, `timeline.events`                           | ✅ required; keep                                                 |
| Accept both `ACTIVE` and `ACTIVATED` (pam.ts:33)                                    | v1 lists `ACTIVE`; v1beta enum lists both spellings                                                                                        | ✅ defensive; keep                                                |
| Treat 400 FAILED_PRECONDITION + "open Grant" message as 409 (pam.ts:56–69, 246–248) | Undocumented; observed in practice (commit dd4b5fa)                                                                                        | ⚠️ undocumented workaround; keep                                  |
| List unfiltered + bucket client-side (pam.ts:268–314)                               | `grants.list` documents a `filter` param but no syntax; `grants.search` documents `filter` explicitly with a required `callerRelationship` | ⚠️ replace with `grants.search` if Phase 1 confirms filter syntax |
| Treat `grants.revoke` as fire-and-forget (pam.ts:470–487)                           | Revoke returns an `Operation` (LRO); requires polling to confirm completion                                                                | ❌ root cause; **fix in Phase 2**                                 |
| `pollGrant` terminal states limited to DENIED, REVOKED, ENDED (pam.ts:379)          | v1beta enum also has EXPIRED, ACTIVATION_FAILED, EXTERNALLY_MODIFIED, WITHDRAWN                                                            | ❌ gap; **fix in Phase 2**                                        |
| Clamp minted token TTL to grant _expiry_ (handlers.ts:302–308)                      | Required so tokens don't outlive elevated authorization; but currently leaves zero overlap window for grant rotation                       | ⚠️ correct _direction_; needs drain margin for concurrency safety |

## Research: zero-downtime patterns for "one-grant-at-a-time" temporary credentials

PAM's "one open Grant per (entitlement, requester)" rule is unusual among cloud temporary-credential systems and forecloses several common patterns:

- **AWS STS** allows arbitrarily many concurrent `AssumeRole` sessions per principal — clients rotate by issuing new sessions before old ones expire, with full overlap. Not applicable to PAM (no overlap allowed).
- **HashiCorp Vault dynamic creds** uses leases; each client gets its own lease, renewable. Not applicable (per-requester, not per-client).
- **Kubernetes service-account tokens** are long-lived; clients mint short-lived bound tokens via TokenRequest API. The cluster handles rotation transparently. Closest analogue, but k8s allows multiple bound tokens valid simultaneously.

For PAM's constraint, the workable patterns are:

| Pattern                                  | Description                                                                                                                                                                                                   | Verdict                                                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Drain margin**                         | Clamp minted token TTLs to `grant_expiry - margin`. By the time the gate revokes the old grant, all tokens minted under it have expired, so no in-flight call is using the about-to-be-revoked authorization. | ✅ **recommended** — minimal complexity, no client coordination                                 |
| **Reference counting**                   | Track active tokens; only rotate when zero are in flight.                                                                                                                                                     | ❌ tokens are opaque to the gate after issuance; can't reliably count                           |
| **Multiple entitlements**                | Operate two entitlements granting the same access; rotate between them.                                                                                                                                       | ❌ operational overhead and IAM coupling                                                        |
| **Long grants + short tokens**           | Set grant duration to max, rotate once per day at low-traffic.                                                                                                                                                | ⚠️ orthogonal; doesn't fix the rotation moment itself                                           |
| **Natural expiry (no proactive revoke)** | Let grants expire on PAM's own schedule; create new only after old is `EXPIRED`.                                                                                                                              | ⚠️ blocked by PAM state-lag — old grant may still 409 for tens of seconds after computed expiry |

The drain-margin pattern is the user's instinct ("Clamp the minted token to the expiration grace period (not the PAM grant's expiration time)") and is the design baseline below.

## Design: drain margin + serialization

### Drain margin

- Reuse the existing `CACHE_MARGIN_MS = 5 * 60 * 1000` (pam.ts:14) — it already plays the role of "minimum useful lifetime" and matches the user's chosen drain-margin duration. Rename for clarity to `DRAIN_MARGIN_MS` and update the comment to describe its dual role: (a) the threshold below which a cached grant triggers rotation, and (b) the buffer subtracted from grant expiry when clamping minted token TTLs.
- `expiresInClampedToGrant` in `src/gate/handlers.ts:302–308` changes from clamping to `grantExpiresAt` to clamping to `grantExpiresAt - DRAIN_MARGIN_MS`. All three callers (handlers.ts:194 session refresh, handlers.ts:485 prod token, handlers.ts:599 session creation) inherit the new behavior automatically.

### Behavior at rotation time

- Token request arrives. `ensureGrant` runs and returns a `PamGrantResult { name, state, expiresAt }`.
- The gate clamps the minted token TTL to `min(token_ttl, expiresAt - DRAIN_MARGIN_MS)`.
- If `expiresAt - DRAIN_MARGIN_MS - now() ≤ 0`, the grant is in its drain window and `ensureGrant` must have already rotated it (because `hasUsableLifetime` returns false on grants within the drain margin — same threshold). So this case is unreachable in steady state.
- Concurrent token requests during rotation all wait for the same in-flight Promise (see below) and receive tokens against the new grant.

### Single-flight rotation

- Add `const inFlight = new Map<string, Promise<PamGrantResult>>()` next to `grantCache` in pam.ts (around line 187).
- Wrap `ensureGrant` body in a coalescing layer:

```ts
async function ensureGrant(entitlementPath, justification): Promise<PamGrantResult> {
  const pending = inFlight.get(entitlementPath);
  if (pending) return pending;
  const p = doEnsureGrant(entitlementPath, justification);
  inFlight.set(entitlementPath, p);
  try {
    return await p;
  } finally {
    inFlight.delete(entitlementPath);
  }
}
```

- The cache fast-path inside `doEnsureGrant` still returns immediately on a healthy cache hit (no API calls), so coalescing is only paid for actual rotations.
- This is in-process serialization. The gate enforces single-instance via the socket bind check (server.ts:91), so per-machine coordination is sufficient — no distributed lock needed.

## Phase 1 — Validate against real PAM (user has access)

Before code changes, confirm three premises in the dev project. These directly inform the implementation:

1. **`grants.revoke` returns an LRO; the Operation is pollable.**
   - `POST .../grants/{id}:revoke`, capture response.
   - Expect body shape `{ name: "projects/.../operations/...", done: false }`.
   - Poll `GET .../operations/{name}` until `done:true`; record typical latency.
   - Confirm `createGrant` posted _after_ `done:true` succeeds; reproduce that posted _before_ `done:true` it 409s with "open Grant". Captures the race we're fixing.

2. **`grants.search` accepts a state filter.**
   - `GET .../grants:search?callerRelationship=HAD_CREATED&filter=state=ACTIVE` — try also `state=ACTIVATED`, `state="ACTIVE"`, `state:ACTIVE`, `state = ACTIVE`.
   - If at least one expression returns only ACTIVE grants for the requester, switch the scan path to use it. Otherwise keep `grants.list` and add `&orderBy=createTime desc` to push the open grant onto page 1 most of the time.

3. **`requestedDuration` is measured from `createTime` (not from `auditTrail.accessGrantTime` or the first `timeline.events[type=Activated].eventTime`).**
   - Create a grant in a no-approval entitlement; immediately GET it and compare `createTime`, `updateTime`, and Activated event time.
   - If they differ materially, `computeGrantExpiry` (pam.ts:392–405) is using the wrong anchor — switch to the Activated event time when present, fall back to `createTime`.

Record findings in a `## Phase 1 results` section in this plan file before starting Phase 2.

## Phase 1 results (verified against `projects/monitron-dev/.../engineering-prod-debug`)

**#1 — LRO revoke confirmed.** `POST .../grants/{id}:revoke` returns:

```
{ "name": "projects/.../operations/operation-...", "done": false,
  "metadata": {..., "createTime": ..., "verb": "update", "apiVersion": "v1"} }
```

Polling `GET .../operations/{name}` flipped `done: true` after ~3 seconds (4 polls at 500-ms intervals). The final operation body carries `response.state = "REVOKED"` and `response.auditTrail.accessRemoveTime`. After `done: true`, an immediate `createGrant` for the same entitlement succeeded with 200 — confirming the race we're fixing is real and the LRO wait is the right fix.

**#2 — `grants.search` filter is unusable.** `state=ACTIVE`, `state=ACTIVATED`, `state = ACTIVE`, and the OR forms return 400 `INVALID_ARGUMENT: invalid list filter`. `state="ACTIVE"` (quoted) and `state:ACTIVE` return 200 OK but `grants: 0` _even when an ACTIVE grant exists on the entitlement_ — the filter is silently dropping the match. Same behavior on `grants.list` with the same expressions. `orderBy=createTime desc` is also rejected with "sort order unsupported." **Decision: keep `grants.list` unfiltered with client-side bucketing. Skip task 2d.**

**#3 — Time fields.** `createTime` (request received) and the `timeline.events[type=activated].eventTime` differ by ~3 s. The grant's `auditTrail.accessGrantTime` matches the activated event time. The current `computeGrantExpiry` uses `createTime`; the ~3-s difference is negligible against the 5-minute drain margin, so no change needed. (If we ever want stricter expiry math, prefer `auditTrail.accessGrantTime` over `createTime`.)

**Other useful observations from the live trace:**

- Entitlement minimum `requestedDuration` is 30 minutes on this project. The verify script defaulted to 600 s and was rejected; bumped to 1860 s for the run.
- Initial grant state is `SCHEDULED` → `ACTIVATING` → `ACTIVE`. The poll loop must traverse SCHEDULED + ACTIVATING (already handled — these are pending states, not terminal).
- Timeline event types observed: `requested`, `scheduled`, `activated`, `revoked`. The `eventTime` is RFC 3339 with sub-second precision.

## Phase 2 — Code changes

### 2a. Drain-margin token clamping (priority 1, the user-facing fix)

- `src/gate/pam.ts:14` — rename `CACHE_MARGIN_MS` → `DRAIN_MARGIN_MS` with an expanded comment explaining its two roles.
- `src/gate/handlers.ts:302–308` — change `expiresInClampedToGrant` to subtract `DRAIN_MARGIN_MS` from `grantExpiresAt` before the min comparison. Add the constant import. Update the function-level comment to explain that the clamp leaves a drain window where no minted token is still valid, so revoke-and-rotate has no in-flight tokens to disrupt.
- No changes needed to the three callers — they pass the grant's `expiresAt` and the helper now does the subtraction.

### 2b. Single-flight rotation

- `src/gate/pam.ts` — add the `inFlight` Map and wrap `ensureGrant` as shown in the Design section. Add a one-line comment explaining the gate is single-instance (per server.ts:91) so per-process coalescing is sufficient.

### 2c. LRO-aware revoke

- `src/gate/pam.ts` — add `pollRevokeOperation(operationName, deadlineMs)`: polls `GET ${PAM_API_BASE}/${operationName}` with exponential backoff (100 ms → 1 s, total 30 s budget); resolves on `done:true`; logs and returns on timeout (don't throw — revoke is best-effort).
- Split the existing `revokeGrantBestEffort` into:
  - `revokeGrantFireAndForget(name, reason)` — current behavior, used only by `revokeAll` on shutdown.
  - `revokeGrantAndWait(name, reason, deadlineMs = 30_000)` — parses the returned Operation, polls until `done`. Used by `createGrantWithRecovery` and `ensureGrant`'s pre-emptive revoke.
- Both helpers tolerate FAILED_PRECONDITION on already-terminal grants (already-revoked, already-expired) without raising.
- In `createGrantWithRecovery` (pam.ts:316–355), with revoke-and-wait the multi-round retry collapses to: `createGrantOnce` → on conflict, scan → reuse if usable, else `revokeGrantAndWait` on stale → `createGrantOnce` once more. The second scan at pam.ts:349 is no longer needed — delete it and the surrounding comments.
- In `ensureGrant` (pam.ts:431–438), the pre-emptive revoke switches to `revokeGrantAndWait`. The comment at pam.ts:432–437 explaining the LRO-race rationale is replaced with one line noting we wait on the LRO.

### 2d. `grants.search` with filter (conditional on Phase 1 #2)

- `src/gate/pam.ts` — if Phase 1 validated a filter expression, rename `scanForOpenGrants` → `findActiveGrant`, reimplement using `GET .../grants:search?callerRelationship=HAD_CREATED&filter=<validated>`. Delete `LIST_GRANTS_PAGE_SIZE`, `LIST_GRANTS_MAX_PAGES`, the pagination loop, and the `stale` collection bucket in the returned struct.
- Retain the `hasUsableLifetime` re-check on the returned grant — even with a state filter, computed expiry from `createTime + requestedDuration` is the authoritative source (state-lag is unrelated to filter syntax).
- If Phase 1 did not validate a filter, keep `scanForOpenGrants` but add `&orderBy=createTime desc` (a documented `list` parameter) and reduce `LIST_GRANTS_MAX_PAGES` to 3.

### 2e. Missing terminal states in `pollGrant`

- `src/gate/pam.ts:33` — add `TERMINAL_GRANT_STATES = new Set([...])` adjacent to `ACTIVE_GRANT_STATES`. Include DENIED, REVOKED, ENDED, EXPIRED, ACTIVATION_FAILED, EXTERNALLY_MODIFIED, WITHDRAWN.
- `src/gate/pam.ts:379` — replace the hard-coded `=== "DENIED" || === "REVOKED" || === "ENDED"` with `TERMINAL_GRANT_STATES.has(grant.state ?? "")`. Updated error message: `PAM grant entered terminal state ${state}: ${grantName}`.

### 2f. Audit header comment

- `src/gate/pam.ts:1–6` — replace the current short header with a 30–40-line block documenting the API quirks table from the audit section above. This is the canonical reference for future maintainers.

## Phase 3 — Tests

`src/__tests__/gate/pam.test.ts`:

**New tests:**

- **Drain-margin clamping** — assert that `expiresInClampedToGrant` returns 0 when the grant has `<DRAIN_MARGIN_MS` remaining, and returns `grantExpiresAt - DRAIN_MARGIN_MS - now` when the grant is within token TTL.
- **Single-flight coalescing** — fire 5 concurrent `ensureGrant` calls for the same entitlement; mock `createGrantOnce` with a 50 ms delay; assert it is called exactly once and all 5 callers receive the same `name`.
- **LRO revoke polling** — mock revoke to return `{ name: "operations/abc", done: false }` then on next poll `{ name: "operations/abc", done: true }`; assert `revokeGrantAndWait` resolves after the second response.
- **LRO error tolerance** — mock revoke Operation `{ done: true, error: { code: 5, message: "NOT_FOUND" } }` (already-terminal grant); assert `revokeGrantAndWait` returns without throwing.
- **LRO timeout** — mock revoke Operation that never reports `done:true`; assert `revokeGrantAndWait` returns within the deadline (best-effort, doesn't throw).
- **Each new terminal state** — for EXPIRED, ACTIVATION_FAILED, EXTERNALLY_MODIFIED, WITHDRAWN: assert `pollGrant` throws immediately rather than retrying.
- **`grants.search` happy path** — only added if Phase 1 #2 validates filter syntax.

**Updated tests:**

- Stale-grant recovery tests (pam.test.ts:727–895, 956–1097) — assertions shift from "multi-round retry" to "revoke-and-wait + single retry"; the "post-revoke rescan" scenario (pam.test.ts:956–1051) is no longer reachable and gets deleted.
- Token-clamp tests in handlers tests — expectations shift down by `DRAIN_MARGIN_MS` seconds.

**Kept verbatim:** ACTIVE/ACTIVATED equivalence, 409 reuse, 400 FAILED_PRECONDITION reuse with narrow-message-match, entitlement-path resolution, shutdown revocation.

## Phase 4 — Documentation

- `CHANGELOG.md` `[Unreleased] / Changed`:
  - "Clamp prod token expiry to PAM grant expiry minus a 5-minute drain margin (was: clamped to grant expiry). Concurrent clients no longer see permission errors during PAM grant rotation."
  - "Use `grants.search` with documented filter parameter to locate active PAM grants (was: unfiltered `grants.list` with client-side bucketing)." — only if 2d lands.
- `CHANGELOG.md` `[Unreleased] / Fixed`:
  - "Poll PAM `grants.revoke` long-running operation before retrying `createGrant`, eliminating the stale-grant race that intermittently surfaced as `PAM grant conflict but no active grant found`."
  - "Detect EXPIRED, ACTIVATION_FAILED, EXTERNALLY_MODIFIED, and WITHDRAWN as terminal grant states during polling, replacing the 120-second silent retry on these conditions."
- `SPEC.md` — add one paragraph under the PAM integration section describing the drain-margin pattern and pointing at the new pam.ts header comment.
- `README.md` — if any user-facing token-lifetime guidance exists, note the up-to-5-minute reduction. (Audit during implementation.)

## Critical files

- `src/gate/pam.ts` — drain-margin constant rename, single-flight Map, LRO polling, search swap, terminal states, audit header
- `src/gate/handlers.ts:302–308` — `expiresInClampedToGrant` subtracts drain margin
- `src/__tests__/gate/pam.test.ts` — extensive test updates and additions
- `src/__tests__/gate/handlers.test.ts` (if it exists) — token-clamp assertions shift
- `CHANGELOG.md`, `SPEC.md` — documentation sync

## Reused code

- `pamFetch` (pam.ts:193–203) — handles ADC token injection; reused by the new Operation poller.
- `parseDurationSeconds` (pam.ts:43–47), `computeGrantExpiry` (pam.ts:392–405), `hasUsableLifetime` (pam.ts:189–191) — all stay; reused by the new search-based code path.
- `isOpenGrantPrecondition` (pam.ts:56–69) — unchanged; still the matcher for the 400/409 reuse branch.
- `ACTIVE_GRANT_STATES` / `isActiveState` (pam.ts:33) — sit next to the new `TERMINAL_GRANT_STATES` set.
- Existing test fixtures `makeModule()` / `makeActivatedGrant()` — reused; add a `makeOperationResponse(done, error?)` helper for LRO tests.

## Verification

1. **Pre-commit suite** (`AGENTS.md`): `bun run format`, `bun run lint`, `bun run typecheck`, `bun test` — all green.
2. **Unit-level** — `bun test src/__tests__/gate/pam.test.ts` and handlers tests; all new and updated tests pass.
3. **Phase 1 findings recorded in this plan file** before Phase 2 starts.
4. **End-to-end against real PAM (dev project, user has access):**
   - Run `with-prod -- gcloud auth print-access-token`; confirm grant is created and token is returned with `expires_in` ≤ `grant_duration - 300` seconds. Compare to `kubectl --token-cache=false` flow for the kube path.
   - Re-run within the grant's useful window; confirm token is reused/refreshed against the same grant (cache hit, no rotation).
   - Force renewal by lowering grant duration (e.g., `--grant-duration 600s`); confirm renewal succeeds on the first attempt — no "stale grant" recovery path.
   - **Concurrent-client repro** (the user-reported bug): in two terminals, run two `with-prod` invocations against the same entitlement. Inject a sleep into the long-running one to span across the drain margin. Verify that when the short-running one triggers rotation, the long-running one's _next_ GCP API call after its token expires gets a fresh token (against the new grant) and the operation completes without spurious 403s.
   - Ctrl-C `with-prod` mid-run to leave an orphaned grant; re-run and confirm the 400/409 reuse branch still finds and reuses the existing grant.
5. **Regression check on the recurring bug** — manually revoke a grant via `gcloud pam grants revoke` immediately before calling the gate's `/token` endpoint; with LRO-aware revoke, the gate should succeed cleanly. Without it, the gate's retry storm would have been observable in logs.
6. **Observability** — tail `audit.log` during the concurrent-client repro: there should be exactly one `pam_grant` create per rotation, not the multi-revoke-multi-create pattern visible today.

## Out of scope

- Changing the default grant duration (`FALLBACK_GRANT_DURATION_SECONDS = 3600`) — orthogonal to the rotation pattern.
- Cross-process / cross-gate-instance coordination — the gate is single-instance per machine by design (server.ts:91).
- Reference counting of in-flight tokens — explicitly considered (Research section) and rejected as too complex for the bounded improvement.
- Surfacing the LRO Operation name in audit logs — could help future debugging, but defer unless Phase 1 reveals an operational need.
