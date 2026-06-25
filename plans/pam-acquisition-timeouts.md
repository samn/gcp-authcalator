# PAM acquisition timeouts & rotation budget

## Problem

Users reported `with-prod` hanging 10+ minutes while acquiring a prod token.

Root cause: **nothing on the prod-token acquisition path or inside the PAM
module bounded its network I/O with a timeout**, while the rest of the codebase
consistently does (`gate-client` 3 s, `detect-nested-session` 2 s, gate
stale-socket 1 s, session revoke 2 s).

Failure mechanism:

1. **No per-call timeout.** `pamFetch` (create/list/poll/withdraw) and the
   client acquisition fetches (`createProdSession`, `/token?level=prod`,
   `/identity`, session refresh) had no `AbortSignal`. A half-open connection —
   NAT/LB idle-drop, a lost RST, or a PAM backend stalled behind IAM-replication
   lag — left the fetch waiting on the OS TCP retransmission timeout (~15 min on
   Linux with default `tcp_retries2`).
2. **Single-flight amplification.** `ensureGrant` coalesces concurrent rotations
   per entitlement and clears the in-flight slot only in a `finally` that runs
   when the rotation promise _settles_. A wedged fetch ⇒ promise never settles ⇒
   slot never cleared ⇒ every concurrent and subsequent caller for that
   entitlement attaches to the same hung promise. One stall ⇒ everyone waits.
3. **No overall budget.** Even with per-call timeouts, the ADC token
   acquisition (`getAccessToken`) runs _inside_ `pamFetch` before each call and
   is not covered by the fetch signal; and a pathological rotation chains many
   sequential calls. An overall wall-clock budget is the backstop.
4. **Config foot-gun (H7).** `pam_grant_ttl_seconds` accepted values ≤ the
   5-minute drain margin. Such a grant is never "usable" (`hasUsableLifetime`
   needs `> DRAIN_MARGIN_MS`) and every minted token clamps to 0 s (born
   expired) → client refresh storm. Flooring the token clamp instead would be
   _wrong_ (it would serve tokens valid past the grant's withdrawal), so the
   guard belongs at config-parse time.

## Fixes (red/green TDD)

1. **Per-request PAM fetch timeout** — `pamFetch` attaches
   `AbortSignal.timeout(PAM_FETCH_TIMEOUT_MS = 10 s)` and rethrows aborts as an
   actionable "PAM API request timed out after Nms: <url>".
2. **Client acquisition timeouts** — `createProdSession` / `/token` /
   `/identity` / session refresh go through `fetchWithGateTimeout`, a shared
   wrapper that bounds the request (AbortController + `clearTimeout`) and
   rethrows aborts as an actionable, URL-bearing error (mirrors `pamFetch`).
   Sized above the gate's legitimate worst case (confirmation ≤120 s + rotation
   budget) so they never false-abort a real wait but convert a wedged socket
   into a clear error. Constants: `PROD_FETCH_TIMEOUT_MS = 600 s`,
   `IDENTITY_FETCH_TIMEOUT_MS = 30 s`, `SESSION_REFRESH_TIMEOUT_MS = 480 s`.
3. **Overall rotation budget** — `ensureGrant` runs `doRotateGrant` under
   `withRotationBudget` (`ROTATION_BUDGET_MS = 420 s`, deliberately set above the
   ~300 s worst-case sum of the rotation's own internal deadlines so it never
   false-aborts an in-progress rotation). On expiry the budget BOTH aborts the
   rotation's `AbortSignal` — threaded through `pamFetch`/`pollGrant`/withdraws,
   so in-flight PAM calls cancel and later ones reject immediately — AND rejects
   the race (so a `getAccessToken` hang, which no signal can cancel, still
   settles the caller). `doRotateGrant` re-checks the signal before writing the
   cache and best-effort withdraws any grant it created post-abort, so a budget
   hit cannot clobber a newer rotation's cache entry or orphan a grant.
4. **Config guard** — `pam_grant_ttl_seconds` must be `> DRAIN_MARGIN_SECONDS`
   (range 301–43200), rejected at parse time. `GateConfigSchema` additionally
   validates the _effective_ grant lifetime: when `pam_policy` is set and
   `pam_grant_ttl_seconds` is unset, `token_ttl_seconds` becomes the grant TTL
   and is held to the same floor — closing the fallback hole.

## Testing notes

- bun 1.3.x does **not** abort a never-settling promise via the per-test
  timeout, so the PAM hang-tests bound their own wait with a `settleWithin`
  helper (guard timer is unref'd + cleared). Otherwise a regression would hang
  the suite instead of failing it.
- `AbortSignal.timeout(...)` is unref'd in bun, so the default 10 s per-fetch
  timeout on every `pamFetch` does not keep the test process alive.
- Client-timeout tests assert a timeout `AbortSignal` is attached to each
  acquisition request, and that an abort surfaces the actionable wrapped error
  (not a bare `DOMException`).

## Code-review follow-ups (xhigh review)

A workflow code review found that the first cut had real gaps; all fixed above:

- Budget (then 300 s) was below the rotation's own worst-case internal sum
  (~300 s incl. the 10-page conflict scan), so it could false-abort a slow but
  healthy rotation. Raised to 420 s with an honest cost breakdown in the comment.
- The original `withRotationBudget` _abandoned_ (didn't cancel) the rotation, so
  a budget-aborted rotation could keep running and clobber the cache, orphan a
  grant, or leak on shutdown. Now threads an `AbortSignal` so the budget cancels
  in-flight work, plus a pre-cache guard + orphan withdraw.
- The drain-margin guard missed the `token_ttl_seconds` fallback (closed above).
- Client aborts surfaced bare `DOMException`s; now normalized via
  `fetchWithGateTimeout`, which also `clearTimeout`s the (multi-minute) timer so
  repeated session refreshes don't accumulate stale timers.

## Out of scope / residual

- If the rotation wedges specifically inside `getAccessToken` (google-auth's own
  token fetch, which takes no `AbortSignal`), the budget still settles the caller
  via the race, but that one background promise stays pending until google-auth's
  internal timeout — it cannot be cancelled from here.
- Manual-approval PAM entitlements (poll times out at 120 s, then withdraws)
  remain unsupported by design.
