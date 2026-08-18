# Codebase bug audit — 2026-08-01

## Goal

Review the codebase for correctness, security, concurrency, timeout, and
resource-lifecycle bugs. Prioritize failures that make `with-prod` callers wait
unnecessarily and behavior that exposes IAM propagation delay immediately after
PAM grant activation.

## Work plan

1. Trace the complete `with-prod` request lifecycle, including nested-session
   detection, gate session creation, token refresh, subprocess signal handling,
   request deadlines, and cleanup.
2. Trace PAM grant lookup, creation, activation polling, reuse, rotation,
   cancellation, and revocation. Verify that a newly active grant is not exposed
   to a client before IAM authorization is observably usable.
3. Review cross-cutting gate, metadata proxy, authentication, TLS, configuration,
   and CLI code for actionable bugs, with tests and documentation as evidence.
4. Reproduce each confirmed issue with a focused failing test before changing
   implementation code.
5. Implement the smallest safe fixes, update user-facing documentation and the
   changelog, and record any deliberately deferred findings.
6. Run focused tests, then the required full verification suite through the
   pinned `mise` toolchain: format, lint, typecheck, and all tests.

## Review criteria

- Every network or operator wait has a deliberate deadline and cancellation
  path.
- Deadlines compose correctly rather than timing out healthy inner operations.
- Shared in-flight work cannot leave callers attached to a permanently pending
  promise.
- PAM activation is followed by a bounded authorization-readiness check, so IAM
  propagation lag is absorbed by the gate rather than the first client request.
- Cleanup cannot revoke authorization still needed by another caller or leave
  stale sessions/grants after ordinary exit paths.
- Errors remain actionable without leaking credentials or sensitive command
  arguments.

## Verification record

### Confirmed and fixed

- Review follow-up: nested-session reuse now validates the backing gate session
  through a non-mutating proxy/provider check. Expired, revoked, or gate-restart
  orphaned sessions fall back to normal acquisition without token minting or PAM.
- Gate/client deadlines now cover response bodies, compose outside the
  operation they guard, and surface typed, actionable timeout errors. Bun's
  shorter transport idle timeout is disabled only where an application
  deadline exists.
- `with-prod` performs a 3-second transport preflight, cancels acquisition on
  signals, avoids token-minting nested-session probes, runs PAM and OAuth work
  concurrently, supervises the child with bounded escalation, and cleans up
  session/token/proxy state transactionally.
- Prod token responses include the identity already resolved for consent, so
  current clients avoid a redundant post-acquisition identity request while
  retaining compatibility with older gates.
- Confirmation subprocess stdin, stderr, and exit are covered by one parent
  deadline; stderr is drained immediately. The rate limiter covers only the
  consent decision and is released before slow post-approval work.
- PAM create retries are idempotent, pagination/requester matching is exact,
  expiry follows the access-grant timeline, ambiguous/externally-modified
  grants are not reused, rotation ownership is generation-fenced, retiring
  grants cannot be re-adopted, and shutdown is bounded and ownership-aware.
- Listener startup/rollback and shutdown are transactional. Socket aliases
  through symlinked parents are rejected before binding.
- Token caching uses an observed-lifetime refresh margin and single-flight
  refresh. A failed gcloud token-file update cannot commit only the in-memory
  copy, and staging files are random/exclusive.
- TLS loading validates filesystem and cryptographic identity constraints;
  missing derived bundles are repaired without needless chain rotation.
- Configuration is strict, path/origin validation is unambiguous, CLI/admin
  errors are actionable, and kubeconfig/token plugin writes and API versions
  follow their external contracts.
- Operator-visible commands redact separate sensitive values and JWT-shaped
  tokens, strip terminal/bidirectional controls, and remain reviewable in full.

### Pending product decision

PAM can report a grant `ACTIVE` before the new IAM binding authorizes API
requests. The implementation needs one configured post-activation readiness
hold; the unresolved choice is whether its default is the recommended 120
seconds (security/reliability first) or 0 seconds (opt-in latency). The safe PAM
grant-TTL floor must be raised from the current 301 seconds at the same time so
the hold plus the 5-minute drain margin still leaves a useful token lifetime.

### Deliberately deferred architectural findings

- Replacing a still-valid ADC file/account does not generically invalidate the
  gate's cached GoogleAuth source client and identity. Credential-expiry errors
  do invalidate them. A complete fix needs a provider-generation signal that
  also works for non-file ADC providers.
- If a successful `POST /session` response is lost after the gate commits the
  session, the client does not know the session ID to revoke. Fixing this needs
  a session request-id/reconciliation protocol rather than an unsafe blind
  retry.
- google-auth-library operations do not accept an AbortSignal on every path.
  The caller deadline settles, but the underlying library promise may continue
  and a provider that never settles can remain stuck internally.
- PID ownership validation synchronously scans `/proc/*/fd` on the metadata
  server event loop. The request is rejected correctly, but a host with an
  extreme process count can add latency outside the network deadlines.
- TLS material is validated as a coherent set at startup, but multi-file
  generation is not committed as one directory-level generation and a running
  daemon does not re-check a certificate that crosses expiry after startup.
- `audit.log` has no rotation/size policy. Per-refresh full argv growth was
  removed, but sustained allowed traffic can still grow the file indefinitely.
- kubeconfig file contents are fsynced before rename, but the containing
  directory is not fsynced; a power loss at the rename boundary remains a small
  durability gap.

### Checks run so far

- `git diff --check` — pass
- `mise exec -- bun run format` — pass
- `mise exec -- bun run lint` — pass
- `mise exec -- bun run typecheck` — pass
- Focused PAM tests — 120 pass
- Focused TLS tests — 85 pass
- Focused gate/client tests — 164 pass
- Focused sanitization/command tests — 57 pass
- Final unrestricted integration run after review fixes — 1240 pass, 0 fail,
  99.12% function coverage, and 98.74% line coverage. Full server tests require
  a sandbox exception for local port and Unix-socket binding.
