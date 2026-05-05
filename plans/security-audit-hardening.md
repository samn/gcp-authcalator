# Security Audit Hardening

Plan tracking the implementation of recommendations from the security audit
on branch `claude/security-audit-tgAEI`.

The audit found no critical/high issues but identified ten defense-in-depth
gaps. This plan implements all of them.

## Recommendations

### F1 — Move admin socket default to `$XDG_RUNTIME_DIR`

**Why:** `/tmp/gcp-authcalator-admin-<uid>/` is in a world-writable
directory. On a multi-user host, an attacker can pre-create that directory
mode `0o777` and intercept the admin socket.

**Change:** `getDefaultAdminSocketPath()` in `src/config.ts` returns
`<XDG_RUNTIME_DIR>/gcp-authcalator-admin/admin.sock`. The directory is
already `0o700` owned by the user, so the parent-dir attack is closed.

### F2 / F6 — Verify socket-directory ownership and mode at startup

**Why:** `mkdirSync({ recursive: true, mode: ... })` silently no-ops on
existing directories, so loose permissions inherited from earlier runs
(or from a hostile pre-create) are not corrected. The operator-socket
trust boundary depends on these dir permissions.

**Change:** Add `ensureUserDir(path, mode)` in `src/gate/dir-utils.ts`
(or a similar shared module) that:

- creates the directory if absent (with the requested mode under a
  `0o077` umask),
- if it already exists, refuses if it is a symlink, owned by another
  uid, or has mode bits looser than the requested mode (mask
  `0o077` for `0o700`-style requests, mask `0o007` for `0o750`-style),
- chmods to the requested mode otherwise (defense-in-depth).

Apply at every `mkdirSync` for socket dirs (gate main/admin/operator),
the audit log dir, the with-prod runtime dir, and the TLS dir.

### F3 — Refuse to start when `agent_uid` is not in `/etc/passwd` and operator socket is enabled

**Why:** `getGroupsForUid` in `src/gate/unix-group.ts` returns `[]` for
any UID that doesn't appear in `/etc/passwd`, silently making the
"agent UID is not in operator group" guardrail a no-op for NSS/LDAP
users.

**Change:** When `operator_socket_path` is set, require that the
resolved `agent_uid` is present in `/etc/passwd`. If not, refuse to
start with an actionable error suggesting the user run `id -u <name>`
and pass the numeric UID, or stop using NSS-managed users for the
agent.

### F4 — Capture and delete `GCP_AUTHCALATOR_TLS_BUNDLE_B64` at the very first line of `main()`

**Why:** Today the env var is deleted lazily inside `resolveClientBundle`,
but the CLI invokes `getCommitSha` (which spawns `git`) during module
init for `formatVersion()`, so child processes can inherit the bundle
via `/proc/<pid>/environ`.

**Change:** Add `captureAndDeleteTlsBundle()` (in `src/tls/bundle.ts`)
that pulls the env var into a module-level slot and deletes it from
`process.env`. Call it as the first line of `main()` in `src/cli.ts`
before any module-level code can spawn. `resolveClientBundle` reads
from the captured slot first.

### F5 — Set `process.umask(0o077)` at gate startup

**Why:** Sockets are created by `Bun.serve` with the inherited umask
(typically `0o022`, yielding `0o755` permissions) and only chmod'd to
`0o600`/`0o660` afterward. A tight umask narrows the brief race window.

**Change:** Call `process.umask(0o077)` at the top of `startGateServer`
and `runWithProd`. Apply via `src/gate/server.ts` and
`src/commands/with-prod.ts`.

### F7 — Filter `/proc/net/tcp` rows to ESTABLISHED state in PID validator

**Why:** `findInodeInFile` returns the first row whose `local_address`
matches the target port, regardless of socket state. Listening sockets
or CLOSE_WAIT sockets bound to the same local port could collide.

**Change:** Parse field 3 (`st`) and accept only `01`
(`TCP_ESTABLISHED`).

### F8 — Strip control characters from all confirm-dialog inputs uniformly

**Why:** `summarizeCommand` already strips control chars from `command`
but `confirm.ts` does not strip them from `email` or `pamPolicy`. Today
both inputs pass through strict upstream validation; the change is
defense-in-depth against future surface expansion.

**Change:** Reuse the existing `stripControlChars` helper. Apply to all
three inputs of `confirmProdAccess` in zenity, osascript, terminal, and
pending-queue paths.

### F9 — Swap config precedence to `cli > env > file`

**Why:** Today `loadConfig` merges `{ ...file, ...cli, ...env }`, so an
env var silently overrides an explicit CLI flag. This inverts universal
convention and is a footgun for operators who rely on CLI flags.

**Change:** Swap to `{ ...file, ...env, ...cli }` and document the
change in CHANGELOG as a breaking precedence change. Update SPEC.md.

### F10 — Pin `GCP_AUTHCALATOR_PROD_SESSION` to loopback

**Why:** `detectNestedSession` uses the env-var value as a host without
validating that it points to a loopback address, allowing an
env-injection attacker (same-UID confused deputy) to redirect the
wrapped command's metadata traffic to a remote attacker-controlled
server.

**Change:** Parse the host with `URL`, accept only `127.0.0.1`,
`localhost`, or `[::1]` literals; otherwise log a warning and ignore
the env var.

### F11 — Wrap `getUniverseDomain` in `withAdcMapping`

**Why:** Every other ADC-touching call in `src/gate/auth.ts` is wrapped
to convert reauth errors into `CredentialsExpiredError` and clear
cached clients. `getUniverseDomain` is not, so it surfaces a generic
500 and leaves the cached source client in place when ADC has been
revoked.

**Change:** Wrap the body in `withAdcMapping`.

## Pre-flight

- [x] Branch `claude/security-audit-tgAEI` already exists and is checked out.
- [x] `mise install` already done in the environment.

## Verification

- `bun run format`
- `bun run lint`
- `bun run typecheck`
- `bun test`

## Documentation updates

- `CHANGELOG.md` — entries under `[Unreleased]` per category.
- `README.md` — admin-socket default path, config precedence note.
- `SPEC.md` — config precedence note, admin-socket default path.
- `config.example.toml` — admin-socket default path comment.
