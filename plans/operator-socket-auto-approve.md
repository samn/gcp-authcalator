# Operator socket: allowlisted auto-approve for human-initiated escalation

## Context

`gcp-authcalator` currently requires interactive confirmation (GUI/TTY/admin-socket
approve) for every prod token request. In a devcontainer where a human operator and
a coding agent share the same machine, that's correct for the agent — but produces
confirmation fatigue for the operator. Fatigued operators dismiss prompts without
reading them, which is a _worse_ security failure mode than no prompt at all.

This plan adds a third Unix socket — the **operator socket** — alongside the
existing main socket and admin socket (the latter introduced in v0.7.2). Requests
on the operator socket auto-approve **iff** the resolved PAM policy is in an
explicit allowlist; everything else returns a clean 403. Trust attaches to the
_socket_ (filesystem permissions decide who reaches it), not to a per-request
extracted UID.

Deployment model: human operator and coding agent run as **different Unix UIDs
inside the same devcontainer**. The operator socket is `0660` group-owned by a
dedicated `operator-group`; the agent UID is forbidden from membership in that
group. The agent continues to use the existing main socket and goes through
the standard confirmation flow.

## Architecture

Three `Bun.serve` instances inside one gate process:

| Socket             | Mode   | Group            | Purpose                                    | Trust           |
| ------------------ | ------ | ---------------- | ------------------------------------------ | --------------- |
| Main               | `0600` | (owner only)     | Token requests from agents and `with-prod` | `trusted=false` |
| Admin              | `0600` | (owner only)     | Approve/deny pending requests              | `trusted=false` |
| **Operator (new)** | `0660` | `operator-group` | Token requests from operator UID           | `trusted=true`  |

A request arriving on the operator socket carries a `RequestContext`
(`{trusted: true, socket: "operator"}`) through the handler chain. In
`acquireProdAccess`, after the existing PAM allowlist check, if
`ctx.trusted && policy ∈ auto_approve_pam_policies`, skip
`confirmProdAccess` entirely and proceed to mint the token.

Sessions (`POST /session`, `GET /token?session=…`) return 403 on the operator
socket. `with-prod` against the operator socket falls back to per-request token
mode — vanilla GCP SDKs in the container never use sessions and are unaffected.

## File-by-file changes

### `src/config.ts`

Add to `ConfigSchema` (after line 82):

- `operator_socket_path: z.string().min(1).transform(expandTilde).optional()` — opt-in; if unset, operator socket is not created.
- `operator_socket_group: z.string().min(1).optional()` — required when `operator_socket_path` is set.
- `auto_approve_pam_policies: z.array(z.string().min(1)).optional()` — defaults to `[]`; nothing auto-approves until populated.
- `agent_uid: z.union([z.number().int().nonnegative(), z.string().min(1)]).optional()` — required when `operator_socket_path` is set. Numeric UID or username.

Add a refinement on `GateConfigSchema` (line 96):

- If `operator_socket_path` is set: `operator_socket_group` AND `agent_uid` MUST be set.
- Every entry in `auto_approve_pam_policies` MUST be in `pam_allowed_policies` (or equal `pam_policy`). Prevents drift where a narrowing of `pam_allowed_policies` leaves an orphan auto-approve entry.

Wire the new keys through `cliToConfigKey` (line 122), `configKeys` (line 168), and env-var loading. Env vars: `GCP_AUTHCALATOR_OPERATOR_SOCKET_PATH`, `GCP_AUTHCALATOR_OPERATOR_SOCKET_GROUP`, `GCP_AUTHCALATOR_AUTO_APPROVE_PAM_POLICIES` (comma-separated), `GCP_AUTHCALATOR_AGENT_UID`.

### `src/gate/types.ts`

Add `RequestContext` type:

```ts
export interface RequestContext {
  trusted: boolean; // request arrived on operator socket
  socket: "main" | "operator" | "tcp" | "admin";
}
```

Extend `AuditEntry` (line 59) with optional fields:

- `auto_approved?: boolean` (only set on the auto-approve path, always `true` when set).
- `socket?: "main" | "operator" | "tcp" | "admin"`.

Add to `GateDeps`:

- `autoApprovePamPolicies?: Set<string>` (empty/undefined = feature off).

### New `src/gate/unix-group.ts`

Pure-function module, ~30 lines. Bun does not expose `getgrnam`; we read `/etc/group` and `/etc/passwd` ourselves. Exports:

```ts
export interface GroupEntry {
  name: string;
  gid: number;
  members: string[];
}
export interface PasswdEntry {
  name: string;
  uid: number;
  gid: number;
}
export function parseGroupFile(content: string): GroupEntry[];
export function parsePasswdFile(content: string): PasswdEntry[];
export function lookupGroup(name: string, file?: string): GroupEntry | undefined;
export function resolveAgentUid(value: number | string): number; // accepts uid or username
export function getGroupsForUid(uid: number, groupFile?: string, passwdFile?: string): number[];
```

`getGroupsForUid` returns primary gid (from `/etc/passwd`) plus all supplementary gids (group entries listing the username as a member). No external deps, no FFI.

### `src/gate/server.ts`

After the admin-socket block (around line 222), add operator-socket setup:

```ts
let operatorServer: ReturnType<typeof Bun.serve> | undefined;
let operatorSocketIno: number | undefined;

if (config.operator_socket_path) {
  // Validation enforced by schema: group and agent_uid are set.
  const grp = lookupGroup(config.operator_socket_group!);
  if (!grp)
    throw new Error(
      `gate: operator socket group '${config.operator_socket_group}' not found in /etc/group`,
    );

  const agentUid = resolveAgentUid(config.agent_uid!);
  if (agentUid === process.getuid!())
    throw new Error(
      `gate: agent_uid (${agentUid}) equals gate uid — operator-socket trust boundary cannot exist`,
    );

  const agentGroups = getGroupsForUid(agentUid);
  if (agentGroups.includes(grp.gid))
    throw new Error(
      `gate: agent uid ${agentUid} is a member of operator group '${grp.name}' — refusing to start. ` +
        `Remove the agent uid from the group, or unset operator_socket_path.`,
    );

  // Stale-socket cleanup mirrors the main/admin pattern (lstat, isSymbolicLink,
  // isSocket, uid check, unlink) — extract a helper to avoid copy-paste.
  const operatorSocketDir = dirname(config.operator_socket_path);
  mkdirSync(operatorSocketDir, { recursive: true, mode: 0o750 });
  chownSync(operatorSocketDir, process.getuid!(), grp.gid);
  cleanStaleSocket(config.operator_socket_path); // shared helper

  operatorServer = Bun.serve({
    unix: config.operator_socket_path,
    fetch(req) {
      return handleRequest(req, deps, { trusted: true, socket: "operator" });
    },
  });

  chownSync(config.operator_socket_path, process.getuid!(), grp.gid);
  chmodSync(config.operator_socket_path, 0o660);
  operatorSocketIno = lstatSync(config.operator_socket_path).ino;
}
```

Update existing `Bun.serve` blocks to pass context:

- Main socket fetch (line 161): `handleRequest(req, deps, { trusted: false, socket: "main" })`.
- TCP+mTLS fetch (line 185): `handleRequest(req, deps, { trusted: false, socket: "tcp" })`.
- Admin socket fetch (line 217): `handleAdminRequest(req, deps, { trusted: false, socket: "admin" })`.

Wire `autoApprovePamPolicies` into `deps` (line 84) — resolve each entry through `resolveEntitlementPath` (matching the `pam_allowed_policies` pattern at lines 75-81) so the comparison in `acquireProdAccess` is on canonical paths.

Extract the stale-socket-cleanup logic into a small local helper to avoid having three near-identical 25-line blocks.

Update `stop()` (line 228) to also close `operatorServer` and inode-protected unlink the operator socket. Update `onSignal` (line 267) — no new work, the existing pendingQueue/sessionManager teardown still applies.

Update startup banner (lines 280-307) to print operator-socket info and an explicit "operator socket: sessions disabled" line so misconfiguration is loud.

### `src/gate/handlers.ts`

Change `handleRequest` (line 21) signature to take `ctx: RequestContext` and thread it through:

- `handleToken` → `handleProdToken` / `handleDevToken` / `handleSessionTokenRefresh`
- `handleCreateSession`, `handleRevokeSession`

In `acquireProdAccess` (line 219), insert auto-approve check **after** the PAM allowlist check (line 261) and **inside** the `try` block after `getIdentityEmail()` (line 281):

```ts
const autoApprove =
  ctx.trusted &&
  effectivePamPolicy !== undefined &&
  deps.autoApprovePamPolicies?.has(effectivePamPolicy) === true;

let approved: boolean;
if (autoApprove) {
  approved = true;
} else {
  approved = await deps.confirmProdAccess(email, commandSummary, effectivePamPolicy, pendingId);
}
```

Tag every audit-write site in `handlers.ts` and `admin-handlers.ts` with `socket: ctx.socket`. On the granted prod path with `autoApprove === true`, also set `auto_approved: true`.

Reject sessions on the operator socket. In `handleCreateSession` (line 414), early return:

```ts
if (ctx.trusted) {
  return jsonResponse({ error: "Session creation not permitted on operator socket" }, 403);
}
```

In `handleSessionTokenRefresh` (line 102), same early return: 403 if `ctx.trusted`. (Defensive — the operator socket cannot create sessions, so no session_id should ever be presented from that socket; but the check makes the invariant explicit.)

Reject `X-Pending-Id` on the auto-approve path: if the request would auto-approve and a `X-Pending-Id` header is present, return 400 — auto-approve never enqueues, so a client-supplied pending ID is meaningless and indicates client confusion.

`handleRevokeSession` (line 492): no behavior change. The audit entry gains `socket: ctx.socket`.

### `src/gate/admin-handlers.ts`

Add `ctx: RequestContext` to `handleAdminRequest`. Pass through to the audit log only.

### `src/with-prod/` and `src/commands/with-prod.ts`

`with-prod` currently calls `createProdSession` first (`fetch-prod-token.ts:117`), then constructs a `SessionTokenProvider`. When pointed at the operator socket, that returns 403 with body `Session creation not permitted on operator socket`. Add fallback in `commands/with-prod.ts` (around line 175):

- On 403 with that error message, log `with-prod: operator socket — falling back to per-request token mode (no session)`.
- Construct a `StaticTokenProvider`-like provider that calls `fetchProdToken` (without `?session=`) on each refresh. If `fetchProdToken` doesn't already exist as a non-session counterpart to `createProdSession`, add it — it's a thin wrapper around `GET /token?level=prod`.

The wrapped subprocess sees no difference: it talks to the inner metadata-proxy as before.

### `src/cli.ts`

Add four new CLI flags to `parseArgs.options` (line 109) and the USAGE block (line 40):

- `--operator-socket-path <path>`
- `--operator-socket-group <name>`
- `--auto-approve-pam-policies <csv>`
- `--agent-uid <uid-or-username>`

Add a one-line warning in USAGE: "Operator-socket auto-approve: the agent UID MUST NOT be a member of the operator group. The gate refuses to start otherwise."

## Permission model (exact rules)

```
operator_socket_dir/        owner=gate-uid  group=operator-gid  mode=0750
operator_socket_dir/op.sock owner=gate-uid  group=operator-gid  mode=0660
```

Connect access requires `uid == gate-uid` OR `operator-gid ∈ caller's groups`.
The agent UID being absent from `operator-gid` is the trust boundary. Enforced at startup by `getGroupsForUid(agent_uid)` against `lookupGroup(operator_socket_group).gid`.

Order of operations on socket creation: `Bun.serve` opens the socket, then `chownSync`, then `chmodSync`. The brief window where the socket has default perms is mitigated by the `0750` directory created and chowned _before_ serving — only owner and operator-group can `cd` into it during that window.

Symlink defenses: identical pattern to main and admin sockets. `lstat` → reject if symlink, reject if not socket, verify uid, then unlink.

## Audit logging

- Every audit entry gains `socket: "main" | "operator" | "tcp" | "admin"`.
- Auto-approved grants gain `auto_approved: true`.
- Find all auto-approvals after the fact: `jq 'select(.auto_approved == true and .socket == "operator")' audit.log`.

Audit-log tamper resistance is **out of scope** and accepted: the gate writes the log with `0600` perms in `~/.gcp-authcalator/`. Under the two-UID model, the agent UID cannot write the log (different owner). The operator UID and the gate UID can. Same risk as today.

## Rate limiting

The existing process-wide `prodRateLimiter` is **shared** across all sockets. Auto-approved requests acquire a slot like any other. Rationale:

- A flooding agent that trips the limiter is a real signal worth surfacing to the operator.
- Auto-approve grants real prod tokens; consuming a slot is correct accounting.
- A second limiter would double the worst-case denial budget.

Trade-off accepted and documented in SPEC.md: the agent UID can starve the operator of prod tokens by exhausting the shared 10/minute budget. The agent already has access to that bucket via the main socket; an attacker UID gains nothing new by spamming.

## Red-team analysis

| Threat                                                                                                                          | Mitigated?                           | How                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Confused-deputy as operator UID (malicious npm postinstall, agent-suggested shell command, planted shell rc, tampered Makefile) | **Partial — accepted.**              | `auto_approve_pam_policies` allowlist caps blast radius. **Anything that runs as the operator UID _is_ the operator from the gate's view.** The plan does not try to fix this; it requires that auto-approve entries are PAM entitlements whose use the operator considers safe to grant on every shell command. Prominent docs requirement. |
| Session leakage                                                                                                                 | **Eliminated structurally.**         | Operator socket cannot create or refresh sessions. No 8-hour bearer credential ever exists from the operator-socket path. (Sessions still exist on main socket; pre-existing risk surface, unchanged.)                                                                                                                                       |
| Group-membership misconfiguration silently disabling boundary                                                                   | **Mitigated.**                       | `agent_uid` is required when operator socket is enabled. Startup verifies `agent_uid`'s groups do not include `operator_socket_group`. Refuse to start otherwise.                                                                                                                                                                            |
| Symlink/race attacks on socket creation                                                                                         | **Mitigated.**                       | Same lstat-isSymbolicLink-isSocket-uid pattern as main and admin sockets. Directory created `0750` and chowned before serving.                                                                                                                                                                                                               |
| Operator socket exists but unreachable (group misconfig, wrong path)                                                            | **Surfaced.**                        | Client gets `EACCES` from connect. `with-prod` connection-error path mentions "verify your UID has access to the gate's operator socket" when path matches `*operator*`.                                                                                                                                                                     |
| TCP+mTLS bypass                                                                                                                 | **Mitigated.**                       | TCP server passes `{trusted: false, socket: "tcp"}`. There is no TCP-mode operator socket. mTLS clients never auto-approve.                                                                                                                                                                                                                  |
| Operator socket bind-mounted with userns remapping that rewrites perms                                                          | **Documented as setup requirement.** | Bind-mounts that change ownership/perms break the boundary silently. Setup guide forbids this.                                                                                                                                                                                                                                               |
| Replay of an auto-approved request through the agent socket                                                                     | **Not applicable.**                  | Tokens are minted server-side and returned over the originating request. No replayable artifact.                                                                                                                                                                                                                                             |
| Pending-queue self-approval via operator socket                                                                                 | **Not applicable.**                  | Auto-approve doesn't enqueue. Admin socket is independent.                                                                                                                                                                                                                                                                                   |

## Setup requirements (operator's responsibility — must appear in README)

1. Create a dedicated Unix group (e.g. `gcp-operators`). Do **not** reuse `wheel`, `staff`, or anyone's primary group.
2. Add **only** the operator UID to this group. Never the agent UID. Never `root`.
3. Run the gate as a UID separate from the agent UID. Same UID as the operator is acceptable; same UID as the agent is forbidden (gate refuses to start).
4. Set `agent_uid` in the gate config. The gate's startup misconfiguration check requires it.
5. Keep `auto_approve_pam_policies` minimal. Treat additions with the same review rigor as IAM policy changes — anything in this list is granted by _any_ code that runs as the operator UID, including malicious code planted via the operator's tooling.
6. Pipe `~/.gcp-authcalator/audit.log` to a SIEM. Auto-approvals are tagged `auto_approved: true, socket: "operator"`. The gate makes no attempt at write-protection; observability is the user's job.
7. Do not run the devcontainer with userns-remapping that rewrites file ownership.
8. Operator socket is **Unix-only**. Remote (TCP+mTLS) operators do not get auto-approve.

## Verification

End-to-end:

1. `bun run typecheck && bun run lint && bun test` — all green.
2. New unit tests:
   - `src/__tests__/gate/unix-group.test.ts` — `parseGroupFile`, `parsePasswdFile`, `getGroupsForUid` (skip blank/comment lines, multi-member groups, primary-gid only, supplementary gids).
   - `src/__tests__/gate/handlers.test.ts` — operator socket happy path (auto-approves, no `confirmProdAccess` call, audit entry has `auto_approved: true`); operator socket + non-allowlisted policy (403); operator socket + `POST /session` (403); operator socket + `GET /token?session=...` (403); main socket + allowlisted policy still calls `confirmProdAccess`; rate limiter is shared (11th request hits cap regardless of socket).
   - `src/__tests__/gate/server.test.ts` — startup with operator socket creates `0660` socket with correct gid; refuse-to-start when group missing, when `agent_uid` missing, when `agent_uid == gate-uid`, when agent UID is in operator group; symlink at operator path refused; shutdown unlinks operator socket inode-protected.
3. Manual end-to-end (recorded in PR description):
   - Boot a devcontainer with two users (e.g. `vscode` UID 1000 and `claude` UID 1001), put `vscode` in group `gcp-operators`.
   - Start gate with `--operator-socket-path` and `--auto-approve-pam-policies <policy>`.
   - As `vscode`: `with-prod gcloud auth print-access-token` against operator socket → no prompt, audit log shows `auto_approved: true`.
   - As `claude`: `gcloud auth print-access-token` against main socket → dev token (no prompt path needed).
   - As `claude`: attempt `with-prod` against main socket → confirmation dialog appears as today.
   - As `claude`: attempt to connect to operator socket path → `EACCES`.
   - With `claude` accidentally added to `gcp-operators`: gate refuses to start with explicit error.

## Documentation updates (mandated by AGENTS.md)

- `README.md` — new section "Operator socket (auto-approve)" with the threat-model trade-off, setup requirements (1-8 above), and `agent_uid` / group setup.
- `SPEC.md` — new "Operator socket" subsection: rationale for two-socket architecture vs. SO_PEERCRED, rejected alternatives, rate-limit and session decisions, accepted residual threats.
- `config.example.toml` — document `operator_socket_path`, `operator_socket_group`, `auto_approve_pam_policies`, `agent_uid` with prominent warning about agent-UID-in-group.
- `src/cli.ts` USAGE — document the four new flags.
- `CHANGELOG.md` — `[Unreleased]` entries under `Added` ("operator socket for allowlisted auto-approve") and `Security` ("session creation rejected on operator socket; startup misconfig check for agent UID in operator group").

## Rejected alternatives (brief)

- **SO_PEERCRED + per-request UID extraction.** `Bun.serve({unix})` does not expose peer creds; would require dropping to raw `Bun.listen()` or `node:http`. Filesystem perms are required anyway for defense-in-depth, making SO_PEERCRED redundant.
- **Single socket with header-based "I am operator" claim.** Trivially forgeable.
- **Separate `GateDeps` per socket.** Would need to thread the resolved PAM policy into a per-socket `confirmProdAccess` impl, which puts allowlist logic in the wrong layer. `RequestContext` plumbing keeps allowlist + decision in `acquireProdAccess`.
- **Wildcard `auto_approve_pam_policies = ["*"]`.** Just "auto-approve everything" with extra steps.
- **Short-lived sessions on operator socket (e.g. 15 min).** A 15-minute bearer token is still a stealable credential; per-request auto-approve is strictly stronger and the UX gap is negligible.
- **Separate rate limiter for operator socket.** Doubles worst-case denial budget; the shared limiter's "agent flood reaches operator's next request" behavior is itself a useful signal.
- **Hooks-based external trust hook.** Punts the security design to the user; no safe defaults shippable.
- **Just don't add the feature; make the prompt faster.** Defensible position. Rejected because the user has explicitly weighed confirmation fatigue and chosen this trade-off; the design narrows blast radius (allowlist + no sessions + group enforcement) to keep it survivable.

## Critical files

- `src/gate/server.ts`
- `src/gate/handlers.ts`
- `src/gate/admin-handlers.ts`
- `src/gate/types.ts`
- `src/gate/unix-group.ts` _(new)_
- `src/config.ts`
- `src/cli.ts`
- `src/commands/with-prod.ts`
- `src/with-prod/fetch-prod-token.ts`
- `README.md`, `SPEC.md`, `config.example.toml`, `CHANGELOG.md`
