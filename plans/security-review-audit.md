# Security Review & Audit — 2026-03-17

## Spec Soundness

The architecture is **sound and well-designed**. The core security property — credentials
never enter the container, only short-lived scoped tokens — mirrors battle-tested patterns
like GKE workload identity. Key design decisions are defensible:

- **GCE metadata emulation**: transparent to all Google Cloud libraries, `Metadata-Flavor`
  header provides SSRF protection
- **Unix domain socket**: 0600 in 0700 directory is a hard OS-level boundary
- **mTLS for remote**: mutual authentication, no shared secrets in transit, pinned CA
- **Human-in-the-loop for prod**: rate-limited confirmation prevents automated abuse

## What's done well

- **Socket security** (`server.ts:62-103`): symlink refusal, ownership verification,
  socket-type check, live-instance detection before cleanup
- **Environment stripping** (`with-prod.ts:30-44`): comprehensive removal of all known
  credential env vars (7 total)
- **Token file over env var** (`with-prod.ts:184-190`): avoids `/proc/*/environ` exposure
- **PID-based process restriction** (`pid-validator.ts`): `/proc/net/tcp` → inode → PID →
  PPid chain with 256-depth limit
- **TLS cert validation** (`store.ts`): checks parse, expiry, issuer match, and
  cryptographic signature for the full chain
- **osascript injection prevention** (`confirm.ts:82-83`): backslash-then-quote escaping
  order is correct
- **`--no-markup` on zenity**: prevents Pango markup injection
- **Secret redaction** (`summarize-command.ts`): strips control chars, redacts base64 and
  sensitive key=value pairs
- **TLS bundle cleanup** (`bundle.ts:25`): deletes env var after read to prevent
  inheritance
- **Inode-based socket cleanup** (`server.ts:139,155`): prevents removing a replacement
  instance's socket
- **gate_url requires https://**: Zod validation at config parse time prevents plaintext

## Issues found and fixed

### 1. Rate limiter constants weaker than documented (medium severity)

The SPEC and code comments specified 5s cooldown and max 5 attempts per window, but the
actual constants were 1s cooldown and 10 attempts. This allowed 2x more brute-force
attempts than the documented security posture permitted.

**Fix**: Updated `DENIAL_COOLDOWN_MS` from 1000 → 5000 and `MAX_ATTEMPTS_PER_WINDOW` from
10 → 5 in `src/gate/rate-limit.ts`.

### 2. SPEC config precedence was wrong (documentation)

SPEC said "CLI args > TOML file > env vars" but the code and README correctly implement
"env vars > CLI args > TOML file".

**Fix**: Updated SPEC.md to match the actual (correct) precedence.

## Issues reviewed and not concerning

- **TOCTOU in socket creation**: mitigated by 0700 directory; cross-user attacks can't
  reach socket path
- **PID validation TOCTOU**: requires attacker to close/reopen connection from same port
  with different PID in the same procfs read window; acceptable risk
- **Single client certificate, no revocation**: 90-day expiry + gate binds 127.0.0.1;
  documented limitation
- **X-Wrapped-Command spoofing**: dialog says "Reported command"; trust decision is "do
  I expect any prod access right now"
- **No EKU enforcement on client cert**: server key stays on host with gate; no
  cross-boundary concern
- **Audit log file permissions**: parent directory is 0700 regardless
- **Token in error messages**: only reaches authenticated clients via Unix socket or mTLS
- **Prod token not revocable**: 1-hour expiry is the mitigation; documented limitation
- **Token file survives SIGKILL**: expires in ~1 hour, stored in 0700 directory

## Threat model boundaries (acknowledged)

Per the project's documented security model:

- Same-user attackers with ptrace/`/proc/*/mem` access can extract tokens — out of scope
- Stolen client bundle (remote mode) usable for 90 days — documented limitation
- Prod token expires in ~1 hour, cannot be revoked early — documented limitation
