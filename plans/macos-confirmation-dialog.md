macOS Desktop Confirmation Dialog

Context

The gcp-gate daemon shows a GUI confirmation dialog when a process requests production-level GCP credentials. Currently this only works on Linux (using zenity). Since we develop on macOS too, we need an equivalent native dialog using osascript (AppleScript), which is built-in on all macOS versions.

Approach

Use osascript with AppleScript’s display dialog command. An AppleScript that explicitly errors on deny/timeout maps cleanly to the same exit code convention as zenity (0=approved, 1=denied, 127=not found).

Only two files need changes — the confirm module and its tests. No interface or wiring changes needed since confirmProdAccess signature stays the same.

Changes

1. src/gate/confirm.ts — Add tryOsascript + platform routing
   Add platform to ConfirmOptions for testability:

export interface ConfirmOptions {
spawn?: SpawnFn;
platform?: string; // Override process.platform for testing
}
Add platform dispatch in confirmProdAccess:

const platform = options.platform ?? process.platform;
const tryGui = platform === "darwin" ? tryOsascript : tryZenity;
Add tryOsascript function (~20 lines) following tryZenity pattern:

Escape email for AppleScript safety: email.replace(/\\/g, "\\\\").replace(/"/g, '\\"')
Spawn osascript with two -e flags:
display dialog "Grant prod-level GCP access to <email>?" buttons {"Deny", "Allow"} default button "Deny" with icon caution giving up after 60
if button returned of r is not "Allow" or gave up of r is true then error "denied"
Exit code mapping: 0→true, 1→false, 127→null (same as zenity) 2. src/**tests**/gate/confirm.test.ts — Add macOS tests
Using existing mockSpawn helper + new platform: "darwin" option:

osascript exit codes: exit 0 → true, exit 1 → false
osascript not found: exit 127 + no TTY → false
argument verification: spawns osascript with -e flag, includes email and display dialog
AppleScript escaping: double quotes and backslashes in email are properly escaped
platform routing: darwin → osascript, linux → zenity
Files to modify

File Change
src/gate/confirm.ts Add platform option, tryOsascript, platform dispatch
src/**tests**/gate/confirm.test.ts Add ~6 new test cases for macOS
No changes to: types.ts, server.ts, handlers.ts — the confirmProdAccess signature is unchanged.

Verification

bun run typecheck — no type errors
bun run lint — no lint warnings
bun run format — formatting clean
bun test — all existing + new tests pass
Manual test on macOS: run gcp-gate and request a prod token — native dialog should appear
