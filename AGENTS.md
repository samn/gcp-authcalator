## Environment setup

**IMPORTANT: Always set up the development environment before doing any work.**
Run these commands at the start of every session if tools are not yet available:

```bash
mise install        # Install pinned tool versions (bun, prek)
bun install         # Install project dependencies
prek install        # Install pre-commit hooks (runs automatically on git commit)
```

Use `mise` to manage the toolchain. Pin versions. Use `bun` to test and run
this project.

## Guidelines

- Make sure that all types compile without warnings.
- Write tests for all functionality that you create. The tests should be robust and reliable.
- Minimize complexity wherever possible, simplicity is what makes this secure.
- Use the latest versions of all dependencies and tools, this should be a modern project with no baggage.
- Fix all warnings when you see them
- Ask the user for clarifications if anything is unclear. DO NOT MAKE ASSUMPTIONS!
- Save the plan you're working on as markdown in plans/

## Changelog

All user-facing changes must be documented in `CHANGELOG.md` following the
[Keep a Changelog](https://keepachangelog.com/) format. Add entries under the
`[Unreleased]` section as you make changes. Categories: Added, Changed,
Deprecated, Removed, Fixed, Security.

## Pre-commit checks

**MANDATORY: Always run the full verification suite before every commit.** These
are the same checks that CI runs — if you skip them, CI will fail.

1. `bun run format` — auto-fix formatting with oxfmt
2. `bun run lint` — run oxlint (also auto-fixes via prek)
3. `bun run typecheck` — ensure no type errors
4. `bun test` — ensure all tests pass and that coverage is adequate

If `prek`, `bun`, or `oxfmt` are not available, run `mise install && bun install`
first (see Environment setup above).
