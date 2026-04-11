- Use `mise` to manage the toolchain for this project to ensure a consistent development environment. Pin versions.
- Install precommit checks when setting up a new environment (after installing tools with `mise`) by running `prek install`
- Use `bun` to test and run this project
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

## Documentation

When making changes that affect user-facing behavior, CLI flags, endpoints,
configuration options, or security properties, update **all** relevant
documentation to stay in sync with the implementation:

- `README.md` — primary user guide (CLI flags, env vars, API tables, examples,
  security model)
- `SPEC.md` — technical specification (architecture, API tables, design
  decisions)
- `config.example.toml` — reference configuration with all options
- `docs/releasing.md` — release process
- CLI `--help` output in `src/cli.ts`

Verify that documented values (rate limits, timeouts, defaults, ID formats)
match the actual constants and code. Stale documentation is a security risk in
a security-focused project.

## Pre-commit checks

Before committing code, always run the full verification suite:

1. `bun run format` — auto-fix formatting with oxfmt
2. `bun run lint` — run oxlint (also auto-fixes via prek)
3. `bun run typecheck` — ensure no type errors
4. `bun test` — ensure all tests pass and that coverage is adequate
