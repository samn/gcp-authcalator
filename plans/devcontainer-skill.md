# Plan: Devcontainer Setup Skill

## Goal

Create a Claude Code skill (`.claude/commands/devcontainer-setup.md`) that users
can invoke via `/devcontainer-setup` to add gcp-authcalator to a project's
devcontainer configuration. The skill should work with both plain
devcontainer.json and docker-compose setups.

## Design Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Container user | Detect from devcontainer.json, prompt if not found | Flexible for any setup |
| Version | Hardcode current version (0.1.5), offer override | Reliable without network; update on release |
| socat | Check and install if missing | Support various base images |
| Kube setup | Optional, ask user | Not all projects use GKE |
| Binary storage | Both in `~/.gcp-authcalator/bin/` with platform names | Shared via volume mount, no container download |
| Gate config | `~/.gcp-authcalator/config.toml` (created by skill) | Shared across projects, mounted into container |
| GitHub repo | `samn/gcp-authcalator` | Official releases |

## Files Created

1. **`.claude/commands/devcontainer-setup.md`** - The skill prompt
2. **`plans/devcontainer-skill.md`** - This plan
3. **`CHANGELOG.md`** - Updated with entry

## Skill Workflow

1. Analyze existing `.devcontainer/` setup (json, compose, scripts)
2. Detect container user from `remoteUser` in devcontainer.json
3. Verify host prerequisites (ADC, service account, config file)
4. Create `initialize.sh` (host): download both host + linux-amd64 binaries,
   start gate with crash recovery
5. Create `post-start.sh` (container): use shared linux-amd64 binary, install
   socat, start metadata-proxy + socat with crash recovery
6. Modify devcontainer.json (or docker-compose.yml) with volume mount, env vars,
   and lifecycle commands
7. Optional: set up GKE kubectl integration
8. Provide verification checklist

## Daemon Restart Strategy

Both gate (host) and metadata-proxy + socat (container) use a bash while-loop
wrapper with 2-second delay between restarts. Each script checks if the daemon
is already running before starting a new instance (health check for gate,
port check for proxy, ss for socat).

## Key Edge Cases

- Existing lifecycle commands: merge, don't overwrite (ask user)
- Docker-compose: volumes and env go in compose file, lifecycle in devcontainer.json
- Multiple compose services: ask user which service
- No devcontainer at all: ask user before creating from scratch
- Config file missing: guide user to create it
- Host platform detection: macOS ARM64 vs Linux x86_64
