import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { z } from "zod";
import { homedir } from "node:os";
import {
  ConfigSchema,
  GateConfigSchema,
  MetadataProxyConfigSchema,
  WithProdConfigSchema,
  expandTilde,
  getDefaultSocketPath,
  getDefaultWithProdRuntimeDir,
  loadConfig,
  loadEnvVars,
  loadTOML,
  mapCliArgs,
} from "../config.ts";

// ---------------------------------------------------------------------------
// expandTilde
// ---------------------------------------------------------------------------

describe("expandTilde", () => {
  const home = homedir();

  test("expands bare ~ to home directory", () => {
    expect(expandTilde("~")).toBe(home);
  });

  test("expands ~/ prefix to home directory", () => {
    expect(expandTilde("~/.gcp-authcalator/sock")).toBe(join(home, ".gcp-authcalator/sock"));
  });

  test("leaves absolute paths unchanged", () => {
    expect(expandTilde("/tmp/gate.sock")).toBe("/tmp/gate.sock");
  });

  test("leaves relative paths unchanged", () => {
    expect(expandTilde("relative/path.sock")).toBe("relative/path.sock");
  });

  test("does not expand ~ in the middle of a path", () => {
    expect(expandTilde("/foo/~/bar")).toBe("/foo/~/bar");
  });

  test("does not expand ~user syntax", () => {
    expect(expandTilde("~other/.gcp-authcalator")).toBe("~other/.gcp-authcalator");
  });
});

// ---------------------------------------------------------------------------
// getDefaultWithProdRuntimeDir
// ---------------------------------------------------------------------------

describe("getDefaultWithProdRuntimeDir", () => {
  let savedRuntimeDir: string | undefined;
  let savedCacheHome: string | undefined;

  beforeEach(() => {
    savedRuntimeDir = process.env.XDG_RUNTIME_DIR;
    savedCacheHome = process.env.XDG_CACHE_HOME;
    delete process.env.XDG_RUNTIME_DIR;
    delete process.env.XDG_CACHE_HOME;
  });

  afterEach(() => {
    if (savedRuntimeDir !== undefined) process.env.XDG_RUNTIME_DIR = savedRuntimeDir;
    else delete process.env.XDG_RUNTIME_DIR;
    if (savedCacheHome !== undefined) process.env.XDG_CACHE_HOME = savedCacheHome;
    else delete process.env.XDG_CACHE_HOME;
  });

  test("uses $XDG_RUNTIME_DIR when set (canonical per-user runtime dir)", () => {
    process.env.XDG_RUNTIME_DIR = "/run/user/1500";
    expect(getDefaultWithProdRuntimeDir()).toBe("/run/user/1500");
  });

  test("falls back to $XDG_CACHE_HOME/gcp-authcalator when only that is set", () => {
    process.env.XDG_CACHE_HOME = "/custom/cache";
    expect(getDefaultWithProdRuntimeDir()).toBe("/custom/cache/gcp-authcalator");
  });

  test("falls back to ~/.cache/gcp-authcalator when neither is set", () => {
    expect(getDefaultWithProdRuntimeDir()).toBe(join(homedir(), ".cache", "gcp-authcalator"));
  });

  test("prefers $XDG_RUNTIME_DIR over $XDG_CACHE_HOME when both are set", () => {
    process.env.XDG_RUNTIME_DIR = "/run/user/1500";
    process.env.XDG_CACHE_HOME = "/custom/cache";
    expect(getDefaultWithProdRuntimeDir()).toBe("/run/user/1500");
  });

  test("is independent of the gate's runtime dir (different default location)", () => {
    // Sanity check: the gate's default is ~/.gcp-authcalator/; with-prod's
    // is ~/.cache/gcp-authcalator/. They must NOT collide on the same
    // path, otherwise the symlink-shared-gate setup re-breaks.
    const withProd = getDefaultWithProdRuntimeDir();
    expect(withProd).not.toBe(join(homedir(), ".gcp-authcalator"));
  });
});

// ---------------------------------------------------------------------------
// ConfigSchema
// ---------------------------------------------------------------------------

describe("ConfigSchema", () => {
  test("applies defaults when no values provided", () => {
    const config = ConfigSchema.parse({});
    expect(config.socket_path).toBe(getDefaultSocketPath());
    expect(config.port).toBe(8173);
    expect(config.project_id).toBeUndefined();
    expect(config.service_account).toBeUndefined();
  });

  test("accepts valid full config", () => {
    const config = ConfigSchema.parse({
      project_id: "my-project",
      service_account: "sa@my-project.iam.gserviceaccount.com",
      socket_path: "/tmp/gate.sock",
      port: 9090,
    });
    expect(config.project_id).toBe("my-project");
    expect(config.service_account).toBe("sa@my-project.iam.gserviceaccount.com");
    expect(config.socket_path).toBe("/tmp/gate.sock");
    expect(config.port).toBe(9090);
  });

  test("coerces port from string to number", () => {
    const config = ConfigSchema.parse({ port: "4000" });
    expect(config.port).toBe(4000);
  });

  test("rejects invalid port (too high)", () => {
    expect(() => ConfigSchema.parse({ port: 70000 })).toThrow(z.ZodError);
  });

  test("rejects invalid port (zero)", () => {
    expect(() => ConfigSchema.parse({ port: 0 })).toThrow(z.ZodError);
  });

  test("rejects invalid port (non-numeric string)", () => {
    expect(() => ConfigSchema.parse({ port: "abc" })).toThrow(z.ZodError);
  });

  test("rejects empty project_id", () => {
    expect(() => ConfigSchema.parse({ project_id: "" })).toThrow(z.ZodError);
  });

  test("rejects invalid service_account (not email)", () => {
    expect(() => ConfigSchema.parse({ service_account: "not-an-email" })).toThrow(z.ZodError);
  });

  test("rejects empty socket_path", () => {
    expect(() => ConfigSchema.parse({ socket_path: "" })).toThrow(z.ZodError);
  });

  test("expands ~ in socket_path", () => {
    const config = ConfigSchema.parse({ socket_path: "~/.gcp-authcalator/my.sock" });
    expect(config.socket_path).toBe(join(homedir(), ".gcp-authcalator/my.sock"));
  });

  test("expands bare ~ in socket_path", () => {
    const config = ConfigSchema.parse({ socket_path: "~" });
    expect(config.socket_path).toBe(homedir());
  });

  test("accepts valid gate_tls_port", () => {
    const config = ConfigSchema.parse({ gate_tls_port: 8174 });
    expect(config.gate_tls_port).toBe(8174);
  });

  test("gate_tls_port is optional", () => {
    const config = ConfigSchema.parse({});
    expect(config.gate_tls_port).toBeUndefined();
  });

  test("rejects invalid gate_tls_port", () => {
    expect(() => ConfigSchema.parse({ gate_tls_port: 0 })).toThrow(z.ZodError);
    expect(() => ConfigSchema.parse({ gate_tls_port: 70000 })).toThrow(z.ZodError);
  });

  test("gate_url must use https://", () => {
    expect(() => ConfigSchema.parse({ gate_url: "http://localhost:8174" })).toThrow(z.ZodError);
  });

  test("accepts valid https gate_url", () => {
    const config = ConfigSchema.parse({ gate_url: "https://localhost:8174" });
    expect(config.gate_url).toBe("https://localhost:8174");
  });

  test("gate_url is optional", () => {
    const config = ConfigSchema.parse({});
    expect(config.gate_url).toBeUndefined();
  });

  test("expands ~ in tls_dir", () => {
    const config = ConfigSchema.parse({ tls_dir: "~/.tls" });
    expect(config.tls_dir).toBe(join(homedir(), ".tls"));
  });

  test("expands ~ in tls_bundle", () => {
    const config = ConfigSchema.parse({ tls_bundle: "~/.tls/bundle.pem" });
    expect(config.tls_bundle).toBe(join(homedir(), ".tls/bundle.pem"));
  });

  test("accepts scopes array", () => {
    const config = ConfigSchema.parse({
      scopes: [
        "https://www.googleapis.com/auth/sqlservice.login",
        "https://www.googleapis.com/auth/cloud-platform",
      ],
    });
    expect(config.scopes).toEqual([
      "https://www.googleapis.com/auth/sqlservice.login",
      "https://www.googleapis.com/auth/cloud-platform",
    ]);
  });

  test("allows undefined scopes", () => {
    const config = ConfigSchema.parse({});
    expect(config.scopes).toBeUndefined();
  });

  test("rejects scopes with empty strings", () => {
    expect(() => ConfigSchema.parse({ scopes: [""] })).toThrow(z.ZodError);
  });

  test("rejects non-array scopes", () => {
    expect(() => ConfigSchema.parse({ scopes: "not-an-array" })).toThrow(z.ZodError);
  });

  test("accepts token_ttl_seconds within valid range", () => {
    const config = ConfigSchema.parse({ token_ttl_seconds: 1800 });
    expect(config.token_ttl_seconds).toBe(1800);
  });

  test("coerces string token_ttl_seconds to number", () => {
    const config = ConfigSchema.parse({ token_ttl_seconds: "900" });
    expect(config.token_ttl_seconds).toBe(900);
  });

  test("allows undefined token_ttl_seconds", () => {
    const config = ConfigSchema.parse({});
    expect(config.token_ttl_seconds).toBeUndefined();
  });

  test("accepts minimum token_ttl_seconds of 60", () => {
    const config = ConfigSchema.parse({ token_ttl_seconds: 60 });
    expect(config.token_ttl_seconds).toBe(60);
  });

  test("accepts maximum token_ttl_seconds of 43200", () => {
    const config = ConfigSchema.parse({ token_ttl_seconds: 43200 });
    expect(config.token_ttl_seconds).toBe(43200);
  });

  test("rejects token_ttl_seconds below 60", () => {
    expect(() => ConfigSchema.parse({ token_ttl_seconds: 30 })).toThrow(z.ZodError);
  });

  test("rejects token_ttl_seconds above 43200", () => {
    expect(() => ConfigSchema.parse({ token_ttl_seconds: 50000 })).toThrow(z.ZodError);
  });

  test("rejects non-integer token_ttl_seconds", () => {
    expect(() => ConfigSchema.parse({ token_ttl_seconds: 3.5 })).toThrow(z.ZodError);
  });
});

// ---------------------------------------------------------------------------
// Command-specific schemas
// ---------------------------------------------------------------------------

describe("GateConfigSchema", () => {
  test("requires project_id and service_account", () => {
    expect(() => GateConfigSchema.parse({})).toThrow(z.ZodError);
  });

  test("rejects missing project_id", () => {
    expect(() =>
      GateConfigSchema.parse({ service_account: "sa@proj.iam.gserviceaccount.com" }),
    ).toThrow(z.ZodError);
  });

  test("rejects missing service_account", () => {
    expect(() => GateConfigSchema.parse({ project_id: "my-proj" })).toThrow(z.ZodError);
  });

  test("accepts valid gate config", () => {
    const config = GateConfigSchema.parse({
      project_id: "my-proj",
      service_account: "sa@proj.iam.gserviceaccount.com",
    });
    expect(config.project_id).toBe("my-proj");
    expect(config.service_account).toBe("sa@proj.iam.gserviceaccount.com");
    expect(config.socket_path).toBe(getDefaultSocketPath());
  });

  test("accepts operator_socket_path without operator_socket_group (UID mode)", () => {
    const config = GateConfigSchema.parse({
      project_id: "my-proj",
      service_account: "sa@proj.iam.gserviceaccount.com",
      operator_socket_path: "/tmp/op.sock",
      agent_uid: 1001,
    });
    expect(config.operator_socket_path).toBe("/tmp/op.sock");
    expect(config.operator_socket_group).toBeUndefined();
    expect(config.agent_uid).toBe(1001);
  });

  test("rejects operator_socket_path without agent_uid", () => {
    expect(() =>
      GateConfigSchema.parse({
        project_id: "my-proj",
        service_account: "sa@proj.iam.gserviceaccount.com",
        operator_socket_path: "/tmp/op.sock",
        operator_socket_group: "operators",
      }),
    ).toThrow(z.ZodError);
  });

  test("accepts complete operator-socket config in group mode", () => {
    const config = GateConfigSchema.parse({
      project_id: "my-proj",
      service_account: "sa@proj.iam.gserviceaccount.com",
      operator_socket_path: "/tmp/op.sock",
      operator_socket_group: "operators",
      agent_uid: 1001,
      pam_policy: "projects/p/locations/global/entitlements/x",
      auto_approve_pam_policies: ["projects/p/locations/global/entitlements/x"],
    });
    expect(config.operator_socket_path).toBe("/tmp/op.sock");
    expect(config.operator_socket_group).toBe("operators");
    expect(config.agent_uid).toBe(1001);
  });

  test("rejects auto_approve_pam_policies entry not in pam_allowed_policies", () => {
    expect(() =>
      GateConfigSchema.parse({
        project_id: "my-proj",
        service_account: "sa@proj.iam.gserviceaccount.com",
        pam_policy: "projects/p/locations/global/entitlements/a",
        pam_allowed_policies: ["projects/p/locations/global/entitlements/a"],
        auto_approve_pam_policies: ["projects/p/locations/global/entitlements/b"],
      }),
    ).toThrow(z.ZodError);
  });

  test("accepts auto_approve_pam_policies that matches pam_policy default", () => {
    const config = GateConfigSchema.parse({
      project_id: "my-proj",
      service_account: "sa@proj.iam.gserviceaccount.com",
      pam_policy: "projects/p/locations/global/entitlements/a",
      auto_approve_pam_policies: ["projects/p/locations/global/entitlements/a"],
    });
    expect(config.auto_approve_pam_policies).toEqual([
      "projects/p/locations/global/entitlements/a",
    ]);
  });

  test("agent_uid accepts a username string", () => {
    const config = GateConfigSchema.parse({
      project_id: "my-proj",
      service_account: "sa@proj.iam.gserviceaccount.com",
      operator_socket_path: "/tmp/op.sock",
      operator_socket_group: "operators",
      agent_uid: "claude",
    });
    expect(config.agent_uid).toBe("claude");
  });
});

describe("MetadataProxyConfigSchema", () => {
  test("requires project_id", () => {
    expect(() => MetadataProxyConfigSchema.parse({})).toThrow(z.ZodError);
  });

  test("accepts valid config with project_id", () => {
    const config = MetadataProxyConfigSchema.parse({ project_id: "my-proj" });
    expect(config.project_id).toBe("my-proj");
    expect(config.port).toBe(8173);
  });
});

describe("WithProdConfigSchema", () => {
  test("requires project_id", () => {
    expect(() => WithProdConfigSchema.parse({})).toThrow(z.ZodError);
  });

  test("accepts valid config with project_id", () => {
    const config = WithProdConfigSchema.parse({ project_id: "my-proj" });
    expect(config.project_id).toBe("my-proj");
  });
});

// ---------------------------------------------------------------------------
// mapCliArgs
// ---------------------------------------------------------------------------

describe("mapCliArgs", () => {
  test("maps kebab-case CLI keys to snake_case config keys", () => {
    const result = mapCliArgs({
      "project-id": "my-proj",
      "service-account": "sa@proj.iam.gserviceaccount.com",
      "socket-path": "/tmp/gate.sock",
      port: "9090",
    });
    expect(result).toEqual({
      project_id: "my-proj",
      service_account: "sa@proj.iam.gserviceaccount.com",
      socket_path: "/tmp/gate.sock",
      port: "9090",
    });
  });

  test("skips undefined values", () => {
    const result = mapCliArgs({
      "project-id": "my-proj",
      "service-account": undefined,
    });
    expect(result).toEqual({ project_id: "my-proj" });
  });

  test("ignores unknown keys", () => {
    const result = mapCliArgs({ config: "/some/path", help: true });
    expect(result).toEqual({});
  });

  test("maps new TLS-related CLI keys", () => {
    const result = mapCliArgs({
      "gate-tls-port": "8174",
      "tls-dir": "~/.tls",
      "gate-url": "https://localhost:8174",
      "tls-bundle": "/path/to/bundle.pem",
    });
    expect(result).toEqual({
      gate_tls_port: "8174",
      tls_dir: "~/.tls",
      gate_url: "https://localhost:8174",
      tls_bundle: "/path/to/bundle.pem",
    });
  });

  test("splits comma-separated scopes string into array", () => {
    const result = mapCliArgs({
      scopes:
        "https://www.googleapis.com/auth/sqlservice.login,https://www.googleapis.com/auth/cloud-platform",
    });
    expect(result).toEqual({
      scopes: [
        "https://www.googleapis.com/auth/sqlservice.login",
        "https://www.googleapis.com/auth/cloud-platform",
      ],
    });
  });

  test("handles single scope string", () => {
    const result = mapCliArgs({
      scopes: "https://www.googleapis.com/auth/sqlservice.login",
    });
    expect(result).toEqual({
      scopes: ["https://www.googleapis.com/auth/sqlservice.login"],
    });
  });

  test("maps token-ttl-seconds to token_ttl_seconds", () => {
    const result = mapCliArgs({ "token-ttl-seconds": "1800" });
    expect(result).toEqual({ token_ttl_seconds: "1800" });
  });
});

// ---------------------------------------------------------------------------
// loadTOML
// ---------------------------------------------------------------------------

describe("loadTOML", () => {
  test("reads and parses a TOML file", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(
      filePath,
      `project_id = "toml-project"\nservice_account = "sa@toml.iam.gserviceaccount.com"\nport = 4000\n`,
    );
    const result = loadTOML(filePath);
    expect(result.project_id).toBe("toml-project");
    expect(result.service_account).toBe("sa@toml.iam.gserviceaccount.com");
    expect(result.port).toBe(4000);
  });

  test("throws on missing file", () => {
    expect(() => loadTOML("/nonexistent/config.toml")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// loadEnvVars
// ---------------------------------------------------------------------------

describe("loadEnvVars", () => {
  /** Helper to run a callback with env vars set, then restore originals. */
  function withEnv(vars: Record<string, string>, fn: () => void) {
    const originals: Record<string, string | undefined> = {};
    for (const key of Object.keys(vars)) {
      originals[key] = process.env[key];
      process.env[key] = vars[key];
    }
    try {
      fn();
    } finally {
      for (const [key, orig] of Object.entries(originals)) {
        if (orig === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = orig;
        }
      }
    }
  }

  test("reads all supported config keys from env vars", () => {
    withEnv(
      {
        GCP_AUTHCALATOR_PROJECT_ID: "env-project",
        GCP_AUTHCALATOR_SERVICE_ACCOUNT: "sa@env.iam.gserviceaccount.com",
        GCP_AUTHCALATOR_SOCKET_PATH: "/env/path.sock",
        GCP_AUTHCALATOR_PORT: "9999",
        GCP_AUTHCALATOR_GATE_TLS_PORT: "8174",
        GCP_AUTHCALATOR_TLS_DIR: "/env/tls",
        GCP_AUTHCALATOR_GATE_URL: "https://env.example.com",
        GCP_AUTHCALATOR_TLS_BUNDLE: "/env/bundle.pem",
        GCP_AUTHCALATOR_TOKEN_TTL_SECONDS: "1800",
      },
      () => {
        const result = loadEnvVars();
        expect(result).toEqual({
          project_id: "env-project",
          service_account: "sa@env.iam.gserviceaccount.com",
          socket_path: "/env/path.sock",
          port: "9999",
          gate_tls_port: "8174",
          tls_dir: "/env/tls",
          gate_url: "https://env.example.com",
          tls_bundle: "/env/bundle.pem",
          token_ttl_seconds: "1800",
        });
      },
    );
  });

  test("skips unset env vars", () => {
    withEnv({ GCP_AUTHCALATOR_PROJECT_ID: "env-project" }, () => {
      const result = loadEnvVars();
      expect(result.project_id).toBe("env-project");
      expect(result.port).toBeUndefined();
    });
  });

  test("returns empty object when no env vars set", () => {
    const result = loadEnvVars();
    // We can't guarantee no GCP_AUTHCALATOR_* vars are set in the
    // test environment, but at minimum it should return an object.
    expect(typeof result).toBe("object");
  });
});

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

describe("loadConfig", () => {
  /** Helper to run a callback with env vars set, then restore originals. */
  function withEnv(vars: Record<string, string>, fn: () => void) {
    const originals: Record<string, string | undefined> = {};
    for (const key of Object.keys(vars)) {
      originals[key] = process.env[key];
      process.env[key] = vars[key];
    }
    try {
      fn();
    } finally {
      for (const [key, orig] of Object.entries(originals)) {
        if (orig === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = orig;
        }
      }
    }
  }

  test("returns defaults when no values provided", () => {
    const config = loadConfig({});
    expect(config.socket_path).toBe(getDefaultSocketPath());
    expect(config.port).toBe(8173);
  });

  test("CLI args override TOML file values", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(filePath, `project_id = "toml-project"\nport = 4000\n`);

    const config = loadConfig({ project_id: "cli-project" }, filePath);
    expect(config.project_id).toBe("cli-project");
    expect(config.port).toBe(4000);
  });

  test("loads TOML values as base", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(filePath, `project_id = "toml-project"\nsocket_path = "/custom/path.sock"\n`);

    const config = loadConfig({}, filePath);
    expect(config.project_id).toBe("toml-project");
    expect(config.socket_path).toBe("/custom/path.sock");
    expect(config.port).toBe(8173);
  });

  test("expands tilde in socket_path from TOML", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(filePath, `project_id = "proj"\nsocket_path = "~/.gcp-authcalator/gate.sock"\n`);

    const config = loadConfig({}, filePath);
    expect(config.socket_path).toBe(join(homedir(), ".gcp-authcalator/gate.sock"));
  });

  test("expands tilde in socket_path from CLI args", () => {
    const config = loadConfig({ socket_path: "~/custom/gate.sock" });
    expect(config.socket_path).toBe(join(homedir(), "custom/gate.sock"));
  });

  test("throws ZodError for invalid merged config", () => {
    expect(() => loadConfig({ port: "abc" })).toThrow(z.ZodError);
  });

  test("env vars are picked up for all config keys", () => {
    withEnv(
      {
        GCP_AUTHCALATOR_PROJECT_ID: "env-project",
        GCP_AUTHCALATOR_PORT: "5555",
      },
      () => {
        const config = loadConfig({});
        expect(config.project_id).toBe("env-project");
        expect(config.port).toBe(5555);
      },
    );
  });

  test("CLI args override env vars (precedence change since v0.10)", () => {
    withEnv({ GCP_AUTHCALATOR_GATE_URL: "https://env.example.com" }, () => {
      const config = loadConfig({ gate_url: "https://cli.example.com" });
      expect(config.gate_url).toBe("https://cli.example.com");
    });
  });

  test("env vars override TOML file values", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(filePath, `project_id = "toml-project"\n`);

    withEnv({ GCP_AUTHCALATOR_PROJECT_ID: "env-project" }, () => {
      const config = loadConfig({}, filePath);
      expect(config.project_id).toBe("env-project");
    });
  });

  test("CLI args override TOML when no env var set", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(filePath, `project_id = "toml-project"\n`);

    const config = loadConfig({ project_id: "cli-project" }, filePath);
    expect(config.project_id).toBe("cli-project");
  });

  test("full precedence: CLI > env > TOML > defaults", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(
      filePath,
      `project_id = "toml-project"\nport = 4000\nsocket_path = "/toml.sock"\n`,
    );

    withEnv(
      {
        GCP_AUTHCALATOR_PROJECT_ID: "env-project",
        GCP_AUTHCALATOR_PORT: "6666",
      },
      () => {
        const config = loadConfig({ port: "5555", socket_path: "/cli.sock" }, filePath);
        // CLI wins over env and TOML
        expect(config.port).toBe(5555);
        // CLI wins over TOML (no env override for socket_path)
        expect(config.socket_path).toBe("/cli.sock");
        // env wins over TOML when no CLI override
        expect(config.project_id).toBe("env-project");
      },
    );
  });

  test("loads scopes from TOML", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(
      filePath,
      `project_id = "proj"\nscopes = ["https://www.googleapis.com/auth/sqlservice.login"]\n`,
    );

    const config = loadConfig({}, filePath);
    expect(config.scopes).toEqual(["https://www.googleapis.com/auth/sqlservice.login"]);
  });

  test("CLI scopes override TOML scopes", () => {
    const dir = mkdtempSync(join(tmpdir(), "config-test-"));
    const filePath = join(dir, "config.toml");
    writeFileSync(
      filePath,
      `project_id = "proj"\nscopes = ["https://www.googleapis.com/auth/cloud-platform"]\n`,
    );

    const config = loadConfig(
      { scopes: ["https://www.googleapis.com/auth/sqlservice.login"] },
      filePath,
    );
    expect(config.scopes).toEqual(["https://www.googleapis.com/auth/sqlservice.login"]);
  });
});
