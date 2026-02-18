import { describe, expect, test } from "bun:test";
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
  loadConfig,
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
// loadConfig
// ---------------------------------------------------------------------------

describe("loadConfig", () => {
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
});
