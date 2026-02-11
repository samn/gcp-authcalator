import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";

const entryPoint = resolve(import.meta.dir, "../../index.ts");

/** Run the CLI as a subprocess and capture output. */
async function runCLI(
  args: string[],
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn(["bun", "run", entryPoint, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  return { stdout, stderr, exitCode };
}

// ---------------------------------------------------------------------------
// Help & Version
// ---------------------------------------------------------------------------

describe("--help", () => {
  test("prints usage and exits 0", async () => {
    const { stdout, exitCode } = await runCLI(["--help"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("gcp-authcalator");
    expect(stdout).toContain("Commands:");
    expect(stdout).toContain("gate");
    expect(stdout).toContain("metadata-proxy");
    expect(stdout).toContain("with-prod");
  });
});

describe("--version", () => {
  test("prints version and exits 0", async () => {
    const { stdout, exitCode } = await runCLI(["--version"]);
    expect(exitCode).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

// ---------------------------------------------------------------------------
// No subcommand / unknown subcommand
// ---------------------------------------------------------------------------

describe("no subcommand", () => {
  test("exits 1 and prints error to stderr", async () => {
    const { stderr, exitCode } = await runCLI([]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("no subcommand provided");
  });
});

describe("unknown subcommand", () => {
  test("exits 1 and prints error to stderr", async () => {
    const { stderr, exitCode } = await runCLI(["foobar"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("unknown subcommand");
    expect(stderr).toContain("foobar");
  });
});

// ---------------------------------------------------------------------------
// Unknown flag (strict mode)
// ---------------------------------------------------------------------------

describe("unknown flag", () => {
  test("exits with error for unknown flag", async () => {
    const { exitCode, stderr } = await runCLI(["gate", "--unknown-flag"]);
    expect(exitCode).not.toBe(0);
    expect(stderr.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Subcommand routing
// ---------------------------------------------------------------------------

describe("gate subcommand", () => {
  test("runs gate stub with valid config", async () => {
    const { stdout, exitCode } = await runCLI([
      "gate",
      "--project-id",
      "test-proj",
      "--service-account",
      "sa@test-proj.iam.gserviceaccount.com",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("gate: starting gcp-gate token daemon");
    expect(stdout).toContain("test-proj");
    expect(stdout).toContain("[STUB] Not yet implemented.");
  });

  test("exits 1 when missing required fields", async () => {
    const { stderr, exitCode } = await runCLI(["gate"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("invalid configuration for 'gate'");
  });
});

describe("metadata-proxy subcommand", () => {
  test("runs metadata-proxy stub with valid config", async () => {
    const { stdout, exitCode } = await runCLI([
      "metadata-proxy",
      "--project-id",
      "test-proj",
      "--port",
      "9090",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("metadata-proxy: starting GCE metadata server emulator");
    expect(stdout).toContain("test-proj");
    expect(stdout).toContain("9090");
    expect(stdout).toContain("[STUB] Not yet implemented.");
  });

  test("exits 1 when missing project_id", async () => {
    const { stderr, exitCode } = await runCLI(["metadata-proxy"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("invalid configuration for 'metadata-proxy'");
  });
});

describe("with-prod subcommand", () => {
  test("runs with-prod stub with valid config and command", async () => {
    const { stdout, exitCode } = await runCLI([
      "with-prod",
      "--project-id",
      "test-proj",
      "python",
      "script.py",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("with-prod: wrapping command with prod credentials");
    expect(stdout).toContain("python script.py");
    expect(stdout).toContain("[STUB] Not yet implemented.");
  });

  test("exits 1 when no wrapped command provided", async () => {
    const { stderr, exitCode } = await runCLI(["with-prod", "--project-id", "test-proj"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("with-prod requires a command to wrap");
  });

  test("exits 1 when missing project_id", async () => {
    const { stderr, exitCode } = await runCLI(["with-prod", "python", "script.py"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("invalid configuration for 'with-prod'");
  });
});

// ---------------------------------------------------------------------------
// Config file integration
// ---------------------------------------------------------------------------

describe("--config flag", () => {
  test("loads config from TOML file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cli-test-"));
    const configFile = join(dir, "config.toml");
    writeFileSync(
      configFile,
      `project_id = "toml-project"\nservice_account = "sa@toml.iam.gserviceaccount.com"\n`,
    );

    const { stdout, exitCode } = await runCLI(["gate", "--config", configFile]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("toml-project");
    expect(stdout).toContain("sa@toml.iam.gserviceaccount.com");
  });

  test("CLI args override TOML values", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cli-test-"));
    const configFile = join(dir, "config.toml");
    writeFileSync(
      configFile,
      `project_id = "toml-project"\nservice_account = "sa@toml.iam.gserviceaccount.com"\n`,
    );

    const { stdout, exitCode } = await runCLI([
      "gate",
      "--config",
      configFile,
      "--project-id",
      "cli-project",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("cli-project");
    expect(stdout).not.toContain("toml-project");
  });
});
