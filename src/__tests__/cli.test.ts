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
  test("starts gate server with valid config", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cli-gate-"));
    const socketPath = join(dir, "gate.sock");

    const proc = Bun.spawn(
      [
        "bun",
        "run",
        entryPoint,
        "gate",
        "--project-id",
        "test-proj",
        "--service-account",
        "sa@test-proj.iam.gserviceaccount.com",
        "--socket-path",
        socketPath,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    // Give it time to start up or fail
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Kill the process since it runs as a daemon
    proc.kill();
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    await proc.exited;

    // Should have printed startup info (even if GCP auth fails later)
    const output = stdout + stderr;
    expect(output).toContain("gate:");
  });

  test("exits 1 when missing required fields", async () => {
    const { stderr, exitCode } = await runCLI(["gate"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("invalid configuration for 'gate'");
  });
});

describe("metadata-proxy subcommand", () => {
  test("starts metadata-proxy server with valid config", async () => {
    const proc = Bun.spawn(
      ["bun", "run", entryPoint, "metadata-proxy", "--project-id", "test-proj", "--port", "19200"],
      { stdout: "pipe", stderr: "pipe" },
    );

    // Give it time to start up
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Kill the process since it runs as a daemon
    proc.kill();
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    await proc.exited;

    const output = stdout + stderr;
    expect(output).toContain("metadata-proxy:");
    expect(output).toContain("test-proj");
    expect(output).toContain("19200");
  });

  test("exits 1 when missing project_id", async () => {
    const { stderr, exitCode } = await runCLI(["metadata-proxy"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("invalid configuration for 'metadata-proxy'");
  });
});

describe("with-prod subcommand", () => {
  test("exits 1 when token fetch fails (no gate socket)", async () => {
    const { stderr, exitCode } = await runCLI([
      "with-prod",
      "--project-id",
      "test-proj",
      "echo",
      "hello",
    ]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("failed to acquire prod token");
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
    const socketPath = join(dir, "gate.sock");
    writeFileSync(
      configFile,
      `project_id = "toml-project"\nservice_account = "sa@toml.iam.gserviceaccount.com"\nsocket_path = "${socketPath}"\n`,
    );

    const proc = Bun.spawn(["bun", "run", entryPoint, "gate", "--config", configFile], {
      stdout: "pipe",
      stderr: "pipe",
    });

    await new Promise((resolve) => setTimeout(resolve, 1000));
    proc.kill();

    const [stdout] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    await proc.exited;

    expect(stdout).toContain("toml-project");
    expect(stdout).toContain("sa@toml.iam.gserviceaccount.com");
  });

  test("CLI args override TOML values", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cli-test-"));
    const configFile = join(dir, "config.toml");
    const socketPath = join(dir, "gate.sock");
    writeFileSync(
      configFile,
      `project_id = "toml-project"\nservice_account = "sa@toml.iam.gserviceaccount.com"\nsocket_path = "${socketPath}"\n`,
    );

    const proc = Bun.spawn(
      ["bun", "run", entryPoint, "gate", "--config", configFile, "--project-id", "cli-project"],
      { stdout: "pipe", stderr: "pipe" },
    );

    await new Promise((resolve) => setTimeout(resolve, 1000));
    proc.kill();

    const [stdout] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    await proc.exited;

    expect(stdout).toContain("cli-project");
    expect(stdout).not.toContain("toml-project");
  });
});
