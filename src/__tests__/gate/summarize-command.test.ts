import { describe, expect, test } from "bun:test";
import { summarizeCommand, parseCommandHeader } from "../../gate/summarize-command.ts";

// ---------------------------------------------------------------------------
// summarizeCommand
// ---------------------------------------------------------------------------

describe("summarizeCommand", () => {
  test("returns undefined for empty command array", () => {
    expect(summarizeCommand([])).toBeUndefined();
  });

  test("returns binary name for single-element command", () => {
    expect(summarizeCommand(["gcloud"])).toBe("gcloud");
  });

  test("extracts basename from full path", () => {
    expect(summarizeCommand(["/usr/bin/gcloud"])).toBe("gcloud");
  });

  test("includes arguments in output", () => {
    expect(summarizeCommand(["gcloud", "compute", "instances", "list"])).toBe(
      "gcloud compute instances list",
    );
  });

  test("truncates commands longer than 80 characters", () => {
    const longArgs = Array.from({ length: 20 }, (_, i) => `arg-with-content-${i}`);
    const result = summarizeCommand(["mybinary", ...longArgs]);

    expect(result).toBeDefined();
    expect(result!.length).toBeLessThanOrEqual(80);
    expect(result!.endsWith("\u2026")).toBe(true);
    expect(result!.startsWith("mybinary")).toBe(true);
  });

  test("redacts long base64-like values (tokens/keys)", () => {
    const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
    const result = summarizeCommand(["gcloud", "--token", token]);

    expect(result).toBeDefined();
    expect(result).toContain("***");
    expect(result).not.toContain(token);
  });

  test("redacts key=value pairs with sensitive key names", () => {
    const result = summarizeCommand(["curl", "--password=s3cret-value"]);

    expect(result).toBeDefined();
    expect(result).toContain("--password=***");
    expect(result).not.toContain("s3cret-value");
  });

  test("redacts api-key values", () => {
    const result = summarizeCommand(["curl", "--api-key=my-secret-key"]);

    expect(result).toBeDefined();
    expect(result).toContain("--api-key=***");
    expect(result).not.toContain("my-secret-key");
  });

  test("redacts credential values", () => {
    const result = summarizeCommand(["tool", "--credential=some-cred"]);

    expect(result).toBeDefined();
    expect(result).toContain("--credential=***");
    expect(result).not.toContain("some-cred");
  });

  test("does not redact normal arguments", () => {
    const result = summarizeCommand(["gcloud", "compute", "--project=my-project"]);

    expect(result).toBe("gcloud compute --project=my-project");
  });

  test("does not redact short values", () => {
    const result = summarizeCommand(["gcloud", "compute", "us-central1-a"]);

    expect(result).toBe("gcloud compute us-central1-a");
  });

  test("handles path binary with arguments", () => {
    const result = summarizeCommand(["/opt/tools/bin/terraform", "apply", "-auto-approve"]);

    expect(result).toBe("terraform apply -auto-approve");
  });
});

// ---------------------------------------------------------------------------
// parseCommandHeader
// ---------------------------------------------------------------------------

describe("parseCommandHeader", () => {
  test("returns undefined for null header", () => {
    expect(parseCommandHeader(null)).toBeUndefined();
  });

  test("returns undefined for empty string", () => {
    expect(parseCommandHeader("")).toBeUndefined();
  });

  test("returns undefined for invalid JSON", () => {
    expect(parseCommandHeader("not json")).toBeUndefined();
  });

  test("returns undefined for non-array JSON", () => {
    expect(parseCommandHeader('{"cmd":"gcloud"}')).toBeUndefined();
  });

  test("returns undefined for empty array", () => {
    expect(parseCommandHeader("[]")).toBeUndefined();
  });

  test("returns undefined for array with non-string elements", () => {
    expect(parseCommandHeader("[1, 2, 3]")).toBeUndefined();
  });

  test("parses valid command array", () => {
    const header = JSON.stringify(["gcloud", "compute", "instances", "list"]);
    expect(parseCommandHeader(header)).toEqual(["gcloud", "compute", "instances", "list"]);
  });

  test("parses single-element command", () => {
    const header = JSON.stringify(["bash"]);
    expect(parseCommandHeader(header)).toEqual(["bash"]);
  });
});
