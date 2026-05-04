import { describe, expect, test } from "bun:test";
import {
  CREDENTIALS_EXPIRED_CODE,
  CredentialsExpiredError,
  formatCredentialsExpiredMessage,
  isCredentialsExpiredMessage,
  mapAdcError,
} from "../../gate/credentials-error.ts";

describe("isCredentialsExpiredMessage", () => {
  // Real strings observed from google-auth-library and OAuth endpoints when
  // the engineer's gcloud Application Default Credentials need a fresh
  // `gcloud auth application-default login`.
  const reauthMessages = [
    "invalid_grant: Bad Request",
    "invalid_grant: reauth related error (rapt_required)",
    "invalid_grant: reauth related error (invalid_rapt)",
    "Reauth required",
    "reauth_required",
    "rapt_required",
    "invalid_rapt",
    "Reauthentication required",
    "Reauthentication is required",
    "Token has been expired or revoked.",
    "refresh token has been expired or revoked",
    "refresh token is invalid",
  ];

  test.each(reauthMessages)("matches %p", (message) => {
    expect(isCredentialsExpiredMessage(message)).toBe(true);
  });

  test("does not match unrelated error messages", () => {
    expect(isCredentialsExpiredMessage("Failed to mint dev token: no access token returned")).toBe(
      false,
    );
    expect(isCredentialsExpiredMessage("CRM API returned 403")).toBe(false);
    expect(isCredentialsExpiredMessage("network error")).toBe(false);
    expect(isCredentialsExpiredMessage("")).toBe(false);
  });
});

describe("formatCredentialsExpiredMessage", () => {
  test("includes the detail, the gate's hostname, and the recovery instruction", () => {
    const message = formatCredentialsExpiredMessage("invalid_grant: Bad Request", "test-host");
    expect(message).toContain("invalid_grant: Bad Request");
    expect(message).toContain('host "test-host"');
    expect(message).toContain("gcloud auth application-default login");
    // The remote-vs-local clarifier is the whole point of naming the
    // hostname — assert it's present so a reword can't drop it silently.
    expect(message).toContain("NOT the devcontainer or remote SSH host");
    expect(message).toContain("no restart needed");
  });

  test("defaults to os.hostname() when no host is supplied", () => {
    const message = formatCredentialsExpiredMessage("invalid_grant: Bad Request");
    // Don't pin to the literal hostname (test machines vary), just
    // verify the shape: `host "<something non-empty>"`.
    expect(message).toMatch(/host "[^"]+"/);
  });
});

describe("mapAdcError", () => {
  test("converts invalid_grant errors to CredentialsExpiredError", () => {
    const original = new Error("invalid_grant: reauth related error (rapt_required)");
    const mapped = mapAdcError(original);

    expect(mapped).toBeInstanceOf(CredentialsExpiredError);
    expect((mapped as CredentialsExpiredError).code).toBe(CREDENTIALS_EXPIRED_CODE);
    expect((mapped as Error).message).toContain("rapt_required");
    expect((mapped as Error).message).toContain("gcloud auth application-default login");
    expect((mapped as { cause?: unknown }).cause).toBe(original);
  });

  test("uses only the first line of a multi-line google-auth message", () => {
    const original = new Error(
      "invalid_grant: Bad Request\n  at <anonymous> (foo.ts:1:1)\n  at bar (baz.ts:2:2)",
    );
    const mapped = mapAdcError(original);

    expect(mapped).toBeInstanceOf(CredentialsExpiredError);
    const message = (mapped as Error).message;
    expect(message).toContain("invalid_grant: Bad Request");
    expect(message).not.toContain("foo.ts");
  });

  test("passes through non-reauth errors unchanged", () => {
    const original = new Error("CRM API returned 403");
    const mapped = mapAdcError(original);
    expect(mapped).toBe(original);
  });

  test("returns existing CredentialsExpiredError untouched", () => {
    const existing = new CredentialsExpiredError("already formatted message");
    expect(mapAdcError(existing)).toBe(existing);
  });

  test("handles non-Error throws", () => {
    expect(mapAdcError("invalid_grant: reauth_required")).toBeInstanceOf(CredentialsExpiredError);
    expect(mapAdcError({ message: "unrelated" })).toEqual({ message: "unrelated" });
  });
});

describe("CredentialsExpiredError", () => {
  test("preserves the constructor message verbatim (no double-prefixing)", () => {
    // The client side receives the gate's already-formatted message and
    // forwards it via `new CredentialsExpiredError(message)`. The
    // constructor must NOT add another prefix or the user sees the
    // recovery instruction twice.
    const formatted = formatCredentialsExpiredMessage("invalid_grant: Bad Request");
    const err = new CredentialsExpiredError(formatted);
    expect(err.message).toBe(formatted);
  });

  test("exposes the code field for programmatic detection", () => {
    const err = new CredentialsExpiredError("anything");
    expect(err.code).toBe(CREDENTIALS_EXPIRED_CODE);
    expect(err.code).toBe("credentials_expired");
  });

  test("strips control characters from the message", () => {
    // Control characters in the wire payload could otherwise hit the
    // engineer's terminal via `console.error` and inject ANSI escape
    // sequences (e.g. set window title, redraw screen, clipboard write).
    const escaped = "invalid_grant\u001b[31mRED\u001b[0m\u0000\u0007\u001b]0;evil\u0007 trailing";
    const err = new CredentialsExpiredError(escaped);
    // eslint-disable-next-line no-control-regex
    expect(err.message).not.toMatch(/[\u0000-\u001f\u007f]/);
    expect(err.message).toContain("invalid_grant");
    expect(err.message).toContain("RED");
    expect(err.message).toContain("trailing");
  });

  test("caps the message length to bound stderr / audit-log cost", () => {
    const huge = "x".repeat(5000);
    const err = new CredentialsExpiredError(huge);
    expect(err.message.length).toBeLessThanOrEqual(1024);
    expect(err.message.endsWith("…")).toBe(true);
  });

  test("a short message is not truncated", () => {
    const formatted = formatCredentialsExpiredMessage("invalid_grant: Bad Request");
    const err = new CredentialsExpiredError(formatted);
    expect(err.message.endsWith("…")).toBe(false);
    expect(err.message).toBe(formatted);
  });
});
