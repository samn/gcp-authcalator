import { describe, expect, test } from "bun:test";
import {
  CREDENTIALS_EXPIRED_CODE,
  CredentialsExpiredError,
  formatCredentialsExpiredMessage,
  isCredentialsExpiredMessage,
  mapAdcError,
  REAUTH_INSTRUCTION,
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
  test("includes the detail and the recovery instruction", () => {
    const message = formatCredentialsExpiredMessage("invalid_grant: Bad Request");
    expect(message).toContain("invalid_grant: Bad Request");
    expect(message).toContain("gcloud auth application-default login");
    expect(message).toContain(REAUTH_INSTRUCTION);
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
});
