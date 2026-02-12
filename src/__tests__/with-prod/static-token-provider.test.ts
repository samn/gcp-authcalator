import { describe, expect, test } from "bun:test";
import { createStaticTokenProvider } from "../../with-prod/static-token-provider.ts";

describe("createStaticTokenProvider", () => {
  test("returns fixed token", async () => {
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    const provider = createStaticTokenProvider("my-static-token", expiresAt);

    const token = await provider.getToken();
    expect(token.access_token).toBe("my-static-token");
    expect(token.expires_at).toBe(expiresAt);
  });

  test("returns same token on repeated calls", async () => {
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    const provider = createStaticTokenProvider("repeat-token", expiresAt);

    const first = await provider.getToken();
    const second = await provider.getToken();
    const third = await provider.getToken();

    expect(first).toBe(second);
    expect(second).toBe(third);
    expect(first.access_token).toBe("repeat-token");
  });
});
