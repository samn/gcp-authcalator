import { describe, expect, test } from "bun:test";
import { createCachingTokenProvider } from "../../with-prod/caching-token-provider.ts";
import type { CachedToken } from "../../metadata-proxy/types.ts";

/** An expired token that needs refreshing. */
function staleToken(): CachedToken {
  return { access_token: "stale", expires_at: new Date(Date.now() - 1000) };
}

/** A token well within validity (served straight from cache). */
function freshToken(access_token = "fresh"): CachedToken {
  return { access_token, expires_at: new Date(Date.now() + 3600_000) };
}

describe("createCachingTokenProvider", () => {
  test("serves a still-valid token from cache without refreshing", async () => {
    let calls = 0;
    const provider = createCachingTokenProvider(freshToken(), undefined, async () => {
      calls++;
      return freshToken("new");
    });

    expect((await provider.getToken()).access_token).toBe("fresh");
    expect(calls).toBe(0);
  });

  test("refreshes when the cached token is expired", async () => {
    let calls = 0;
    const provider = createCachingTokenProvider(staleToken(), undefined, async () => {
      calls++;
      return freshToken("new");
    });

    expect((await provider.getToken()).access_token).toBe("new");
    expect(calls).toBe(1);
  });

  test("coalesces concurrent refreshes into a single gate call (single-flight)", async () => {
    let calls = 0;
    let resolveRefresh!: (t: CachedToken) => void;
    const provider = createCachingTokenProvider(staleToken(), undefined, () => {
      calls++;
      return new Promise<CachedToken>((resolve) => {
        resolveRefresh = resolve;
      });
    });

    // Fire several concurrent getToken() calls while the token is stale. Only
    // one underlying refresh should be started; the rest await that promise.
    const p1 = provider.getToken();
    const p2 = provider.getToken();
    const p3 = provider.getToken();
    expect(calls).toBe(1);

    resolveRefresh(freshToken("new"));
    const tokens = await Promise.all([p1, p2, p3]);
    expect(tokens.map((t) => t.access_token)).toEqual(["new", "new", "new"]);
    expect(calls).toBe(1);
  });

  test("fires onRefresh exactly once for a coalesced refresh", async () => {
    let refreshes = 0;
    let resolveRefresh!: (t: CachedToken) => void;
    const onRefreshTokens: string[] = [];
    const provider = createCachingTokenProvider(
      staleToken(),
      (t) => onRefreshTokens.push(t.access_token),
      () => {
        refreshes++;
        return new Promise<CachedToken>((resolve) => {
          resolveRefresh = resolve;
        });
      },
    );

    const calls = [provider.getToken(), provider.getToken(), provider.getToken()];
    resolveRefresh(freshToken("new"));
    await Promise.all(calls);

    expect(refreshes).toBe(1);
    expect(onRefreshTokens).toEqual(["new"]);
  });

  test("starts a fresh refresh after a previous one completes", async () => {
    let calls = 0;
    const provider = createCachingTokenProvider(staleToken(), undefined, async () => {
      calls++;
      // Each refresh returns a token that is itself still stale, so the next
      // getToken() must refresh again rather than reuse the in-flight slot.
      return staleToken();
    });

    await provider.getToken();
    await provider.getToken();
    expect(calls).toBe(2);
  });

  test("does not immediately refresh a newly observed short-lived token", async () => {
    let calls = 0;
    const shortToken: CachedToken = {
      access_token: "short",
      expires_at: new Date(Date.now() + 60_000),
    };
    const provider = createCachingTokenProvider(shortToken, undefined, async () => {
      calls++;
      return freshToken("unexpected");
    });

    expect((await provider.getToken()).access_token).toBe("short");
    expect((await provider.getToken()).access_token).toBe("short");
    expect(calls).toBe(0);
  });

  test("refreshes a long-lived token at its capped five-minute margin", async () => {
    let currentTime = 1_000;
    let calls = 0;
    const token: CachedToken = {
      access_token: "old",
      expires_at: new Date(currentTime + 60 * 60 * 1000),
    };
    const provider = createCachingTokenProvider(
      token,
      undefined,
      async () => {
        calls++;
        return { access_token: "new", expires_at: new Date(currentTime + 60 * 60 * 1000) };
      },
      () => currentTime,
    );

    currentTime += 55 * 60 * 1000;
    expect((await provider.getToken()).access_token).toBe("new");
    expect(calls).toBe(1);
  });

  test("propagates refresh errors to all concurrent callers and recovers", async () => {
    let calls = 0;
    const provider = createCachingTokenProvider(staleToken(), undefined, async () => {
      calls++;
      if (calls === 1) throw new Error("gate down");
      return freshToken("recovered");
    });

    await expect(provider.getToken()).rejects.toThrow("gate down");
    // A subsequent call should start a new refresh (in-flight slot released).
    expect((await provider.getToken()).access_token).toBe("recovered");
    expect(calls).toBe(2);
  });

  test("retries when the refresh side effect fails before cache commit", async () => {
    let refreshCalls = 0;
    let callbackCalls = 0;
    const provider = createCachingTokenProvider(
      staleToken(),
      () => {
        callbackCalls++;
        if (callbackCalls === 1) throw new Error("token file write failed");
      },
      async () => {
        refreshCalls++;
        return freshToken(`new-${refreshCalls}`);
      },
    );

    await expect(provider.getToken()).rejects.toThrow("token file write failed");
    expect((await provider.getToken()).access_token).toBe("new-2");
    expect(refreshCalls).toBe(2);
    expect(callbackCalls).toBe(2);
  });
});
