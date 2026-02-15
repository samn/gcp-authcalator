import { describe, expect, test } from "bun:test";
import { createProdRateLimiter } from "../../gate/rate-limit.ts";

// ---------------------------------------------------------------------------
// Single-flight (mutex)
// ---------------------------------------------------------------------------

describe("single-flight", () => {
  test("allows the first request", () => {
    const limiter = createProdRateLimiter();
    const result = limiter.acquire();
    expect(result.allowed).toBe(true);
  });

  test("rejects a second request while one is pending", () => {
    const limiter = createProdRateLimiter();
    limiter.acquire();

    const second = limiter.acquire();
    expect(second.allowed).toBe(false);
    if (!second.allowed) {
      expect(second.reason).toContain("already pending");
    }
  });

  test("allows a new request after release", () => {
    const limiter = createProdRateLimiter();
    limiter.acquire();
    limiter.release("granted");

    const result = limiter.acquire();
    expect(result.allowed).toBe(true);
  });

  test("allows a new request after denied release (once cooldown expires)", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      denialCooldownMs: 100,
    });

    limiter.acquire();
    limiter.release("denied");

    // During cooldown — blocked by cooldown, not mutex
    const during = limiter.acquire();
    expect(during.allowed).toBe(false);
    if (!during.allowed) {
      expect(during.reason).toContain("retry in");
    }

    // After cooldown — allowed
    clock = 101;
    const after = limiter.acquire();
    expect(after.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Cooldown after denial
// ---------------------------------------------------------------------------

describe("cooldown after denial", () => {
  test("imposes cooldown after denied result", () => {
    const clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      denialCooldownMs: 30_000,
    });

    limiter.acquire();
    limiter.release("denied");

    // Immediately after denial
    const result = limiter.acquire();
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("retry in 30s");
    }
  });

  test("cooldown message shows correct remaining seconds", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      denialCooldownMs: 30_000,
    });

    limiter.acquire();
    limiter.release("denied");

    // 20 seconds later — 10 seconds remaining
    clock = 20_000;
    const result = limiter.acquire();
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("retry in 10s");
    }
  });

  test("allows request after cooldown expires", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      denialCooldownMs: 30_000,
    });

    limiter.acquire();
    limiter.release("denied");

    clock = 30_001;
    const result = limiter.acquire();
    expect(result.allowed).toBe(true);
  });

  test("no cooldown after granted result", () => {
    const limiter = createProdRateLimiter();

    limiter.acquire();
    limiter.release("granted");

    const result = limiter.acquire();
    expect(result.allowed).toBe(true);
  });

  test("no cooldown after error result", () => {
    const limiter = createProdRateLimiter();

    limiter.acquire();
    limiter.release("error");

    const result = limiter.acquire();
    expect(result.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Sliding window rate limit
// ---------------------------------------------------------------------------

describe("sliding window rate limit", () => {
  test("allows up to maxAttemptsPerWindow attempts", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      maxAttemptsPerWindow: 3,
      windowMs: 60_000,
      denialCooldownMs: 0,
    });

    for (let i = 0; i < 3; i++) {
      const result = limiter.acquire();
      expect(result.allowed).toBe(true);
      limiter.release("granted");
      clock += 1000;
    }

    // 4th attempt should be rejected
    const result = limiter.acquire();
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("Rate limit exceeded");
      expect(result.reason).toContain("3");
    }
  });

  test("allows new attempts after old ones expire from window", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      maxAttemptsPerWindow: 2,
      windowMs: 10_000,
      denialCooldownMs: 0,
    });

    // Use up both attempts
    limiter.acquire();
    limiter.release("granted");
    clock += 1000;

    limiter.acquire();
    limiter.release("granted");
    clock += 1000;

    // Should be blocked
    const blocked = limiter.acquire();
    expect(blocked.allowed).toBe(false);

    // Move past the window so the first attempt expires
    clock = 11_000;
    const allowed = limiter.acquire();
    expect(allowed.allowed).toBe(true);
  });

  test("denied attempts also count toward the window", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      maxAttemptsPerWindow: 2,
      windowMs: 60_000,
      denialCooldownMs: 0,
    });

    limiter.acquire();
    limiter.release("denied");
    clock += 1000;

    limiter.acquire();
    limiter.release("denied");
    clock += 1000;

    const result = limiter.acquire();
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("Rate limit exceeded");
    }
  });
});

// ---------------------------------------------------------------------------
// Combined behavior
// ---------------------------------------------------------------------------

describe("combined protections", () => {
  test("single-flight checked before cooldown", () => {
    const clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      denialCooldownMs: 30_000,
    });

    // First request acquires
    limiter.acquire();

    // Second request — should fail due to single-flight, not cooldown
    const result = limiter.acquire();
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("already pending");
    }
  });

  test("cooldown and rate limit interact correctly", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      denialCooldownMs: 5_000,
      maxAttemptsPerWindow: 2,
      windowMs: 60_000,
    });

    // First attempt — denied
    limiter.acquire();
    limiter.release("denied");

    // Wait for cooldown
    clock = 6_000;

    // Second attempt — denied
    limiter.acquire();
    limiter.release("denied");

    // Wait for cooldown
    clock = 12_000;

    // Third attempt — should be blocked by rate limit, not cooldown
    const result = limiter.acquire();
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("Rate limit exceeded");
    }
  });

  test("error release does not trigger cooldown but counts toward window", () => {
    let clock = 0;
    const limiter = createProdRateLimiter({
      now: () => clock,
      maxAttemptsPerWindow: 2,
      windowMs: 60_000,
      denialCooldownMs: 30_000,
    });

    // Error result — no cooldown, but counts toward window
    limiter.acquire();
    limiter.release("error");
    clock += 1000;

    // Should be allowed (no cooldown from error)
    const second = limiter.acquire();
    expect(second.allowed).toBe(true);
    limiter.release("error");
    clock += 1000;

    // Third attempt — rate limited
    const third = limiter.acquire();
    expect(third.allowed).toBe(false);
    if (!third.allowed) {
      expect(third.reason).toContain("Rate limit exceeded");
    }
  });
});
