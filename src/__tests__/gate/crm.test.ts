import { describe, expect, test } from "bun:test";
import { createFolderMembershipChecker } from "../../gate/crm.ts";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Build a fetch mock from a sequence of responses keyed by the CRM resource
 * name (e.g. "projects/foo" or "folders/123"). Each call increments the
 * matched key's call counter and returns the next queued response. Unmatched
 * URLs throw immediately so tests fail loudly on unexpected calls.
 */
function makeCrmMock(routes: Record<string, Array<() => Response | Promise<Response>>>): {
  fetchFn: typeof globalThis.fetch;
  callCounts: Record<string, number>;
} {
  const callCounts: Record<string, number> = {};
  const pointers: Record<string, number> = {};
  const fetchFn = (async (url: string | URL) => {
    const s = typeof url === "string" ? url : url.toString();
    const matched = Object.keys(routes).find((k) => s.endsWith(`/v3/${k}`));
    if (!matched) throw new Error(`unexpected CRM URL: ${s}`);
    callCounts[matched] = (callCounts[matched] ?? 0) + 1;
    const queue = routes[matched]!;
    const i = pointers[matched] ?? 0;
    pointers[matched] = i + 1;
    const factory = queue[Math.min(i, queue.length - 1)]!;
    return factory();
  }) as unknown as typeof globalThis.fetch;
  return { fetchFn, callCounts };
}

const tokenProvider = async () => "stub-token";

describe("createFolderMembershipChecker", () => {
  test("returns true when project's parent is the configured folder", async () => {
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [
        () => jsonResponse({ name: "projects/100", parent: "folders/123456789012" }),
      ],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    expect(await checker.isProjectInFolder("tenant-a")).toBe(true);
  });

  test("walks ancestry through nested sub-folders to the target", async () => {
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [() => jsonResponse({ parent: "folders/999" })],
      "folders/999": [() => jsonResponse({ parent: "folders/888" })],
      "folders/888": [() => jsonResponse({ parent: "folders/123456789012" })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    expect(await checker.isProjectInFolder("tenant-a")).toBe(true);
  });

  test("returns false when ancestry hits organization without crossing the folder", async () => {
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [() => jsonResponse({ parent: "organizations/42" })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
  });

  test("returns false on 403", async () => {
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [() => new Response("forbidden", { status: 403 })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
  });

  test("returns false on 404", async () => {
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [() => new Response("not found", { status: 404 })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
  });

  test("throws on 5xx when no cached positive is available", async () => {
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [() => new Response("boom", { status: 503 })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    await expect(checker.isProjectInFolder("tenant-a")).rejects.toThrow(/returned 503/);
  });

  test("caches positives — repeated lookups hit one CRM call within TTL", async () => {
    const { fetchFn, callCounts } = makeCrmMock({
      "projects/tenant-a": [() => jsonResponse({ parent: "folders/123456789012" })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    await checker.isProjectInFolder("tenant-a");
    await checker.isProjectInFolder("tenant-a");
    await checker.isProjectInFolder("tenant-a");
    expect(callCounts["projects/tenant-a"]).toBe(1);
  });

  test("caches negatives — repeated lookups hit one CRM call within negative TTL", async () => {
    const { fetchFn, callCounts } = makeCrmMock({
      "projects/tenant-a": [() => jsonResponse({ parent: "organizations/42" })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
    expect(callCounts["projects/tenant-a"]).toBe(1);
  });

  test("negative cache expires before positive cache", async () => {
    let t = 0;
    const now = () => t;
    const { fetchFn, callCounts } = makeCrmMock({
      "projects/tenant-a": [
        () => jsonResponse({ parent: "organizations/42" }), // first call: negative
        () => jsonResponse({ parent: "folders/123456789012" }), // second call: positive
      ],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn, now });

    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
    // Advance 31s — past negative TTL (30s), well before positive TTL (10min).
    t = 31_000;
    expect(await checker.isProjectInFolder("tenant-a")).toBe(true);
    expect(callCounts["projects/tenant-a"]).toBe(2);
  });

  test("serves stale positive when CRM 5xx within stale-OK window", async () => {
    let t = 0;
    const now = () => t;
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [
        () => jsonResponse({ parent: "folders/123456789012" }), // confirm positive
        () => new Response("boom", { status: 503 }), // outage on refresh
      ],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn, now });

    expect(await checker.isProjectInFolder("tenant-a")).toBe(true);
    // Past positive TTL (10min) but within stale-OK window (extra 5min).
    t = 11 * 60 * 1000;
    expect(await checker.isProjectInFolder("tenant-a")).toBe(true);
  });

  test("does not serve stale beyond the stale-OK window", async () => {
    let t = 0;
    const now = () => t;
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [
        () => jsonResponse({ parent: "folders/123456789012" }),
        () => new Response("boom", { status: 503 }),
      ],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn, now });

    await checker.isProjectInFolder("tenant-a");
    // Past TTL (10min) + stale window (5min).
    t = 16 * 60 * 1000;
    await expect(checker.isProjectInFolder("tenant-a")).rejects.toThrow(/returned 503/);
  });

  test("does not serve stale on CRM 5xx if last result was negative", async () => {
    let t = 0;
    const now = () => t;
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [
        () => jsonResponse({ parent: "organizations/42" }),
        () => new Response("boom", { status: 503 }),
      ],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn, now });

    expect(await checker.isProjectInFolder("tenant-a")).toBe(false);
    t = 60_000; // past negative TTL
    await expect(checker.isProjectInFolder("tenant-a")).rejects.toThrow(/returned 503/);
  });

  test("single-flight: concurrent calls for the same project coalesce", async () => {
    let pending: ((r: Response) => void) | undefined;
    const wait = new Promise<Response>((resolve) => {
      pending = resolve;
    });
    let crmCalls = 0;
    const fetchFn = (async () => {
      crmCalls++;
      return wait;
    }) as unknown as typeof globalThis.fetch;
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });

    const a = checker.isProjectInFolder("tenant-a");
    const b = checker.isProjectInFolder("tenant-a");
    const c = checker.isProjectInFolder("tenant-a");

    pending!(jsonResponse({ parent: "folders/123456789012" }));
    expect(await a).toBe(true);
    expect(await b).toBe(true);
    expect(await c).toBe(true);
    expect(crmCalls).toBe(1);
  });

  test("throws when ancestry walk exceeds MAX_ANCESTRY_HOPS", async () => {
    // Loop the parent pointer back to itself so we never reach the target.
    const { fetchFn } = makeCrmMock({
      "projects/tenant-a": [() => jsonResponse({ parent: "folders/999" })],
      "folders/999": [() => jsonResponse({ parent: "folders/999" })],
    });
    const checker = createFolderMembershipChecker("123456789012", tokenProvider, { fetchFn });
    await expect(checker.isProjectInFolder("tenant-a")).rejects.toThrow(/exceeded.*hops/);
  });
});
