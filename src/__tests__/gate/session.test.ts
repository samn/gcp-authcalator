import { describe, expect, test } from "bun:test";
import { createSessionManager } from "../../gate/session.ts";

describe("createSessionManager", () => {
  const baseParams = {
    email: "eng@example.com",
    projectId: "test-project",
    ttlSeconds: 3600,
    sessionLifetimeSeconds: 28800,
  };

  test("create returns a session with a 64-char hex ID", () => {
    const mgr = createSessionManager();
    const session = mgr.create(baseParams);

    expect(session.id).toHaveLength(64);
    expect(session.id).toMatch(/^[0-9a-f]{64}$/);
    expect(session.email).toBe("eng@example.com");
    expect(session.ttlSeconds).toBe(3600);
  });

  test("create generates unique IDs", () => {
    const mgr = createSessionManager();
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(mgr.create(baseParams).id);
    }
    expect(ids.size).toBe(100);
  });

  test("create preserves scopes and pamPolicy", () => {
    const mgr = createSessionManager();
    const session = mgr.create({
      ...baseParams,
      scopes: ["cloud-platform", "sqlservice.login"],
      pamPolicy: "projects/my-proj/locations/global/entitlements/my-ent",
    });

    expect(session.scopes).toEqual(["cloud-platform", "sqlservice.login"]);
    expect(session.pamPolicy).toBe("projects/my-proj/locations/global/entitlements/my-ent");
  });

  test("create sets createdAt and expiresAt based on now()", () => {
    const now = () => 1_000_000;
    const mgr = createSessionManager({ now });
    const session = mgr.create(baseParams);

    expect(session.createdAt.getTime()).toBe(1_000_000);
    expect(session.expiresAt.getTime()).toBe(1_000_000 + 28800 * 1000);
  });

  test("validate returns the session for a valid ID", () => {
    const mgr = createSessionManager();
    const session = mgr.create(baseParams);

    const result = mgr.validate(session.id);
    expect(result).not.toBeNull();
    expect(result!.id).toBe(session.id);
    expect(result!.email).toBe("eng@example.com");
  });

  test("validate returns null for unknown ID", () => {
    const mgr = createSessionManager();
    expect(mgr.validate("0".repeat(64))).toBeNull();
  });

  test("validate returns null for expired session", () => {
    let time = 1_000_000;
    const mgr = createSessionManager({ now: () => time });
    const session = mgr.create({ ...baseParams, sessionLifetimeSeconds: 60 });

    // Still valid
    expect(mgr.validate(session.id)).not.toBeNull();

    // Advance past expiry
    time = 1_000_000 + 61_000;
    expect(mgr.validate(session.id)).toBeNull();
  });

  test("validate cleans up expired sessions from storage", () => {
    let time = 1_000_000;
    const mgr = createSessionManager({ now: () => time });
    const session = mgr.create({ ...baseParams, sessionLifetimeSeconds: 60 });

    // Expire it
    time = 1_000_000 + 61_000;
    mgr.validate(session.id);

    // A second validate should also return null (session was deleted)
    expect(mgr.validate(session.id)).toBeNull();
  });

  test("revoke removes the session", () => {
    const mgr = createSessionManager();
    const session = mgr.create(baseParams);

    expect(mgr.revoke(session.id)).toBe(true);
    expect(mgr.validate(session.id)).toBeNull();
  });

  test("revoke returns false for unknown ID", () => {
    const mgr = createSessionManager();
    expect(mgr.revoke("0".repeat(64))).toBe(false);
  });

  test("revokeAll clears all sessions", () => {
    const mgr = createSessionManager();
    const s1 = mgr.create(baseParams);
    const s2 = mgr.create(baseParams);

    mgr.revokeAll();

    expect(mgr.validate(s1.id)).toBeNull();
    expect(mgr.validate(s2.id)).toBeNull();
  });

  test("validate returns null at exact expiry boundary", () => {
    let time = 1_000_000;
    const mgr = createSessionManager({ now: () => time });
    const session = mgr.create({ ...baseParams, sessionLifetimeSeconds: 60 });

    // Exactly at expiry
    time = 1_000_000 + 60_000;
    expect(mgr.validate(session.id)).toBeNull();
  });
});
