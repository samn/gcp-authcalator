import { describe, expect, test } from "bun:test";
import { createPendingQueue } from "../../gate/pending.ts";

describe("createPendingQueue", () => {
  const baseOpts = { timeoutMs: 5000, now: () => 1_000_000 };

  test("enqueue returns a promise that resolves to true when approved", async () => {
    const queue = createPendingQueue(baseOpts);
    const promise = queue.enqueue("user@example.com", "gcloud compute instances list");
    const pending = queue.list();

    expect(pending).toHaveLength(1);
    expect(pending[0]!.email).toBe("user@example.com");
    expect(pending[0]!.command).toBe("gcloud compute instances list");

    queue.approve(pending[0]!.id);
    expect(await promise).toBe(true);
  });

  test("enqueue returns a promise that resolves to false when denied", async () => {
    const queue = createPendingQueue(baseOpts);
    const promise = queue.enqueue("user@example.com");
    const [req] = queue.list();

    queue.deny(req!.id);
    expect(await promise).toBe(false);
  });

  test("enqueue auto-denies after timeout", async () => {
    const queue = createPendingQueue({ timeoutMs: 50 });
    const promise = queue.enqueue("user@example.com");

    expect(await promise).toBe(false);
    expect(queue.list()).toHaveLength(0);
  });

  test("list returns all pending requests", () => {
    const queue = createPendingQueue(baseOpts);
    queue.enqueue("a@example.com", "cmd1");
    queue.enqueue("b@example.com", "cmd2", "pam-policy");

    const pending = queue.list();
    expect(pending).toHaveLength(2);
    expect(pending[0]!.email).toBe("a@example.com");
    expect(pending[1]!.email).toBe("b@example.com");
    expect(pending[1]!.pamPolicy).toBe("pam-policy");
  });

  test("list omits expired requests", () => {
    let time = 1_000_000;
    const queue = createPendingQueue({ timeoutMs: 5000, now: () => time });

    queue.enqueue("user@example.com");
    expect(queue.list()).toHaveLength(1);

    // Advance past expiry
    time = 1_000_000 + 6000;
    expect(queue.list()).toHaveLength(0);
  });

  test("approve returns false for unknown ID", () => {
    const queue = createPendingQueue(baseOpts);
    expect(queue.approve("nonexistent")).toBe(false);
  });

  test("deny returns false for unknown ID", () => {
    const queue = createPendingQueue(baseOpts);
    expect(queue.deny("nonexistent")).toBe(false);
  });

  test("approve returns false for expired request", () => {
    let time = 1_000_000;
    const queue = createPendingQueue({ timeoutMs: 5000, now: () => time });

    queue.enqueue("user@example.com");
    const [req] = queue.list();

    // Advance past expiry
    time = 1_000_000 + 6000;
    expect(queue.approve(req!.id)).toBe(false);
  });

  test("approve returns false for already-resolved request", async () => {
    const queue = createPendingQueue(baseOpts);
    const promise = queue.enqueue("user@example.com");
    const [req] = queue.list();

    expect(queue.approve(req!.id)).toBe(true);
    expect(queue.approve(req!.id)).toBe(false);
    await promise;
  });

  test("denyAll resolves all pending promises with false", async () => {
    const queue = createPendingQueue(baseOpts);
    const p1 = queue.enqueue("a@example.com");
    const p2 = queue.enqueue("b@example.com");

    expect(queue.list()).toHaveLength(2);
    queue.denyAll();
    expect(queue.list()).toHaveLength(0);

    expect(await p1).toBe(false);
    expect(await p2).toBe(false);
  });

  test("auto-generated IDs are 32-char hex strings", () => {
    const queue = createPendingQueue(baseOpts);
    queue.enqueue("user@example.com");
    const [req] = queue.list();
    expect(req!.id).toHaveLength(32);
    expect(req!.id).toMatch(/^[0-9a-f]{32}$/);
  });

  test("auto-generated IDs are unique", () => {
    const queue = createPendingQueue(baseOpts);
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) {
      queue.enqueue(`user${i}@example.com`);
    }
    for (const req of queue.list()) {
      ids.add(req.id);
    }
    expect(ids.size).toBe(50);
  });

  test("accepts a valid client-provided ID", async () => {
    const queue = createPendingQueue(baseOpts);
    const clientId = "a".repeat(32);
    const promise = queue.enqueue("user@example.com", "cmd", undefined, clientId);
    const [req] = queue.list();

    expect(req!.id).toBe(clientId);
    queue.approve(clientId);
    expect(await promise).toBe(true);
  });

  test("rejects client-provided ID with wrong length", () => {
    const queue = createPendingQueue(baseOpts);
    expect(() => queue.enqueue("user@example.com", undefined, undefined, "tooshort")).toThrow(
      "Invalid pending ID format",
    );
  });

  test("rejects client-provided ID with uppercase chars", () => {
    const queue = createPendingQueue(baseOpts);
    expect(() => queue.enqueue("user@example.com", undefined, undefined, "A".repeat(32))).toThrow(
      "Invalid pending ID format",
    );
  });

  test("rejects duplicate client-provided ID", () => {
    const queue = createPendingQueue(baseOpts);
    const clientId = "b".repeat(32);
    queue.enqueue("a@example.com", undefined, undefined, clientId);

    expect(() => queue.enqueue("b@example.com", undefined, undefined, clientId)).toThrow(
      "Pending ID already in use",
    );
  });

  test("createdAt and expiresAt are set correctly", () => {
    const queue = createPendingQueue({ timeoutMs: 5000, now: () => 1_000_000 });
    queue.enqueue("user@example.com");
    const [req] = queue.list();

    expect(req!.createdAt.getTime()).toBe(1_000_000);
    expect(req!.expiresAt.getTime()).toBe(1_005_000);
  });

  test("enqueue preserves optional fields", () => {
    const queue = createPendingQueue(baseOpts);
    queue.enqueue("user@example.com", "terraform apply", "prod-db-admin");
    const [req] = queue.list();

    expect(req!.email).toBe("user@example.com");
    expect(req!.command).toBe("terraform apply");
    expect(req!.pamPolicy).toBe("prod-db-admin");
  });

  test("enqueue with no optional fields leaves them undefined", () => {
    const queue = createPendingQueue(baseOpts);
    queue.enqueue("user@example.com");
    const [req] = queue.list();

    expect(req!.command).toBeUndefined();
    expect(req!.pamPolicy).toBeUndefined();
  });

  test("multiple concurrent requests are independent", async () => {
    const queue = createPendingQueue(baseOpts);
    const p1 = queue.enqueue("a@example.com");
    const p2 = queue.enqueue("b@example.com");
    const pending = queue.list();

    // Approve first, deny second
    queue.approve(pending[0]!.id);
    queue.deny(pending[1]!.id);

    expect(await p1).toBe(true);
    expect(await p2).toBe(false);
  });
});
