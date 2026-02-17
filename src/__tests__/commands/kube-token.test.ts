import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { runKubeToken } from "../../commands/kube-token.ts";

function mockMetadataFetch(
  body: Record<string, unknown> = {
    access_token: "ya29.test-token",
    expires_in: 3600,
    token_type: "Bearer",
  },
  status = 200,
): typeof globalThis.fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof globalThis.fetch;
}

describe("runKubeToken", () => {
  let exitSpy: ReturnType<typeof spyOn>;
  let errorSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    errorSpy = spyOn(console, "error").mockImplementation(() => {});
    exitSpy = spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
  });

  afterEach(() => {
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  });

  test("outputs valid ExecCredential JSON on success", async () => {
    let output = "";
    const writeFn = (data: string) => {
      output += data;
    };

    await runKubeToken({
      fetchFn: mockMetadataFetch(),
      writeFn,
      metadataHost: "127.0.0.1:9999",
    });

    const parsed = JSON.parse(output);
    expect(parsed.apiVersion).toBe("client.authentication.k8s.io/v1beta1");
    expect(parsed.kind).toBe("ExecCredential");
    expect(parsed.status.token).toBe("ya29.test-token");
    expect(parsed.status.expirationTimestamp).toBeDefined();
  });

  test("sets expirationTimestamp ~1s from now", async () => {
    let output = "";
    const writeFn = (data: string) => {
      output += data;
    };

    const before = Date.now();
    await runKubeToken({
      fetchFn: mockMetadataFetch(),
      writeFn,
      metadataHost: "127.0.0.1:9999",
    });
    const after = Date.now();

    const parsed = JSON.parse(output);
    const expiry = new Date(parsed.status.expirationTimestamp).getTime();

    // Should be ~1s from the time of the call, with some margin
    expect(expiry).toBeGreaterThanOrEqual(before + 500);
    expect(expiry).toBeLessThanOrEqual(after + 2000);
  });

  test("sends request with Metadata-Flavor header to correct URL", async () => {
    let capturedUrl = "";
    let capturedHeaders: Record<string, string> = {};

    const mockFetch = (async (url: string, init?: RequestInit) => {
      capturedUrl = url;
      if (init?.headers) {
        capturedHeaders = init.headers as Record<string, string>;
      }
      return new Response(
        JSON.stringify({ access_token: "tok", expires_in: 3600, token_type: "Bearer" }),
        { status: 200 },
      );
    }) as unknown as typeof globalThis.fetch;

    await runKubeToken({
      fetchFn: mockFetch,
      writeFn: () => {},
      metadataHost: "127.0.0.1:8173",
    });

    expect(capturedUrl).toBe(
      "http://127.0.0.1:8173/computeMetadata/v1/instance/service-accounts/default/token",
    );
    expect(capturedHeaders["Metadata-Flavor"]).toBe("Google");
  });

  test("falls back to default metadata host when not specified", async () => {
    let capturedUrl = "";

    const originalEnv = process.env.GCE_METADATA_HOST;
    delete process.env.GCE_METADATA_HOST;

    const mockFetch = (async (url: string) => {
      capturedUrl = url;
      return new Response(
        JSON.stringify({ access_token: "tok", expires_in: 3600, token_type: "Bearer" }),
        { status: 200 },
      );
    }) as unknown as typeof globalThis.fetch;

    try {
      await runKubeToken({
        fetchFn: mockFetch,
        writeFn: () => {},
      });
    } finally {
      if (originalEnv !== undefined) {
        process.env.GCE_METADATA_HOST = originalEnv;
      }
    }

    expect(capturedUrl).toContain("127.0.0.1:8173");
  });

  test("uses GCE_METADATA_HOST from environment when set", async () => {
    let capturedUrl = "";

    const originalEnv = process.env.GCE_METADATA_HOST;
    process.env.GCE_METADATA_HOST = "127.0.0.1:54321";

    const mockFetch = (async (url: string) => {
      capturedUrl = url;
      return new Response(
        JSON.stringify({ access_token: "tok", expires_in: 3600, token_type: "Bearer" }),
        { status: 200 },
      );
    }) as unknown as typeof globalThis.fetch;

    try {
      await runKubeToken({
        fetchFn: mockFetch,
        writeFn: () => {},
      });
    } finally {
      if (originalEnv !== undefined) {
        process.env.GCE_METADATA_HOST = originalEnv;
      } else {
        delete process.env.GCE_METADATA_HOST;
      }
    }

    expect(capturedUrl).toContain("127.0.0.1:54321");
  });

  test("exits 1 when fetch fails (network error)", async () => {
    const failingFetch = (async () => {
      throw new Error("Connection refused");
    }) as unknown as typeof globalThis.fetch;

    await expect(
      runKubeToken({
        fetchFn: failingFetch,
        writeFn: () => {},
        metadataHost: "127.0.0.1:9999",
      }),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("failed to reach metadata proxy");
    expect(errorOutput).toContain("Connection refused");
  });

  test("exits 1 when metadata proxy returns non-200 status", async () => {
    await expect(
      runKubeToken({
        fetchFn: mockMetadataFetch({ error: "Forbidden" }, 403),
        writeFn: () => {},
        metadataHost: "127.0.0.1:9999",
      }),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("HTTP 403");
  });

  test("exits 1 when response has no access_token", async () => {
    await expect(
      runKubeToken({
        fetchFn: mockMetadataFetch({ expires_in: 3600, token_type: "Bearer" }),
        writeFn: () => {},
        metadataHost: "127.0.0.1:9999",
      }),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("no access_token");
  });

  test("exits 1 when response is invalid JSON", async () => {
    const badJsonFetch = (async () =>
      new Response("not json", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      })) as unknown as typeof globalThis.fetch;

    await expect(
      runKubeToken({
        fetchFn: badJsonFetch,
        writeFn: () => {},
        metadataHost: "127.0.0.1:9999",
      }),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("invalid JSON");
  });

  test("writes nothing to stdout on error (diagnostics go to stderr)", async () => {
    let stdoutOutput = "";
    const writeFn = (data: string) => {
      stdoutOutput += data;
    };

    try {
      await runKubeToken({
        fetchFn: mockMetadataFetch({ error: "denied" }, 500),
        writeFn,
        metadataHost: "127.0.0.1:9999",
      });
    } catch {
      // process.exit mock throws
    }

    expect(stdoutOutput).toBe("");
  });
});
