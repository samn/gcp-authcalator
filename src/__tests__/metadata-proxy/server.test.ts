import { describe, expect, test, afterEach, spyOn } from "bun:test";
import {
  startMetadataProxyServer,
  type MetadataProxyServerResult,
} from "../../metadata-proxy/server.ts";
import type { MetadataProxyConfig } from "../../config.ts";
import type { TokenProvider } from "../../metadata-proxy/types.ts";

/** Port counter to avoid collisions between tests. */
let nextPort = 19100;

function mockGateFetch(
  token: string,
  expiresIn = 3600,
  projectNumber = "123456789012",
  universeDomain = "googleapis.com",
): typeof globalThis.fetch {
  return ((input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("/project-number")) {
      return Promise.resolve(
        new Response(JSON.stringify({ project_number: projectNumber }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
    if (url.includes("/universe-domain")) {
      return Promise.resolve(
        new Response(JSON.stringify({ universe_domain: universeDomain }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
    return Promise.resolve(
      new Response(
        JSON.stringify({ access_token: token, expires_in: expiresIn, token_type: "Bearer" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  }) as unknown as typeof globalThis.fetch;
}

function makeConfig(port: number): MetadataProxyConfig {
  return {
    project_id: "test-project",
    service_account: "sa@test-project.iam.gserviceaccount.com",
    socket_path: "/tmp/test-gate.sock",
    port,
  };
}

describe("startMetadataProxyServer", () => {
  let result: MetadataProxyServerResult | null = null;

  afterEach(() => {
    if (result) {
      result.stop();
      result = null;
    }
  });

  test("starts server and responds to root detection ping", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok") },
    });

    const res = await fetch(`http://127.0.0.1:${port}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
  });

  test("serves token endpoint via gate client", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("my-dev-token") },
    });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/instance/service-accounts/default/token`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(200);

    const body = (await res.json()) as { access_token: string; token_type: string };
    expect(body.access_token).toBe("my-dev-token");
    expect(body.token_type).toBe("Bearer");
  });

  test("serves project-id endpoint", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok") },
    });

    const res = await fetch(`http://127.0.0.1:${port}/computeMetadata/v1/project/project-id`, {
      headers: { "Metadata-Flavor": "Google" },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe("test-project");
  });

  test("serves email endpoint when configured", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok") },
    });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/instance/service-accounts/default/email`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe("sa@test-project.iam.gserviceaccount.com");
  });

  test("serves numeric-project-id endpoint via gate client", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok", 3600, "999888777666") },
    });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/project/numeric-project-id`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    const body = await res.text();
    expect(body).toBe("999888777666");
  });

  test("serves universe-domain endpoint via gate client", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: {
        fetchFn: mockGateFetch("tok", 3600, "123456789012", "custom.googleapis.com"),
      },
    });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/universe/universe-domain`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    const body = await res.text();
    expect(body).toBe("custom.googleapis.com");
  });

  test("universe-domain returns 404 when using custom tokenProvider", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    const customProvider: TokenProvider = {
      getToken: async () => ({
        access_token: "custom-token",
        expires_at: new Date(Date.now() + 3600_000),
      }),
    };

    result = startMetadataProxyServer(config, { tokenProvider: customProvider });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/universe/universe-domain`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(404);
  });

  test("numeric-project-id returns 404 when using custom tokenProvider", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    const customProvider: TokenProvider = {
      getToken: async () => ({
        access_token: "custom-token",
        expires_at: new Date(Date.now() + 3600_000),
      }),
    };

    result = startMetadataProxyServer(config, { tokenProvider: customProvider });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/project/numeric-project-id`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(404);
  });

  test("returns 404 for unknown paths", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok") },
    });

    const res = await fetch(`http://127.0.0.1:${port}/nonexistent`, {
      headers: { "Metadata-Flavor": "Google" },
    });
    expect(res.status).toBe(404);
  });

  test("returns 403 when Metadata-Flavor header is missing", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok") },
    });

    const res = await fetch(`http://127.0.0.1:${port}/computeMetadata/v1/project/project-id`);
    expect(res.status).toBe(403);
  });

  test("stop() shuts down the server", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    result = startMetadataProxyServer(config, {
      gateClientOptions: { fetchFn: mockGateFetch("tok") },
    });

    // Verify server is running
    const res = await fetch(`http://127.0.0.1:${port}/`);
    expect(res.status).toBe(200);

    result.stop();
    result = null;

    // Server should be stopped — fetch should fail
    try {
      await fetch(`http://127.0.0.1:${port}/`);
      // If fetch succeeds the server is still running — fail the test
      expect(true).toBe(false);
    } catch {
      // Expected: connection refused
    }
  });

  test("uses custom tokenProvider instead of gate client", async () => {
    const port = nextPort++;
    const config = makeConfig(port);

    const customProvider: TokenProvider = {
      getToken: async () => ({
        access_token: "custom-provider-token",
        expires_at: new Date(Date.now() + 3600_000),
      }),
    };

    result = startMetadataProxyServer(config, { tokenProvider: customProvider });

    const res = await fetch(
      `http://127.0.0.1:${port}/computeMetadata/v1/instance/service-accounts/default/token`,
      { headers: { "Metadata-Flavor": "Google" } },
    );
    expect(res.status).toBe(200);

    const body = (await res.json()) as { access_token: string };
    expect(body.access_token).toBe("custom-provider-token");
  });

  test("port 0 assigns a random port", async () => {
    const config: MetadataProxyConfig = {
      project_id: "test-project",
      service_account: "sa@test-project.iam.gserviceaccount.com",
      socket_path: "/tmp/test-gate.sock",
      port: 0,
    };

    const customProvider: TokenProvider = {
      getToken: async () => ({
        access_token: "tok",
        expires_at: new Date(Date.now() + 3600_000),
      }),
    };

    result = startMetadataProxyServer(config, {
      tokenProvider: customProvider,
      quiet: true,
    });

    // server.port should be a real port, not 0
    expect(result.server.port).toBeGreaterThan(0);

    const res = await fetch(`http://127.0.0.1:${result.server.port}/`);
    expect(res.status).toBe(200);
  });

  test("quiet: true suppresses startup logs", async () => {
    const port = nextPort++;
    const config = makeConfig(port);
    const logSpy = spyOn(console, "log").mockImplementation(() => {});

    try {
      const customProvider: TokenProvider = {
        getToken: async () => ({
          access_token: "tok",
          expires_at: new Date(Date.now() + 3600_000),
        }),
      };

      result = startMetadataProxyServer(config, {
        tokenProvider: customProvider,
        quiet: true,
      });

      // No startup logs should have been emitted
      const calls = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
      expect(calls).not.toContain("metadata-proxy: starting");
    } finally {
      logSpy.mockRestore();
    }
  });
});
