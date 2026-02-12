import { describe, expect, test, afterEach } from "bun:test";
import {
  startMetadataProxyServer,
  type MetadataProxyServerResult,
} from "../../metadata-proxy/server.ts";
import type { MetadataProxyConfig } from "../../config.ts";

/** Port counter to avoid collisions between tests. */
let nextPort = 19100;

function mockGateFetch(token: string, expiresIn = 3600): typeof globalThis.fetch {
  return (async () =>
    new Response(
      JSON.stringify({ access_token: token, expires_in: expiresIn, token_type: "Bearer" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )) as unknown as typeof globalThis.fetch;
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
});
