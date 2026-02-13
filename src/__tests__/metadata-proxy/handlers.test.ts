import { describe, expect, test } from "bun:test";
import { handleRequest } from "../../metadata-proxy/handlers.ts";
import type { MetadataProxyDeps, CachedToken } from "../../metadata-proxy/types.ts";

function makeDeps(overrides: Partial<MetadataProxyDeps> = {}): MetadataProxyDeps {
  const token: CachedToken = {
    access_token: "test-access-token",
    expires_at: new Date(Date.now() + 3600 * 1000),
  };

  return {
    getToken: async () => token,
    projectId: "test-project",
    serviceAccountEmail: "sa@test-project.iam.gserviceaccount.com",
    startTime: new Date(Date.now() - 60_000),
    ...overrides,
  };
}

function makeRequest(path: string, method = "GET", headers?: Record<string, string>): Request {
  return new Request(`http://localhost${path}`, {
    method,
    headers: headers ?? {},
  });
}

function metadataRequest(path: string, method = "GET"): Request {
  return makeRequest(path, method, { "Metadata-Flavor": "Google" });
}

// ---------------------------------------------------------------------------
// GET / (detection ping)
// ---------------------------------------------------------------------------

describe("GET /", () => {
  test("returns 200 with Metadata-Flavor header", async () => {
    const res = await handleRequest(makeRequest("/"), makeDeps());
    expect(res.status).toBe(200);
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
  });

  test("does not require Metadata-Flavor request header", async () => {
    const res = await handleRequest(makeRequest("/"), makeDeps());
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Metadata-Flavor header validation
// ---------------------------------------------------------------------------

describe("Metadata-Flavor header validation", () => {
  test("returns 403 when header is missing on /computeMetadata/ paths", async () => {
    const res = await handleRequest(
      makeRequest("/computeMetadata/v1/project/project-id"),
      makeDeps(),
    );
    expect(res.status).toBe(403);
    const body = await res.text();
    expect(body).toContain("Metadata-Flavor");
  });

  test("returns 403 when header has wrong value", async () => {
    const res = await handleRequest(
      makeRequest("/computeMetadata/v1/project/project-id", "GET", {
        "Metadata-Flavor": "Wrong",
      }),
      makeDeps(),
    );
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/instance/service-accounts/default/token
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance/service-accounts/default/token", () => {
  test("returns access token with Bearer type", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("test-access-token");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
  });

  test("includes Metadata-Flavor response header", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"),
      makeDeps(),
    );
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
  });

  test("returns 500 when token fetch fails", async () => {
    const deps = makeDeps({
      getToken: async () => {
        throw new Error("gate unreachable");
      },
    });

    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"),
      deps,
    );

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("gate unreachable");
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/project/project-id
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/project/project-id", () => {
  test("returns project ID as plain text", async () => {
    const deps = makeDeps({ projectId: "my-gcp-project" });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/project/project-id"),
      deps,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = await res.text();
    expect(body).toBe("my-gcp-project");
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/instance/service-accounts/default/email
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance/service-accounts/default/email", () => {
  test("returns service account email as plain text", async () => {
    const deps = makeDeps({ serviceAccountEmail: "sa@project.iam.gserviceaccount.com" });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/email"),
      deps,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    const body = await res.text();
    expect(body).toBe("sa@project.iam.gserviceaccount.com");
  });

  test("returns 404 when service account email is not configured", async () => {
    const deps = makeDeps({ serviceAccountEmail: undefined });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/email"),
      deps,
    );

    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/instance/service-accounts/default/ (recursive)
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance/service-accounts/default/", () => {
  test("returns JSON service account info with recursive=true", async () => {
    const deps = makeDeps({ serviceAccountEmail: "sa@project.iam.gserviceaccount.com" });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/?recursive=true"),
      deps,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("sa@project.iam.gserviceaccount.com");
    expect(body.aliases).toEqual(["default"]);
    expect(body.scopes).toEqual(["https://www.googleapis.com/auth/cloud-platform"]);
  });

  test("does not include token in recursive response", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/?recursive=true"),
      makeDeps(),
    );

    const body = (await res.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty("token");
    expect(body).not.toHaveProperty("identity");
  });

  test("returns text directory listing without recursive param", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    const body = await res.text();
    expect(body).toContain("email");
    expect(body).toContain("token");
    expect(body).toContain("scopes");
    expect(body).toContain("aliases");
  });

  test("handles path without trailing slash", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default?recursive=true"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("sa@test-project.iam.gserviceaccount.com");
  });
});

// ---------------------------------------------------------------------------
// Non-GET methods
// ---------------------------------------------------------------------------

describe("non-GET methods", () => {
  test("returns 405 for POST", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token", "POST"),
      makeDeps(),
    );
    expect(res.status).toBe(405);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toContain("Method not allowed");
  });

  test("returns 405 for PUT", async () => {
    const res = await handleRequest(metadataRequest("/", "PUT"), makeDeps());
    expect(res.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// Unknown path
// ---------------------------------------------------------------------------

describe("unknown path", () => {
  test("returns 404 for unknown top-level path", async () => {
    const res = await handleRequest(metadataRequest("/unknown"), makeDeps());
    expect(res.status).toBe(404);
  });

  test("returns 404 for unknown computeMetadata path", async () => {
    const res = await handleRequest(metadataRequest("/computeMetadata/v1/unknown"), makeDeps());
    expect(res.status).toBe(404);
  });
});
