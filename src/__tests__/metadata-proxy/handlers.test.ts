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
// GET /computeMetadata/v1/project/numeric-project-id
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/project/numeric-project-id", () => {
  test("returns numeric project ID as plain text", async () => {
    const deps = makeDeps({ getNumericProjectId: async () => "123456789012" });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/project/numeric-project-id"),
      deps,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = await res.text();
    expect(body).toBe("123456789012");
  });

  test("returns 404 when getNumericProjectId is not configured", async () => {
    const deps = makeDeps({ getNumericProjectId: undefined });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/project/numeric-project-id"),
      deps,
    );

    expect(res.status).toBe(404);
  });

  test("returns 500 when numeric project ID lookup fails", async () => {
    const deps = makeDeps({
      getNumericProjectId: async () => {
        throw new Error("CRM API unreachable");
      },
    });

    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/project/numeric-project-id"),
      deps,
    );

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("CRM API unreachable");
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/universe/universe-domain
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/universe/universe-domain", () => {
  test("returns universe domain as plain text", async () => {
    const deps = makeDeps({ getUniverseDomain: async () => "googleapis.com" });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/universe/universe-domain"),
      deps,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = await res.text();
    expect(body).toBe("googleapis.com");
  });

  test("returns 404 when getUniverseDomain is not configured", async () => {
    const deps = makeDeps({ getUniverseDomain: undefined });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/universe/universe-domain"),
      deps,
    );

    expect(res.status).toBe(404);
  });

  test("returns 500 when universe domain lookup fails", async () => {
    const deps = makeDeps({
      getUniverseDomain: async () => {
        throw new Error("gate unreachable");
      },
    });

    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/universe/universe-domain"),
      deps,
    );

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("gate unreachable");
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
// GET /computeMetadata/v1/instance/service-accounts/default/scopes
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance/service-accounts/default/scopes", () => {
  test("returns cloud-platform scope as newline-delimited text", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/scopes"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = await res.text();
    expect(body).toBe("https://www.googleapis.com/auth/cloud-platform\n");
  });

  test("works via email-based path", async () => {
    const email = "sa@test-project.iam.gserviceaccount.com";
    const res = await handleRequest(
      metadataRequest(`/computeMetadata/v1/instance/service-accounts/${email}/scopes`),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe("https://www.googleapis.com/auth/cloud-platform\n");
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/instance/service-accounts/default/identity
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance/service-accounts/default/identity", () => {
  test("returns 400 when audience parameter is missing", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/identity"),
      makeDeps(),
    );

    expect(res.status).toBe(400);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = await res.text();
    expect(body).toContain("audience");
  });

  test("returns 404 when audience parameter is provided", async () => {
    const res = await handleRequest(
      metadataRequest(
        "/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com",
      ),
      makeDeps(),
    );

    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    const body = await res.text();
    expect(body).toContain("not supported");
  });

  test("returns 400 when audience parameter is empty", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/identity?audience="),
      makeDeps(),
    );

    expect(res.status).toBe(400);
    const body = await res.text();
    expect(body).toContain("audience");
  });

  test("works via email-based path", async () => {
    const email = "sa@test-project.iam.gserviceaccount.com";
    const res = await handleRequest(
      metadataRequest(
        `/computeMetadata/v1/instance/service-accounts/${email}/identity?audience=https://example.com`,
      ),
      makeDeps(),
    );

    expect(res.status).toBe(404);
    const body = await res.text();
    expect(body).toContain("not supported");
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
    expect(body).toContain("aliases");
    expect(body).toContain("email");
    expect(body).toContain("identity");
    expect(body).toContain("scopes");
    expect(body).toContain("token");
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
// GET /computeMetadata/v1/instance/service-accounts/ (listing)
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance/service-accounts/", () => {
  test("returns text listing with 'default/' and email for non-recursive request", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = await res.text();
    expect(body).toBe("default/\nsa@test-project.iam.gserviceaccount.com/\n");
  });

  test("returns only 'default/' when serviceAccountEmail is undefined", async () => {
    const deps = makeDeps({ serviceAccountEmail: undefined });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/"),
      deps,
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe("default/\n");
  });

  test("returns JSON with service account info for recursive=true", async () => {
    const email = "sa@project.iam.gserviceaccount.com";
    const deps = makeDeps({ serviceAccountEmail: email });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/?recursive=true"),
      deps,
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    const body = (await res.json()) as Record<string, Record<string, unknown>>;
    expect(body.default).toBeDefined();
    expect(body.default!.email).toBe(email);
    expect(body.default!.aliases).toEqual(["default"]);
    expect(body.default!.scopes).toEqual(["https://www.googleapis.com/auth/cloud-platform"]);
    // Email-keyed entry must also exist (required by gcloud Accounts() discovery)
    expect(body[email]).toBeDefined();
    expect(body[email]!.email).toBe(email);
  });

  test("uses configured serviceAccountEmail in recursive response", async () => {
    const email = "custom@my-project.iam.gserviceaccount.com";
    const deps = makeDeps({ serviceAccountEmail: email });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/?recursive=true"),
      deps,
    );

    const body = (await res.json()) as Record<string, Record<string, unknown>>;
    expect(body.default!.email).toBe(email);
    expect(body[email]).toBeDefined();
    expect(body[email]!.email).toBe(email);
  });

  test("falls back to 'default' when serviceAccountEmail is undefined in recursive response", async () => {
    const deps = makeDeps({ serviceAccountEmail: undefined });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/?recursive=true"),
      deps,
    );

    const body = (await res.json()) as Record<string, Record<string, unknown>>;
    expect(body.default!.email).toBe("default");
    expect(Object.keys(body)).toEqual(["default"]);
  });

  test("handles path without trailing slash", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe("default/\nsa@test-project.iam.gserviceaccount.com/\n");
  });

  test("handles path without trailing slash with recursive=true", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts?recursive=true"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { default: Record<string, unknown> };
    expect(body.default).toBeDefined();
    expect(body.default.email).toBe("sa@test-project.iam.gserviceaccount.com");
  });
});

// ---------------------------------------------------------------------------
// Email-based service account path aliasing (gcloud compatibility)
// ---------------------------------------------------------------------------

describe("email-based service account paths", () => {
  const email = "sa@test-project.iam.gserviceaccount.com";

  test("serves token via email-based path", async () => {
    const res = await handleRequest(
      metadataRequest(`/computeMetadata/v1/instance/service-accounts/${email}/token`),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("test-access-token");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
  });

  test("serves email via email-based path", async () => {
    const res = await handleRequest(
      metadataRequest(`/computeMetadata/v1/instance/service-accounts/${email}/email`),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe(email);
  });

  test("serves recursive info via email-based path", async () => {
    const res = await handleRequest(
      metadataRequest(`/computeMetadata/v1/instance/service-accounts/${email}/?recursive=true`),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe(email);
    expect(body.aliases).toEqual(["default"]);
    expect(body.scopes).toEqual(["https://www.googleapis.com/auth/cloud-platform"]);
  });

  test("serves directory listing via email-based path (no recursive)", async () => {
    const res = await handleRequest(
      metadataRequest(`/computeMetadata/v1/instance/service-accounts/${email}/`),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("email");
    expect(body).toContain("token");
  });

  test("aliases any unknown email to default (single-account proxy)", async () => {
    const res = await handleRequest(
      metadataRequest(
        "/computeMetadata/v1/instance/service-accounts/other@project.iam.gserviceaccount.com/token",
      ),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("test-access-token");
  });

  test("aliases unknown email even when serviceAccountEmail is undefined", async () => {
    const deps = makeDeps({ serviceAccountEmail: undefined });
    const res = await handleRequest(
      metadataRequest(`/computeMetadata/v1/instance/service-accounts/${email}/token`),
      deps,
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("test-access-token");
  });

  test("aliases unknown email for recursive info endpoint", async () => {
    const res = await handleRequest(
      metadataRequest(
        "/computeMetadata/v1/instance/service-accounts/cached-dev-sa@project.iam.gserviceaccount.com/?recursive=true",
      ),
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
