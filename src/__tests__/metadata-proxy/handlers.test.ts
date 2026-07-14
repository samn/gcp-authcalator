import { describe, expect, test } from "bun:test";
import { handleRequest } from "../../metadata-proxy/handlers.ts";
import type { MetadataProxyDeps, CachedToken } from "../../metadata-proxy/types.ts";
import { DEFAULT_SCOPES } from "../../config.ts";

const TEST_REFRESH_TOKEN = "gcp-authcalator-stub-test-refresh-token";

function makeDeps(overrides: Partial<MetadataProxyDeps> = {}): MetadataProxyDeps {
  const token: CachedToken = {
    access_token: "test-access-token",
    expires_at: new Date(Date.now() + 3600 * 1000),
  };

  return {
    getToken: async () => token,
    projectId: "test-project",
    serviceAccountEmail: "sa@test-project.iam.gserviceaccount.com",
    scopes: DEFAULT_SCOPES,
    startTime: new Date(Date.now() - 60_000),
    refreshToken: TEST_REFRESH_TOKEN,
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
// GET /computeMetadata/v1/instance
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/instance", () => {
  test("returns 200 with directory listing of available subpaths", async () => {
    const res = await handleRequest(metadataRequest("/computeMetadata/v1/instance"), makeDeps());

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/plain");
    expect(res.headers.get("Metadata-Flavor")).toBe("Google");
    expect(await res.text()).toBe("service-accounts/\n");
  });

  test("trailing slash variant resolves to the same handler", async () => {
    const res = await handleRequest(metadataRequest("/computeMetadata/v1/instance/"), makeDeps());

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("service-accounts/\n");
  });

  test("returns 403 without Metadata-Flavor request header", async () => {
    const res = await handleRequest(makeRequest("/computeMetadata/v1/instance"), makeDeps());
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

  test("includes the stubbed refresh token", async () => {
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.refresh_token).toBe(TEST_REFRESH_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// POST /token (OAuth2 refresh-token grant against the stubbed refresh token)
// ---------------------------------------------------------------------------

describe("POST /token", () => {
  function refreshRequest(params: Record<string, string>, path = "/token"): Request {
    const body = new URLSearchParams(params).toString();
    return new Request(`http://localhost${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
      },
      body,
    });
  }

  test("exchanges the stubbed refresh token for an access token", async () => {
    const res = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: TEST_REFRESH_TOKEN }),
      makeDeps(),
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/json");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBe("test-access-token");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe("https://www.googleapis.com/auth/cloud-platform");
  });

  test("does not issue a new refresh token on refresh (matches Google)", async () => {
    const res = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: TEST_REFRESH_TOKEN }),
      makeDeps(),
    );

    const body = (await res.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty("refresh_token");
  });

  test("responses carry Cache-Control: no-store and no Metadata-Flavor header (RFC 6749 §5.1)", async () => {
    const success = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: TEST_REFRESH_TOKEN }),
      makeDeps(),
    );
    expect(success.headers.get("Cache-Control")).toBe("no-store");
    expect(success.headers.get("Pragma")).toBe("no-cache");
    expect(success.headers.get("Metadata-Flavor")).toBeNull();

    const error = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: "wrong" }),
      makeDeps(),
    );
    expect(error.headers.get("Cache-Control")).toBe("no-store");
    expect(error.headers.get("Metadata-Flavor")).toBeNull();
  });

  test("accepts a case-variant media type (RFC 9110: media types are case-insensitive)", async () => {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: TEST_REFRESH_TOKEN,
    }).toString();
    const req = new Request("http://localhost/token", {
      method: "POST",
      headers: {
        "Content-Type": "Application/x-www-form-URLENCODED; charset=UTF-8",
        "Content-Length": String(Buffer.byteLength(body)),
      },
      body,
    });

    const res = await handleRequest(req, makeDeps());
    expect(res.status).toBe(200);
  });

  test("rejects a missing Content-Length (chunked bodies) with invalid_request", async () => {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: TEST_REFRESH_TOKEN,
    }).toString();
    const req = new Request("http://localhost/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    const res = await handleRequest(req, makeDeps());
    expect(res.status).toBe(400);
    const resBody = (await res.json()) as Record<string, unknown>;
    expect(resBody.error).toBe("invalid_request");
    expect(resBody.error_description).toContain("Content-Length");
  });

  test("rejects an oversized Content-Length with invalid_request", async () => {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: TEST_REFRESH_TOKEN,
    }).toString();
    const req = new Request("http://localhost/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "100000000",
      },
      body,
    });

    const res = await handleRequest(req, makeDeps());
    expect(res.status).toBe(400);
    const resBody = (await res.json()) as Record<string, unknown>;
    expect(resBody.error).toBe("invalid_request");
  });

  test("does not require the Metadata-Flavor header (OAuth clients don't send it)", async () => {
    const req = refreshRequest({
      grant_type: "refresh_token",
      refresh_token: TEST_REFRESH_TOKEN,
    });
    expect(req.headers.get("Metadata-Flavor")).toBeNull();

    const res = await handleRequest(req, makeDeps());
    expect(res.status).toBe(200);
  });

  test("is exact-path like the real endpoint: POST /token/ returns 405", async () => {
    const res = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: TEST_REFRESH_TOKEN }, "/token/"),
      makeDeps(),
    );
    expect(res.status).toBe(405);
  });

  test("rejects an unknown refresh token with invalid_grant", async () => {
    const res = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: "not-the-issued-stub" }),
      makeDeps(),
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
  });

  test("rejects a real-looking GCP refresh token with invalid_grant", async () => {
    const res = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: "1//0abcdefghijklmnop" }),
      makeDeps(),
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
  });

  test("rejects a missing refresh_token with invalid_request", async () => {
    const res = await handleRequest(refreshRequest({ grant_type: "refresh_token" }), makeDeps());

    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("refresh_token");
  });

  test("rejects a missing grant_type with invalid_request", async () => {
    const res = await handleRequest(
      refreshRequest({ refresh_token: TEST_REFRESH_TOKEN }),
      makeDeps(),
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("grant_type");
  });

  test("rejects other grant types with unsupported_grant_type", async () => {
    const res = await handleRequest(
      refreshRequest({ grant_type: "authorization_code", code: "abc" }),
      makeDeps(),
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("unsupported_grant_type");
  });

  test("rejects a non-form body with invalid_request", async () => {
    const req = new Request("http://localhost/token", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: new Uint8Array([0xff, 0xfe, 0xfd]),
    });

    const res = await handleRequest(req, makeDeps());
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_request");
  });

  test("returns 503 temporarily_unavailable when the token provider fails after a valid grant", async () => {
    const deps = makeDeps({
      getToken: async () => {
        throw new Error("gate unreachable");
      },
    });

    const res = await handleRequest(
      refreshRequest({ grant_type: "refresh_token", refresh_token: TEST_REFRESH_TOKEN }),
      deps,
    );

    // The error member is a registered OAuth code (RFC 6749 §5.2), not prose —
    // the provider failure goes in error_description.
    expect(res.status).toBe(503);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("temporarily_unavailable");
    expect(body.error_description).toBe("gate unreachable");
  });

  test("GET /token remains 404 (redemption is POST-only)", async () => {
    const res = await handleRequest(metadataRequest("/token"), makeDeps());
    expect(res.status).toBe(404);
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
// GET /computeMetadata/v1/universe/universe_domain
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/universe/universe_domain", () => {
  test("returns universe domain as plain text", async () => {
    const deps = makeDeps({ getUniverseDomain: async () => "googleapis.com" });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/universe/universe_domain"),
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
      metadataRequest("/computeMetadata/v1/universe/universe_domain"),
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
      metadataRequest("/computeMetadata/v1/universe/universe_domain"),
      deps,
    );

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("gate unreachable");
  });
});

// ---------------------------------------------------------------------------
// GET /computeMetadata/v1/universe/universe-domain (hyphenated alias)
// ---------------------------------------------------------------------------

describe("GET /computeMetadata/v1/universe/universe-domain", () => {
  test("returns universe domain as plain text (same as underscore path)", async () => {
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

  test("returns custom scopes when configured", async () => {
    const customScopes = [
      "https://www.googleapis.com/auth/sqlservice.login",
      "https://www.googleapis.com/auth/devstorage.read_only",
    ];
    const deps = makeDeps({ scopes: customScopes });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/scopes"),
      deps,
    );

    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toBe(customScopes.join("\n") + "\n");
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

  test("returns custom scopes in recursive response when configured", async () => {
    const customScopes = ["https://www.googleapis.com/auth/sqlservice.login"];
    const deps = makeDeps({ scopes: customScopes });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/?recursive=true"),
      deps,
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.scopes).toEqual(customScopes);
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

  test("returns custom scopes in recursive service account listing", async () => {
    const customScopes = ["https://www.googleapis.com/auth/sqlservice.login"];
    const deps = makeDeps({ scopes: customScopes });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/?recursive=true"),
      deps,
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, Record<string, unknown>>;
    expect(body.default!.scopes).toEqual(customScopes);
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

// ---------------------------------------------------------------------------
// expires_in edge cases
// ---------------------------------------------------------------------------

describe("expires_in edge cases", () => {
  test("token expires_in is never negative", async () => {
    const pastToken: CachedToken = {
      access_token: "expired-token",
      expires_at: new Date(Date.now() - 1000),
    };
    const deps = makeDeps({ getToken: async () => pastToken });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"),
      deps,
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.expires_in).toBe(0);
  });

  test("token error handles non-Error thrown values", async () => {
    const deps = makeDeps({
      getToken: async () => {
        throw "string-error"; // eslint-disable-line no-throw-literal
      },
    });
    const res = await handleRequest(
      metadataRequest("/computeMetadata/v1/instance/service-accounts/default/token"),
      deps,
    );

    expect(res.status).toBe(500);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("Unknown error");
  });
});
