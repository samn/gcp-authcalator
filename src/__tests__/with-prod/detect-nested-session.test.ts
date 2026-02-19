import { describe, expect, test } from "bun:test";
import {
  detectNestedSession,
  PROD_SESSION_ENV_VAR,
} from "../../with-prod/detect-nested-session.ts";

/** Build a mock fetch that simulates a healthy parent metadata proxy. */
function mockProxyFetch(overrides?: {
  rootStatus?: number;
  rootHeaders?: Record<string, string>;
  tokenStatus?: number;
  tokenBody?: Record<string, unknown>;
  emailStatus?: number;
  emailBody?: string;
  projectStatus?: number;
  projectBody?: string;
}): typeof globalThis.fetch {
  return (async (url: string, init?: RequestInit) => {
    // Consume body to avoid "request body not consumed" warnings
    void init;
    const parsed = new URL(url);
    const path = parsed.pathname;

    if (path === "/") {
      return new Response("ok", {
        status: overrides?.rootStatus ?? 200,
        headers: overrides?.rootHeaders ?? { "Metadata-Flavor": "Google" },
      });
    }
    if (path === "/computeMetadata/v1/instance/service-accounts/default/token") {
      return new Response(
        JSON.stringify(
          overrides?.tokenBody ?? {
            access_token: "ya29.prod-token",
            expires_in: 3000,
            token_type: "Bearer",
          },
        ),
        {
          status: overrides?.tokenStatus ?? 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    if (path === "/computeMetadata/v1/instance/service-accounts/default/email") {
      return new Response(overrides?.emailBody ?? "eng@example.com", {
        status: overrides?.emailStatus ?? 200,
      });
    }
    if (path === "/computeMetadata/v1/project/project-id") {
      return new Response(overrides?.projectBody ?? "my-project", {
        status: overrides?.projectStatus ?? 200,
      });
    }
    return new Response("Not found", { status: 404 });
  }) as unknown as typeof globalThis.fetch;
}

describe("detectNestedSession", () => {
  test("returns null when env var is not set", async () => {
    const result = await detectNestedSession({}, mockProxyFetch());
    expect(result).toBeNull();
  });

  test("returns null when env var is empty string", async () => {
    const result = await detectNestedSession({ [PROD_SESSION_ENV_VAR]: "" }, mockProxyFetch());
    expect(result).toBeNull();
  });

  test("returns session info when proxy is healthy", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch(),
    );
    expect(result).toEqual({
      metadataHost: "127.0.0.1:54321",
      email: "eng@example.com",
      projectId: "my-project",
    });
  });

  test("returns null when root ping returns non-200", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ rootStatus: 503 }),
    );
    expect(result).toBeNull();
  });

  test("returns null when Metadata-Flavor header is missing", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ rootHeaders: {} }),
    );
    expect(result).toBeNull();
  });

  test("returns null when token endpoint returns non-200", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ tokenStatus: 403 }),
    );
    expect(result).toBeNull();
  });

  test("returns null when token has expired (expires_in <= 0)", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ tokenBody: { access_token: "tok", expires_in: 0 } }),
    );
    expect(result).toBeNull();
  });

  test("returns null when token has negative expires_in", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ tokenBody: { access_token: "tok", expires_in: -100 } }),
    );
    expect(result).toBeNull();
  });

  test("returns null when email endpoint fails", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ emailStatus: 404 }),
    );
    expect(result).toBeNull();
  });

  test("returns null when email is empty", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ emailBody: "  " }),
    );
    expect(result).toBeNull();
  });

  test("returns null when project-id endpoint fails", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ projectStatus: 404 }),
    );
    expect(result).toBeNull();
  });

  test("returns null when project-id is empty", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ projectBody: "" }),
    );
    expect(result).toBeNull();
  });

  test("returns null when fetch throws (connection refused)", async () => {
    const throwingFetch = (() => {
      throw new Error("Connection refused");
    }) as unknown as typeof globalThis.fetch;

    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      throwingFetch,
    );
    expect(result).toBeNull();
  });

  test("returns null when fetch rejects (async error)", async () => {
    const rejectingFetch = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof globalThis.fetch;

    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      rejectingFetch,
    );
    expect(result).toBeNull();
  });

  test("trims whitespace from email and project-id", async () => {
    const result = await detectNestedSession(
      { [PROD_SESSION_ENV_VAR]: "127.0.0.1:54321" },
      mockProxyFetch({ emailBody: "  eng@example.com\n", projectBody: "  my-project\n" }),
    );
    expect(result).toEqual({
      metadataHost: "127.0.0.1:54321",
      email: "eng@example.com",
      projectId: "my-project",
    });
  });
});
