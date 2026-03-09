import type { GateConnection } from "../gate/connection.ts";

export interface FetchProdTokenOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** The command being wrapped, sent to gcp-gate for display in the confirmation dialog. */
  command?: string[];
}

export interface ProdTokenResult {
  access_token: string;
  expires_in: number;
  /** Engineer's email address (from gcp-gate /identity endpoint). */
  email: string;
}

/**
 * Build the base URL and extra fetch options for a gate connection.
 */
function connectionFetchOpts(conn: GateConnection): { baseUrl: string; extraOpts: RequestInit } {
  if (conn.mode === "unix") {
    return {
      baseUrl: "http://localhost",
      extraOpts: { unix: conn.socketPath } as RequestInit,
    };
  }
  return {
    baseUrl: conn.gateUrl,
    extraOpts: {
      tls: {
        cert: conn.clientCert,
        key: conn.clientKey,
        ca: conn.caCert,
      },
    } as RequestInit,
  };
}

/**
 * One-shot fetch of a prod-level token and engineer identity from gcp-gate.
 *
 * 1. Hits `/token?level=prod` (triggers host-side confirmation).
 * 2. Hits `/identity` to retrieve the engineer's email address.
 *
 * The email is needed so the temporary metadata proxy can advertise a real
 * service-account email — gcloud ignores the "default" alias and only
 * recognises email-keyed accounts.
 */
export async function fetchProdToken(
  conn: GateConnection,
  options: FetchProdTokenOptions = {},
): Promise<ProdTokenResult> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const { baseUrl, extraOpts } = connectionFetchOpts(conn);

  const headers: Record<string, string> = {};
  if (options.command && options.command.length > 0) {
    headers["X-Wrapped-Command"] = JSON.stringify(options.command);
  }

  const fetchOpts = { ...extraOpts, headers };

  // Fetch prod token (may trigger host-side confirmation dialog)
  const tokenRes = await fetchFn(`${baseUrl}/token?level=prod`, fetchOpts);

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`gcp-gate returned ${tokenRes.status}: ${text}`);
  }

  const tokenBody = (await tokenRes.json()) as { access_token?: string; expires_in?: number };

  if (!tokenBody.access_token) {
    throw new Error("gcp-gate returned no access_token");
  }

  // Fetch engineer identity
  const identityRes = await fetchFn(`${baseUrl}/identity`, extraOpts);

  if (!identityRes.ok) {
    const text = await identityRes.text();
    throw new Error(`gcp-gate /identity returned ${identityRes.status}: ${text}`);
  }

  const identityBody = (await identityRes.json()) as { email?: string };

  if (!identityBody.email) {
    throw new Error("gcp-gate /identity returned no email");
  }

  return {
    access_token: tokenBody.access_token,
    expires_in: tokenBody.expires_in ?? 3600,
    email: identityBody.email,
  };
}
