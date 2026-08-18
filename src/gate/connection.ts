import { resolveClientBundle } from "../tls/bundle.ts";
import { validateClientBundle } from "../tls/store.ts";

/** Bun-specific extension of RequestInit with `unix` and `tls` fields. */
export type BunRequestInit = RequestInit & {
  unix?: string;
  tls?: {
    cert?: string;
    key?: string;
    ca?: string;
  };
};

export type GateConnection =
  | { mode: "unix"; socketPath: string }
  | { mode: "tcp"; gateUrl: string; caCert: string; clientCert: string; clientKey: string };

/**
 * Determine how to connect to the gate daemon based on configuration and
 * environment variables.
 *
 * - If `gate_url` is configured (or `GCP_AUTHCALATOR_GATE_URL` env var):
 *   resolve and validate the client bundle, then return TCP mode.
 * - Otherwise: return Unix socket mode.
 */
export async function buildGateConnection(
  config: { socket_path: string; gate_url?: string; tls_bundle?: string; tls_dir?: string },
  env: Record<string, string | undefined> = process.env,
): Promise<GateConnection> {
  const configuredGateUrl = config.gate_url ?? env.GCP_AUTHCALATOR_GATE_URL;

  if (!configuredGateUrl) {
    return { mode: "unix", socketPath: config.socket_path };
  }

  // All gate callers append absolute endpoint paths. Keep the connection's
  // base URL canonical so a user-supplied trailing slash cannot turn `/token`
  // into `//token`, which some HTTP servers and proxies route differently.
  const gateUrl = configuredGateUrl.replace(/\/+$/, "");

  const bundle = resolveClientBundle(config, env);

  if (!bundle) {
    throw new Error(
      "gate_url is set but no TLS client bundle is available.\n" +
        "  Set GCP_AUTHCALATOR_TLS_BUNDLE_B64 env var, --tls-bundle path, or --tls-dir directory.",
    );
  }

  await validateClientBundle(bundle);

  return {
    mode: "tcp",
    gateUrl,
    caCert: bundle.caCert,
    clientCert: bundle.clientCert,
    clientKey: bundle.clientKey,
  };
}

/**
 * Build fetch options for a given gate connection.
 * Returns the base URL and extra RequestInit options (with Bun-specific fields).
 */
export function connectionFetchOpts(conn: GateConnection): {
  baseUrl: string;
  extraOpts: BunRequestInit;
} {
  if (conn.mode === "unix") {
    return {
      baseUrl: "http://localhost",
      extraOpts: { unix: conn.socketPath },
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
    },
  };
}

/** A gate request exceeded the caller-provided wall-clock deadline. */
export class GateTimeoutError extends Error {
  constructor(timeoutMs: number, url: string, cause: Error) {
    super(`gcp-gate request timed out after ${timeoutMs}ms: ${url}`, { cause });
    this.name = "GateTimeoutError";
  }
}

/**
 * Fetch a small gate response under a wall-clock deadline.
 *
 * `fetch()` resolves when response headers arrive, not when the body is fully
 * received. Buffering the body here keeps a peer that stalls after sending its
 * headers under the same timeout as connection establishment. Gate responses
 * are deliberately small JSON/text payloads, so buffering is bounded in
 * normal operation and lets callers parse the returned response synchronously
 * from memory.
 */
export async function fetchWithGateTimeout(
  fetchFn: typeof globalThis.fetch,
  url: string,
  init: BunRequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const signal = init.signal
    ? AbortSignal.any([init.signal, controller.signal])
    : controller.signal;
  try {
    const res = await fetchFn(url, { ...init, signal });
    const body = await res.arrayBuffer();
    return new Response(body.byteLength > 0 ? body : null, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  } catch (err) {
    if (controller.signal.aborted) {
      const cause = err instanceof Error ? err : new Error(String(err));
      throw new GateTimeoutError(timeoutMs, url, cause);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
