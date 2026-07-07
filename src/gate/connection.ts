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
  const gateUrl = config.gate_url ?? env.GCP_AUTHCALATOR_GATE_URL;

  if (!gateUrl) {
    return { mode: "unix", socketPath: config.socket_path };
  }

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

/**
 * Thrown by `fetchWithGateTimeout` when the backstop timer aborts a stalled
 * gate request. Typed so callers that want their own wording (e.g. the
 * approve CLI) can distinguish a timeout from a connection failure without
 * matching on the message.
 */
export class GateTimeoutError extends Error {
  constructor(timeoutMs: number, url: string, cause: Error) {
    super(`gcp-gate request timed out after ${timeoutMs}ms: ${url}`, { cause });
    this.name = "GateTimeoutError";
  }
}

/**
 * Fetch the gate with a backstop timeout, rethrowing an abort as an actionable,
 * URL-bearing `GateTimeoutError` instead of a bare `DOMException` — mirroring
 * the gate's own `pamFetch`, so a wedged socket surfaces "gcp-gate request
 * timed out after Nms: <url>" rather than "The operation timed out". Uses an
 * AbortController + `clearTimeout` so the timer is released the instant the
 * request settles, rather than lingering — important on repeatedly-called
 * paths (session refresh, dev-token fetch).
 *
 * The response body is buffered here, under the same timer: `fetch` resolves
 * as soon as response headers arrive, so returning the raw Response would
 * leave the caller's `res.json()`/`res.text()` unbounded — a socket that
 * stalls mid-body would hang exactly like the header stall this exists to
 * prevent. Gate responses are small JSON, so buffering costs nothing.
 *
 * Shared by both gate clients (`with-prod` and the metadata proxy); each passes
 * its own `timeoutMs` sized above the gate's legitimate worst-case wait for that
 * path, so this never false-aborts a real request.
 */
export async function fetchWithGateTimeout(
  fetchFn: typeof globalThis.fetch,
  url: string,
  init: BunRequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, { ...init, signal: controller.signal });
    const body = await res.arrayBuffer();
    return new Response(body.byteLength > 0 ? body : null, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  } catch (err) {
    if (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError")) {
      throw new GateTimeoutError(timeoutMs, url, err);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
