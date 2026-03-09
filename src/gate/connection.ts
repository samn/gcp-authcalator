import { resolveClientBundle } from "../tls/bundle.ts";

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
 *   resolve the client bundle and return TCP mode.
 * - Otherwise: return Unix socket mode.
 */
export function buildGateConnection(
  config: { socket_path: string; gate_url?: string; tls_bundle?: string },
  env: Record<string, string | undefined> = process.env,
): GateConnection {
  const gateUrl = config.gate_url ?? env.GCP_AUTHCALATOR_GATE_URL;

  if (!gateUrl) {
    return { mode: "unix", socketPath: config.socket_path };
  }

  const bundle = resolveClientBundle(config, env);

  if (!bundle) {
    throw new Error(
      "gate_url is set but no TLS client bundle is available.\n" +
        "  Set GCP_AUTHCALATOR_TLS_BUNDLE_B64 env var or --tls-bundle config option.",
    );
  }

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
