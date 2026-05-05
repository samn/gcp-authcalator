/**
 * Detect whether we are already inside a `with-prod` session by checking
 * for a sentinel environment variable and health-checking the parent's
 * metadata proxy.
 */

export const PROD_SESSION_ENV_VAR = "GCP_AUTHCALATOR_PROD_SESSION";

export interface NestedSessionInfo {
  metadataHost: string;
  email: string;
  projectId: string;
}

/**
 * Verify a `host:port` value points to a loopback address.
 *
 * The metadataHost from `GCP_AUTHCALATOR_PROD_SESSION` is set by a
 * trusted parent `with-prod`, but env vars are inherited by anything in
 * the process tree — a same-UID attacker could plant a sentinel
 * pointing at an attacker-controlled remote server, then wait for the
 * legitimate user to run `with-prod` again. Letting that through would
 * silently redirect the wrapped command's metadata traffic off-host.
 *
 * Accept only literal loopback hosts. Hostnames are not resolved here
 * — DNS could be attacker-controlled too.
 */
function isLoopbackHost(metadataHost: string): boolean {
  // Strip port. URL parsing is overkill since this isn't a full URL.
  // Bracketed IPv6: [::1]:8080
  let host = metadataHost;
  if (host.startsWith("[")) {
    const close = host.indexOf("]");
    if (close === -1) return false;
    host = host.slice(1, close);
  } else {
    const colon = host.lastIndexOf(":");
    if (colon !== -1) host = host.slice(0, colon);
  }
  host = host.toLowerCase();
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

/**
 * Check if we are already inside a with-prod session with a live proxy.
 *
 * Returns session info if the parent proxy is alive and serving valid tokens,
 * or `null` if we should fall through to the normal (new session) flow.
 */
export async function detectNestedSession(
  env: Record<string, string | undefined>,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<NestedSessionInfo | null> {
  const metadataHost = env[PROD_SESSION_ENV_VAR];
  if (!metadataHost) return null;

  if (!isLoopbackHost(metadataHost)) {
    console.error(
      `with-prod: ignoring ${PROD_SESSION_ENV_VAR}=${metadataHost} — not a loopback address. ` +
        `Nested-session reuse only follows 127.0.0.1, ::1, or localhost.`,
    );
    return null;
  }

  try {
    // Health check: root ping — verify it's a metadata proxy
    const pingRes = await fetchFn(`http://${metadataHost}/`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!pingRes.ok) return null;
    if (pingRes.headers.get("Metadata-Flavor") !== "Google") return null;

    const headers = { "Metadata-Flavor": "Google" };

    // Validate token is available and not expired (also validates PID ancestry)
    const tokenRes = await fetchFn(
      `http://${metadataHost}/computeMetadata/v1/instance/service-accounts/default/token`,
      { headers, signal: AbortSignal.timeout(2000) },
    );
    if (!tokenRes.ok) return null;
    const tokenBody = (await tokenRes.json()) as { expires_in?: number };
    if (!tokenBody.expires_in || tokenBody.expires_in <= 0) return null;

    // Read email
    const emailRes = await fetchFn(
      `http://${metadataHost}/computeMetadata/v1/instance/service-accounts/default/email`,
      { headers, signal: AbortSignal.timeout(2000) },
    );
    if (!emailRes.ok) return null;
    const email = (await emailRes.text()).trim();
    if (!email) return null;

    // Read project ID
    const projRes = await fetchFn(`http://${metadataHost}/computeMetadata/v1/project/project-id`, {
      headers,
      signal: AbortSignal.timeout(2000),
    });
    if (!projRes.ok) return null;
    const projectId = (await projRes.text()).trim();
    if (!projectId) return null;

    return { metadataHost, email, projectId };
  } catch {
    return null;
  }
}
