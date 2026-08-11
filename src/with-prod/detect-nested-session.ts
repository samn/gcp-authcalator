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
 * Accept only literal loopback hosts (127.0.0.1, ::1, localhost). DNS
 * is intentionally NOT resolved — a same-UID attacker who plants a
 * non-loopback value in the env could otherwise redirect the wrapped
 * command's metadata traffic off-host.
 */
function isLoopbackHost(metadataHost: string): boolean {
  let hostname: string;
  try {
    hostname = new URL(`http://${metadataHost}`).hostname.toLowerCase();
  } catch {
    return false;
  }
  return (
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1" ||
    hostname === "localhost"
  );
}

/**
 * Check if we are already inside a with-prod session with a live proxy.
 *
 * Returns session info if the parent proxy is alive, its backing gate authority
 * is still valid, and it is serving the expected identity/project metadata; or
 * `null` if normal new-session flow is needed.
 * Deliberately does not call the token endpoint: that endpoint may start a
 * minutes-long PAM refresh, so using it as a two-second health probe can both
 * abandon live work and spuriously create a second session.
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

    // The root, email, and project responses are local proxy constants. They
    // remain healthy if the gate restarts or a parent session expires, so they
    // cannot authorize nested reuse on their own. This control route asks the
    // provider to validate its exact session (or live per-request gate) without
    // minting a token or triggering PAM work.
    const authorityRes = await fetchFn(`http://${metadataHost}/session-health`, {
      headers,
      signal: AbortSignal.timeout(2000),
    });
    if (!authorityRes.ok) return null;

    // Read email. PID ancestry validation wraps this route just like the token
    // route, so a successful response also proves this process may use the
    // parent proxy without triggering a credential refresh.
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
