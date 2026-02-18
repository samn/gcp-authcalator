export interface FetchProdTokenOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** The command being wrapped, sent to gcp-gate for display in the confirmation dialog. */
  command?: string[];
  /** OAuth scopes for the prod token. */
  scopes?: string[];
}

export interface ProdTokenResult {
  access_token: string;
  expires_in: number;
  /** Engineer's email address (from gcp-gate /identity endpoint). */
  email: string;
}

/**
 * One-shot fetch of a prod-level token and engineer identity from gcp-gate.
 *
 * 1. Hits `/token?level=prod` on the Unix socket (triggers host-side confirmation).
 * 2. Hits `/identity` to retrieve the engineer's email address.
 *
 * The email is needed so the temporary metadata proxy can advertise a real
 * service-account email — gcloud ignores the "default" alias and only
 * recognises email-keyed accounts.
 */
export async function fetchProdToken(
  socketPath: string,
  options: FetchProdTokenOptions = {},
): Promise<ProdTokenResult> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const headers: Record<string, string> = {};
  if (options.command && options.command.length > 0) {
    headers["X-Wrapped-Command"] = JSON.stringify(options.command);
  }
  const unixOpts = { unix: socketPath, headers } as RequestInit;

  // Fetch prod token (may trigger host-side confirmation dialog)
  let tokenUrl = "http://localhost/token?level=prod";
  if (options.scopes && options.scopes.length > 0) {
    tokenUrl += `&scopes=${options.scopes.join(",")}`;
  }
  const tokenRes = await fetchFn(tokenUrl, unixOpts);

  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`gcp-gate returned ${tokenRes.status}: ${text}`);
  }

  const tokenBody = (await tokenRes.json()) as { access_token?: string; expires_in?: number };

  if (!tokenBody.access_token) {
    throw new Error("gcp-gate returned no access_token");
  }

  // Fetch engineer identity
  const identityRes = await fetchFn("http://localhost/identity", unixOpts);

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
