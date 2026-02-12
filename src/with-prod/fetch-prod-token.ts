export interface FetchProdTokenOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
}

export interface ProdTokenResult {
  access_token: string;
  expires_in: number;
}

/**
 * One-shot fetch of a prod-level token from the gcp-gate daemon.
 *
 * Hits `/token?level=prod` on the Unix socket — this triggers a host-side
 * confirmation prompt before the token is issued.
 */
export async function fetchProdToken(
  socketPath: string,
  options: FetchProdTokenOptions = {},
): Promise<ProdTokenResult> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;

  const res = await fetchFn("http://localhost/token?level=prod", {
    unix: socketPath,
  } as RequestInit);

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`gcp-gate returned ${res.status}: ${text}`);
  }

  const body = (await res.json()) as { access_token?: string; expires_in?: number };

  if (!body.access_token) {
    throw new Error("gcp-gate returned no access_token");
  }

  return {
    access_token: body.access_token,
    expires_in: body.expires_in ?? 3600,
  };
}
