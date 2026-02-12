import type { CachedToken, TokenProvider } from "./types.ts";

/** Minimum remaining lifetime before we re-fetch a cached token (5 minutes). */
const CACHE_MARGIN_MS = 5 * 60 * 1000;

export interface GateClientOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
}

/**
 * Create a token provider that fetches from the gcp-gate daemon over a Unix socket.
 *
 * - Caches the token in memory
 * - Re-fetches when remaining lifetime < 5 minutes
 * - Accepts an optional fetchFn for test injection
 */
export function createGateClient(
  socketPath: string,
  options: GateClientOptions = {},
): TokenProvider {
  const fetchFn = options.fetchFn ?? globalThis.fetch;

  let cache: CachedToken | null = null;

  function isCacheValid(cached: CachedToken | null): cached is CachedToken {
    if (!cached) return false;
    return cached.expires_at.getTime() - Date.now() > CACHE_MARGIN_MS;
  }

  async function getToken(): Promise<CachedToken> {
    if (isCacheValid(cache)) {
      return cache;
    }

    const res = await fetchFn("http://localhost/token", {
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

    const expiresIn = body.expires_in ?? 3600;

    cache = {
      access_token: body.access_token,
      expires_at: new Date(Date.now() + expiresIn * 1000),
    };

    return cache;
  }

  return { getToken };
}
