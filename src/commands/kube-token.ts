/**
 * kubectl exec credential plugin.
 *
 * Fetches a token from the authcalator metadata proxy and returns it as
 * an ExecCredential JSON on stdout.  kubectl calls this binary whenever it
 * needs a GKE bearer token.
 *
 * The expirationTimestamp is set ~1 s from now so kubectl never caches the
 * credential.  This ensures concurrent kubectl processes (some under
 * with-prod, some not) always get the token for their own metadata proxy.
 */

const DEFAULT_METADATA_HOST = "127.0.0.1:8173";
const TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token";

export interface KubeTokenOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** Override the write function (defaults to process.stdout.write). */
  writeFn?: (data: string) => void;
  /** Override GCE_METADATA_HOST for testing. */
  metadataHost?: string;
}

interface MetadataTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

export async function runKubeToken(options: KubeTokenOptions = {}): Promise<void> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const writeFn = options.writeFn ?? ((data: string) => process.stdout.write(data));
  const metadataHost =
    options.metadataHost ?? process.env.GCE_METADATA_HOST ?? DEFAULT_METADATA_HOST;

  const url = `http://${metadataHost}${TOKEN_PATH}`;

  let res: Response;
  try {
    res = await fetchFn(url, {
      headers: { "Metadata-Flavor": "Google" },
      signal: AbortSignal.timeout(5_000),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`kube-token: failed to reach metadata proxy at ${metadataHost}: ${msg}`);
    process.exit(1);
  }

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    console.error(`kube-token: metadata proxy returned HTTP ${res.status}: ${body}`);
    process.exit(1);
  }

  let token: MetadataTokenResponse;
  try {
    token = (await res.json()) as MetadataTokenResponse;
  } catch {
    console.error("kube-token: metadata proxy returned invalid JSON");
    process.exit(1);
  }

  if (!token.access_token) {
    console.error("kube-token: metadata proxy returned no access_token");
    process.exit(1);
  }

  // Set expiry ~1 s from now so kubectl never caches the credential.
  const expirationTimestamp = new Date(Date.now() + 1_000).toISOString();

  const execCredential = {
    apiVersion: "client.authentication.k8s.io/v1beta1",
    kind: "ExecCredential",
    status: {
      token: token.access_token,
      expirationTimestamp,
    },
  };

  writeFn(JSON.stringify(execCredential));
}
