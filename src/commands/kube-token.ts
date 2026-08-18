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
const DEFAULT_EXEC_CREDENTIAL_API_VERSION = "client.authentication.k8s.io/v1beta1";
const SUPPORTED_EXEC_CREDENTIAL_API_VERSIONS = new Set([
  "client.authentication.k8s.io/v1",
  "client.authentication.k8s.io/v1beta1",
]);

export interface KubeTokenOptions {
  /** Override fetch for testing. */
  fetchFn?: typeof globalThis.fetch;
  /** Override the write function (defaults to process.stdout.write). */
  writeFn?: (data: string) => void;
  /** Override GCE_METADATA_HOST for testing. */
  metadataHost?: string;
  /** Override KUBERNETES_EXEC_INFO for testing. */
  execInfo?: string | null;
}

interface MetadataTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

/**
 * Kubernetes requires an exec plugin response to use the same API version as
 * the ExecCredential request provided through KUBERNETES_EXEC_INFO. Keep the
 * historical v1beta1 fallback for direct/manual invocations without that env.
 */
function resolveExecCredentialApiVersion(execInfo: string | undefined): string {
  if (!execInfo) return DEFAULT_EXEC_CREDENTIAL_API_VERSION;

  try {
    const request = JSON.parse(execInfo) as { apiVersion?: unknown };
    if (
      typeof request.apiVersion === "string" &&
      SUPPORTED_EXEC_CREDENTIAL_API_VERSIONS.has(request.apiVersion)
    ) {
      return request.apiVersion;
    }
  } catch {
    // Fall through to the backwards-compatible default. Kubernetes itself
    // validates the configured exec API version before invoking the plugin.
  }

  return DEFAULT_EXEC_CREDENTIAL_API_VERSION;
}

export async function runKubeToken(options: KubeTokenOptions = {}): Promise<void> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  const writeFn = options.writeFn ?? ((data: string) => process.stdout.write(data));
  const metadataHost =
    options.metadataHost ?? process.env.GCE_METADATA_HOST ?? DEFAULT_METADATA_HOST;
  const execInfo =
    options.execInfo === undefined
      ? process.env.KUBERNETES_EXEC_INFO
      : (options.execInfo ?? undefined);
  const apiVersion = resolveExecCredentialApiVersion(execInfo);

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
    apiVersion,
    kind: "ExecCredential",
    status: {
      token: token.access_token,
      expirationTimestamp,
    },
  };

  writeFn(JSON.stringify(execCredential));
}
