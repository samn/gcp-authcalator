/** Minimal Bun server surface needed to override one request's idle timeout. */
export interface RequestTimeoutServer {
  timeout(request: Request, seconds: number): void;
}

/**
 * Let the endpoint's own wall-clock deadline govern a potentially slow request.
 *
 * Bun's HTTP idle timeout counts time spent inside an active fetch handler. A
 * PAM-backed token refresh can legitimately take several minutes, so the
 * transport timeout must not close the client socket while that bounded work
 * is still running. Callers are responsible for an application-level deadline.
 */
export function useApplicationDeadline(request: Request, server: RequestTimeoutServer): void {
  server.timeout(request, 0);
}
