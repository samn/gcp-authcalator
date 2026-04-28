// Augments bun-types' Bun.serve options. As of bun-types 1.3.x, `idleTimeout`
// is declared only on `HostnamePortServeOptions`, but the runtime accepts it
// on Unix-socket servers too (verified against bun 1.3.13). Without this,
// passing `idleTimeout` alongside `unix` produces a spurious TS2345.
declare module "bun" {
  namespace Serve {
    interface UnixServeOptions<WebSocketData> {
      idleTimeout?: number;
    }
  }
}

export {};
