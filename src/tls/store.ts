import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import * as x509 from "@peculiar/x509";
import { generateCA } from "./ca.ts";
import { generateServerCert, generateClientCert } from "./certs.ts";

export interface TlsFiles {
  caCert: string;
  caKey: string;
  serverCert: string;
  serverKey: string;
  clientCert: string;
  clientKey: string;
}

export interface ClientBundle {
  caCert: string;
  clientCert: string;
  clientKey: string;
}

const DEFAULT_TLS_DIR = join(homedir(), ".gcp-authcalator", "tls");

/**
 * Ensure all TLS certificate files exist and are valid.
 * Generates or regenerates as needed.
 *
 * Returns the loaded PEM contents.
 */
export async function ensureTlsFiles(tlsDir?: string): Promise<TlsFiles> {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  const paths = tlsPaths(dir);

  const allExist = Object.values(paths).every((p) => existsSync(p));

  if (allExist) {
    // Check expiry
    const caCertPem = readFileSync(paths.caCert, "utf-8");
    const serverCertPem = readFileSync(paths.serverCert, "utf-8");
    const clientCertPem = readFileSync(paths.clientCert, "utf-8");

    const caExpired = isCertExpired(caCertPem);
    const serverExpired = isCertExpired(serverCertPem);
    const clientExpired = isCertExpired(clientCertPem);

    if (!caExpired && !serverExpired && !clientExpired) {
      return loadTlsFiles(dir);
    }

    if (caExpired) {
      console.warn("gate: CA certificate expired — regenerating all TLS certificates");
      console.warn("gate: Remote client bundles need updating!");
      console.warn("gate: Run: gcp-authcalator init-tls --bundle-b64");
    } else {
      console.warn("gate: TLS certificates regenerated (previous certs expired)");
      console.warn("gate: Remote client bundles need updating!");
      console.warn("gate: Run: gcp-authcalator init-tls --bundle-b64");
    }
  }

  // Generate everything fresh
  const ca = await generateCA();
  const server = await generateServerCert(ca.caCert, ca.caKey);
  const client = await generateClientCert(ca.caCert, ca.caKey);

  writeSecure(paths.caCert, ca.caCert);
  writeSecure(paths.caKey, ca.caKey);
  writeSecure(paths.serverCert, server.cert);
  writeSecure(paths.serverKey, server.key);
  writeSecure(paths.clientCert, client.cert);
  writeSecure(paths.clientKey, client.key);

  // Write combined client bundle
  const bundleContent = `${ca.caCert}${client.cert}${client.key}`;
  writeSecure(paths.clientBundle, bundleContent);

  return {
    caCert: ca.caCert,
    caKey: ca.caKey,
    serverCert: server.cert,
    serverKey: server.key,
    clientCert: client.cert,
    clientKey: client.key,
  };
}

/** Load TLS files from disk. Throws if files are missing. */
export function loadTlsFiles(tlsDir?: string): TlsFiles {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  const paths = tlsPaths(dir);

  return {
    caCert: readFileSync(paths.caCert, "utf-8"),
    caKey: readFileSync(paths.caKey, "utf-8"),
    serverCert: readFileSync(paths.serverCert, "utf-8"),
    serverKey: readFileSync(paths.serverKey, "utf-8"),
    clientCert: readFileSync(paths.clientCert, "utf-8"),
    clientKey: readFileSync(paths.clientKey, "utf-8"),
  };
}

/** Parse a client-bundle.pem into its three PEM sections. */
export function loadClientBundle(bundlePath: string): ClientBundle {
  const content = readFileSync(bundlePath, "utf-8");
  return parseClientBundle(content);
}

/** Decode a base64-encoded client bundle string into its PEM sections. */
export function loadClientBundleFromBase64(b64: string): ClientBundle {
  const content = Buffer.from(b64, "base64").toString("utf-8");
  return parseClientBundle(content);
}

/** Read client-bundle.pem and return as base64 string. */
export function getClientBundleBase64(tlsDir?: string): string {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  const bundlePath = join(dir, "client-bundle.pem");
  const content = readFileSync(bundlePath, "utf-8");
  return Buffer.from(content).toString("base64");
}

/** Get the TLS directory path. */
export function getDefaultTlsDir(): string {
  return DEFAULT_TLS_DIR;
}

// ---- Internal helpers ----

function tlsPaths(dir: string) {
  return {
    caCert: join(dir, "ca.pem"),
    caKey: join(dir, "ca-key.pem"),
    serverCert: join(dir, "server.pem"),
    serverKey: join(dir, "server-key.pem"),
    clientCert: join(dir, "client.pem"),
    clientKey: join(dir, "client-key.pem"),
    clientBundle: join(dir, "client-bundle.pem"),
  };
}

function writeSecure(filePath: string, content: string): void {
  writeFileSync(filePath, content, { mode: 0o600 });
  // Ensure permissions even if file already existed
  chmodSync(filePath, 0o600);
}

function isCertExpired(pem: string): boolean {
  const cert = new x509.X509Certificate(pem);
  return cert.notAfter.getTime() < Date.now();
}

function parseClientBundle(content: string): ClientBundle {
  const pemBlocks = content.match(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g);

  if (!pemBlocks || pemBlocks.length < 3) {
    throw new Error(
      `Invalid client bundle: expected 3 PEM blocks (CA cert, client cert, client key), found ${pemBlocks?.length ?? 0}`,
    );
  }

  // Order: CA cert, client cert, client key
  const caCert = pemBlocks[0]! + "\n";
  const clientCert = pemBlocks[1]! + "\n";
  const clientKey = pemBlocks[2]! + "\n";

  return { caCert, clientCert, clientKey };
}
