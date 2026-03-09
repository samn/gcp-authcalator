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
export async function ensureTlsFiles(tlsDir?: string, force?: boolean): Promise<TlsFiles> {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  const paths = tlsPaths(dir);

  const allExist = Object.values(paths).every((p) => existsSync(p));

  if (allExist && !force) {
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
      console.warn("tls: CA certificate expired — regenerating all TLS certificates");
      console.warn("tls: Remote client bundles need updating!");
    } else {
      console.warn("tls: TLS certificates regenerated (previous certs expired)");
      console.warn("tls: Remote client bundles need updating!");
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

/**
 * Load and validate TLS files from disk.
 *
 * Unlike `ensureTlsFiles`, this does NOT generate certificates — it only loads
 * existing ones and validates that they are well-formed, not expired, and that
 * the server/client certificates are properly signed by the CA.
 *
 * Throws actionable errors when files are missing, invalid, or expired.
 */
export async function loadAndValidateTlsFiles(tlsDir?: string): Promise<TlsFiles> {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  const hint = `\n  Run 'gcp-authcalator init-tls' to regenerate the certificate chain.`;

  let files: TlsFiles;
  try {
    files = loadTlsFiles(dir);
  } catch {
    throw new Error(`TLS certificates not found in ${dir}` + hint);
  }

  // Validate that all PEM content is parseable as X.509 certificates
  let caCert: x509.X509Certificate;
  try {
    caCert = new x509.X509Certificate(files.caCert);
  } catch {
    throw new Error(`TLS CA certificate is malformed in ${dir}` + hint);
  }

  let serverCert: x509.X509Certificate;
  try {
    serverCert = new x509.X509Certificate(files.serverCert);
  } catch {
    throw new Error(`TLS server certificate is malformed in ${dir}` + hint);
  }

  let clientCert: x509.X509Certificate;
  try {
    clientCert = new x509.X509Certificate(files.clientCert);
  } catch {
    throw new Error(`TLS client certificate is malformed in ${dir}` + hint);
  }

  // Validate the CA has BasicConstraints CA=true
  const bcExt = caCert.getExtension("2.5.29.19"); // basicConstraints OID
  if (!bcExt) {
    throw new Error(`TLS CA certificate is missing BasicConstraints extension in ${dir}` + hint);
  }

  // Validate expiry
  const now = Date.now();
  if (caCert.notAfter.getTime() < now) {
    throw new Error(`TLS CA certificate has expired in ${dir}` + hint);
  }
  if (serverCert.notAfter.getTime() < now) {
    throw new Error(`TLS server certificate has expired in ${dir}` + hint);
  }
  if (clientCert.notAfter.getTime() < now) {
    throw new Error(`TLS client certificate has expired in ${dir}` + hint);
  }

  // Validate that server and client certs were signed by this CA
  const caPublicKey = await caCert.publicKey.export();
  if (serverCert.issuer !== caCert.subject) {
    throw new Error(
      `TLS server certificate was not issued by the CA in ${dir}` +
        `\n  Server issuer: ${serverCert.issuer}` +
        `\n  CA subject:    ${caCert.subject}` +
        hint,
    );
  }
  try {
    const serverValid = await serverCert.verify({ publicKey: caPublicKey, signatureOnly: true });
    if (!serverValid) {
      throw new Error(`TLS server certificate signature is invalid in ${dir}` + hint);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes(dir)) throw err;
    throw new Error(`TLS server certificate signature verification failed in ${dir}` + hint);
  }

  if (clientCert.issuer !== caCert.subject) {
    throw new Error(
      `TLS client certificate was not issued by the CA in ${dir}` +
        `\n  Client issuer: ${clientCert.issuer}` +
        `\n  CA subject:    ${caCert.subject}` +
        hint,
    );
  }
  try {
    const clientValid = await clientCert.verify({ publicKey: caPublicKey, signatureOnly: true });
    if (!clientValid) {
      throw new Error(`TLS client certificate signature is invalid in ${dir}` + hint);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes(dir)) throw err;
    throw new Error(`TLS client certificate signature verification failed in ${dir}` + hint);
  }

  return files;
}

/**
 * Validate a client bundle's certificates are well-formed, not expired, and
 * that the client certificate is signed by the bundle's CA.
 *
 * Throws actionable errors with regeneration instructions.
 */
export async function validateClientBundle(bundle: ClientBundle): Promise<void> {
  const hint =
    "\n  On the host, run 'gcp-authcalator init-tls' to regenerate certificates," +
    "\n  then update the client bundle (GCP_AUTHCALATOR_TLS_BUNDLE_B64 or --tls-bundle).";

  let caCert: x509.X509Certificate;
  try {
    caCert = new x509.X509Certificate(bundle.caCert);
  } catch {
    throw new Error("TLS client bundle: CA certificate is malformed" + hint);
  }

  let clientCert: x509.X509Certificate;
  try {
    clientCert = new x509.X509Certificate(bundle.clientCert);
  } catch {
    throw new Error("TLS client bundle: client certificate is malformed" + hint);
  }

  const now = Date.now();
  if (caCert.notAfter.getTime() < now) {
    throw new Error("TLS client bundle: CA certificate has expired" + hint);
  }
  if (clientCert.notAfter.getTime() < now) {
    throw new Error("TLS client bundle: client certificate has expired" + hint);
  }

  // Validate the client cert was signed by the bundle's CA
  if (clientCert.issuer !== caCert.subject) {
    throw new Error(
      "TLS client bundle: client certificate was not issued by the bundle CA" +
        `\n  Client issuer: ${clientCert.issuer}` +
        `\n  CA subject:    ${caCert.subject}` +
        hint,
    );
  }
  try {
    const caPublicKey = await caCert.publicKey.export();
    const valid = await clientCert.verify({ publicKey: caPublicKey, signatureOnly: true });
    if (!valid) {
      throw new Error("TLS client bundle: client certificate signature is invalid" + hint);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("TLS client bundle")) throw err;
    throw new Error("TLS client bundle: client certificate signature verification failed" + hint);
  }
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

/**
 * Load a client bundle from a file.
 *
 * Accepts either a PEM file (containing -----BEGIN blocks) or a base64-encoded
 * PEM file (as produced by `init-tls --bundle-b64`). Auto-detects the format.
 */
export function loadClientBundle(bundlePath: string): ClientBundle {
  const raw = readFileSync(bundlePath, "utf-8").trim();

  // If the file contains PEM headers, parse directly.
  // Otherwise, assume base64-encoded PEM and decode first.
  const content = raw.includes("-----BEGIN ") ? raw : Buffer.from(raw, "base64").toString("utf-8");
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

  // Parse by PEM label type rather than assuming fixed order
  const certs: string[] = [];
  const keys: string[] = [];

  for (const block of pemBlocks) {
    if (block.startsWith("-----BEGIN CERTIFICATE-----")) {
      certs.push(block + "\n");
    } else if (block.startsWith("-----BEGIN PRIVATE KEY-----")) {
      keys.push(block + "\n");
    } else {
      throw new Error(`Invalid client bundle: unexpected PEM block type: ${block.slice(0, 40)}...`);
    }
  }

  if (certs.length !== 2) {
    throw new Error(
      `Invalid client bundle: expected 2 CERTIFICATE blocks (CA + client), found ${certs.length}`,
    );
  }
  if (keys.length !== 1) {
    throw new Error(`Invalid client bundle: expected 1 PRIVATE KEY block, found ${keys.length}`);
  }

  return { caCert: certs[0]!, clientCert: certs[1]!, clientKey: keys[0]! };
}
